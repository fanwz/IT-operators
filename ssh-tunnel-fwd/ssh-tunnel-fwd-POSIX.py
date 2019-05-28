#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/05/01 0025 15:13
# @Author  : Fanwz
# @File    : ssh-tunnel-fwd-POSIX.py
# @Software: PyCharm

# refer:
# https://stackoverflow.com/questions/5136611/capture-stdout-from-a-script-in-python
# https://gist.github.com/bortzmeyer/1284249
# https://stackoverflow.com/questions/7114990/pseudo-terminal-will-not-be-allocated-because-stdin-is-not-a-terminal
# https://stackoverflow.com/questions/41473000/how-can-i-monitor-health-of-ssh-tunnel-with-pexpect

# config.json sample
# {
#     "SSH": {
#         "User": "yourid",
#         "IP": "remotehost",
#         "Port": "22",
#         "Key": "xxxxxxxxxx"
#     },
#     "FwdSetting": [
#         {
#             "LocalPort": "6522",
#             "RemoteIP": "192.168.12.123",
#             "RemotePort": "22"
#         },
#         {
#             "LocalPort": "3389",
#             "RemoteIP": "192.168.96.21",
#             "RemotePort": "5123"
#         }
#     ]
# }


import os
import time
import sys
import socket
if sys.version_info < (3,4):
    import thread
else:
    import _thread as thread

import re

import json
import io
import webbrowser
import subprocess
import threading
import platform
try:
    from queue import Queue, Empty
except ImportError:
    from Queue import Queue, Empty  # python 2.x

import pexpect

ON_POSIX = 'posix' in sys.builtin_module_names

CST_NULL = 0 # nothing
CST_CNNI = 1 # connecting
CST_CNND = 2 # connected
CST_EST = 3 # establish
CST_TM = 4 # timeout

CNND_PROMPT = ['#|>|\$|>>>', 'deni', pexpect.EOF, pexpect.TIMEOUT]
EST_PROMPT = [pexpect.EOF]

is_win_f = False
if platform.system() == "Windows":
    is_win_f = True

def jsonload(filename):
	with io.open(filename, 'r', encoding = 'utf-8') as f:
		return json.load(f)


def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")


class SSHConnect(object):
    def __init__(self, conf):
        self.fwdcmd = ""
        for index in range(len(conf.localbind)):
            # print(index)
            self.fwdcmd += "-L {}:{}:{} ".format(str(conf.localbind[index][1]),
                                   conf.remotebind[index][0],
                                   str(conf.remotebind[index][1]))

        self.cmdline = "ssh -tt  -o TCPKeepAlive=yes -o ServerAliveInterval=15  -o ServerAliveCountMax=3 -o StrictHostKeyChecking=ask {0}@{1} -p {2} {4}".format(
            conf.USER,
            conf.SSH_IP,
            conf.SSH_PORT,
            conf.PSW,
            self.fwdcmd
        )

        # print(self.cmdline)
        self.is_active = False
        self.is_alive = False
        self.connect_status = CST_NULL
        self.conf = conf
        # exit(1)

    def __polling(self):
        pass


    def start(self):
        self.child = pexpect.spawn(self.cmdline)
        self.connect_status = CST_CNNI

    def restart(self):
        if self.child.isalive():
            self.child.kill()
            time.sleep(2)
        self.child = pexpect.spawn(self.cmdline)
        self.connect_status = CST_CNNI

    def update_status(self):
        if self.connect_status == CST_CNNI:
            ret = self.child.expect(['password', 'continue connecting',
                                     pexpect.EOF, pexpect.TIMEOUT], timeout=15, searchwindowsize=None)
            if ret == 0:                
                self.child.sendline(self.conf.PSW)
                self.connect_status = CST_CNND
            if ret == 1:
                outmsg = str(self.child.before)
                # print(outmsg)
                keyinfo = re.findall(r'(fingerprint.+?)\\n', outmsg)
                if len(keyinfo) > 0:
                    print("[Warning]:Please confirm the Server Key(ask your IT support):")
                    for info in keyinfo:
                        print(info.strip('\\r'))
                    
                    if self.conf.KEY == None:
                        userinput = input("If the Key is right,enter [yes],or exit by other actions:")
                        if userinput == "yes":
                            self.child.sendline("yes")
                        else:
                            exit(11)
                    else:
                        for info in keyinfo:
                            if self.conf.KEY in info:
                                print("Config key has matched!")
                                self.child.sendline("yes")
                                return
                        print(
                            "Config key is not matched!Your network maybe under monitoring!")
                        exit(11)
                        
                else:
                    print("can not find the fingerprint key.exit!")
                    print("msg:\n{}".format(outmsg))
                    exit(11)
                        
                pass
            if ret == 2:
                pass
            if ret == 3:
                pass

        if self.connect_status == CST_CNND:
            ret = self.child.expect(CNND_PROMPT, timeout=15, searchwindowsize=None)
            if ret == 0:
                print("connection establish")
                self.connect_status = CST_EST
                self.is_active = True
                self.is_alive = True
            if ret == 1:
                print("server deny access")
                exit(11)

            if ret == 2 or ret == 3:
                print("connect lost")
                self.connect_status = CST_NULL
                self.is_active = False
                self.is_alive = False

        if self.connect_status == CST_EST:
            ret = self.child.expect(EST_PROMPT, timeout=None)
            if ret == 0:
                print("connect lost")
                print(self.child.after)
                print(self.child.before)
                self.connect_status = CST_NULL
                self.is_active = False
                self.is_alive = False


class SSHTunnelConfig(object):
    def __init__(self,file):
        conf = jsonload(file)
        self.conf = conf
        try:
            self.SSH_IP = conf["SSH"]["IP"]
        except:
            self.SSH_IP = input('Enter a host name or IP:')

        try:
            self.SSH_PORT = int(conf["SSH"]["Port"])
        except:
            self.SSH_PORT = input('Enter port:')

        try:
            self.USER = conf["SSH"]["User"]
        except:
            self.USER = input("Enter user name:")

        try:
            self.PSW = conf["SSH"]["Password"]
        except:
            self.PSW = input("Enter password:")

        try:
            self.KEY = conf["SSH"]["Key"]
        except:
            self.KEY = None

        if is_win_f:
            os.system('cls')
        else:
            os.system('clear')

        self.localbind = []
        self.remotebind = []
        for fwd in conf["FwdSetting"]:
            lb = ('0.0.0.0',int(fwd["LocalPort"]))
            rb = (fwd["RemoteIP"], int(fwd["RemotePort"]))
            self.localbind.append(lb)
            self.remotebind.append(rb)

Conf = SSHTunnelConfig("config.json")

open_browser_flag = False

link = SSHConnect(Conf)
link.start()

bakstatus = False
waitcnt = 0

while True:
    link.update_status()
    if link.is_alive == False:
        if bakstatus != link.is_alive:
            print("[{}]Server lose connect!".format(timestamp()))
            bakstatus = link.is_alive
        waitcnt += 1
        if waitcnt > 10:
            waitcnt = 0
            try:
                print("[{}]Try to restart Server connect!".format(timestamp()))
                link.restart()
            except:
                print("[{}]Try to restart Server fail!".format(timestamp()))
    else:
        # if open_browser_flag == False:
        #     webbrowser.open("http://127.0.0.1:"+Conf.conf["FwdSetting"][0]["LocalPort"])
        #     open_browser_flag = True
        if bakstatus != link.is_alive:
            print("[{}]Server has connected!".format(timestamp()))
            bakstatus = link.is_alive
    time.sleep(1)
