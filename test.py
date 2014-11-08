#!/usr/bin/env python
# -*- coding:utf-8 -*-
""" DrCOM 802.1x Authentication
    Forked from: http://github.com/humiaozuzu/YaH3C
"""

import os, sys
import ConfigParser
import getpass
import argparse
import logging

import eapauth
import usermgr

user_info = {'username': "",
             'password': "",
             'ethernet_interface': "eth0",
             'daemon': False,
             'dhcp_command': "dhclient eth0"
             }

def start_yah3c(login_info):
    yah3c = eapauth.EAPAuth(login_info)
    yah3c.serve_forever()

def main():
    # check for root privilege
    if not (os.getuid() == 0):
        print 'Need root'
        exit(-1)

    logging.basicConfig(level=logging.DEBUG,
            format='%(asctime)s %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S')
    logging.debug('Debugging mode enabled.')

    login_info = user_info
    logging.debug(login_info)
    start_yah3c(login_info)

if __name__ == "__main__":
    main()
