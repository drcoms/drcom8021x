#coding=utf-8
import os
import multiprocessing
import drcom
import eapauth

user_info = {'username': "",
             'password': "",
             'ethernet_interface': "eth0",
             'daemon': False,
             'dhcp_command': ''
             }

need_drcom = True

if not (os.getuid() == 0):
    print 'Need root'
    exit(-1)
    
# 802.1x成功以后就进入正常drcom认证
if need_drcom:
    auth = eapauth.EAPAuth(user_info, success_handler=drcom.main)
    auth.serve_forever()
else:
    auth = eapauth.EAPAuth(user_info)
    auth.serve_forever()
