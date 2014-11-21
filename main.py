import multiprocessing
import drcom
import eapauth

user_info = {'username': "",
             'password': "",
             'ethernet_interface': "eth0",
             'daemon': False,
             'dhcp_command': "dhclient eth0"
             }

# 802.1x成功以后就进入正常drcom认证
auth = eapauth.EAPAuth(login_info, success_callback=drcom.main)
auth.serve_forever()
