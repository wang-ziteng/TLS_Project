#!/usr/bin/python
# -*- coding: utf-8 -*-

from scapy.all import *
load_layer("tls")
# import urllib
import webbrowser as web
# import socket
# import time
import os
from readfile import *
import threading

# from scapy.all import sniff, ls, ARP, IPv6, DNS, DNSRR, Ether, conf, IP, TCP, TLS


# def buildConn(dname):
#     # src = "192.168.1.104"
#     # for sport in range(1024, 65535):
#     #     IPlayer = IP(src=src, dst=dname)
#     #     TCPlayer = TCP(sport=sport, dport=443)
#     #     pkt = IPlayer / TCPlayer
#     #     send(pkt)
#     url = "https://" + dname
#     headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20100101 Firefox/23.0'}
#     req = urllib.request.Request(url=url,headers=headers)
#     resp = urllib.request.urlopen(req)
#     data = resp.read().decode('utf-8')
#     print(data)

# def buildConn(dname):
#     # web.open(dname, new=0, autoraise=True)
#     firefoxpath = r'D:\火狐浏览器\firefox.exe'
#     web.register('firefox', None, web.BackgroundBrowser(firefoxpath))
#     web.get('firefox').open(dname, new=0, autoraise=True)
#     time.sleep(10)
#     os.system('taskkill /F /IM firefox.exe')

# def buildConn(dname):
#     client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     client.connect((dname, 80))
#     while True:
#         msg = b'GET / HTTP/1.1\r\nHost: 192.168.1.104\r\n\r\n'
#         client.sendall(msg)
#         data = client.recv(1024)
#         print(data.decode("utf8"))
#         if data:
#             break
#         else:
#             continue
#         # client.close()


def handlePacket(p):
    # print(p.show())
    print(p.summary())
    # for IP in IPs:
    #     if p["IP"].src == IP or p["IP"].dst == IP:
    #         print(p.show())
    #         print(p.summary())
    #     else:
    #         continue


def connFun(dname,IPs):
    # packets = sniff(store=1,prn=handlePacket,filter="host 61.135.169.125",count=5)
    # packets = sniff(prn=lambda x: x.summary(), lfilter=lambda x: TLS in x)

    # 调用浏览器访问
    chromepath = r'C:\Users\ipc\AppData\Local\Google\Chrome\Application\chrome.exe'
    web.register('chrome', None, web.BackgroundBrowser(chromepath))
    web.get('chrome').open(dname, new=1, autoraise=True)

    # sr1(IP(dst=dname)/TCP()/"GET / HTTP/1.1\r\nHost: 192.168.1.104\r\n\r\nHEAD = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20100101 Firefox/23.0'}\r\n\r\n")

    packets = sniff(prn=handlePacket, lfilter= lambda x: TLS in x and (x.haslayer('IP')) and (x['IP'].src in IPs or x['IP'].dst in IPs), timeout = 10)

    # 关闭浏览器
    os.system('taskkill /F /IM chrome.exe')
    # buildConn(dname)

    if packets:
        print(packets)
    else:
        print("nonononono packets")
        web.get('chrome').open(dname, new=1, autoraise=True)
        packets = sniff(prn=handlePacket, lfilter=lambda x: x.haslayer('IP') and (x['IP'].src in IPs or x['IP'].dst in IPs), timeout=10)
        os.system('taskkill /F /IM chrome.exe')
        if packets:
            print(packets)
        else:
            print('还是没有')

    filepath = "C:\\Users\\ipc\\Desktop\\TLS_Project\\datapackets\\" + dname.replace(".", "_") + ".pcap"
    if not os.path.exists(filepath):
        f = open(filepath, 'w')
        f.close()
    wrpcap(filepath, packets)



if __name__ == "__main__":
    items_list = readfile(r"C:\Users\ipc\Desktop\TLS_Project\filetest.txt")
    # jobs = []

    for item in items_list:
        dname_target = item.get('dname')
        IPs = item.get('IP')
        print(dname_target)
        print(IPs)
        connFun(dname_target, IPs)
        # connFun('www.tintonfallsfiredistrict1.com',['2606:4700:3034::681c:a32', '2606:4700:3037::681c:b32', '104.28.11.50', '104.28.10.50'])
    #     thread = threading.Thread(target=connFun, args=(dname_target,IPs))
    #     jobs.append(thread)
    #
    # for j in jobs:
    #     threads = threading.active_count()
    #     while threads > 5:
    #         time.sleep(0.05)
    #         threads = threading.active_count()
    #     # print(threads)
    #     j.start()
    #
    # for j in jobs:
    #     j.join()
