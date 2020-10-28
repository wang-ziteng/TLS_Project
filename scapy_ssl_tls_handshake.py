#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import ssl
from scapy.all import *
from scapy_ssl_tls.ssl_tls import *
import OpenSSL
import re
from readfile import *
from scapy.all import *
import datetime
import time


with open(r'C:\Users\ipc\Desktop\TLS_Project\ciphers_list.txt')as f:
    ciphers = f.readlines()
    cipher_list = []
    for item in ciphers:
        cipher = re.split('\s+', item)[0]
        cipher_list.append(cipher)
    # print(cipher_list)

def connectFun(hostname):
    target = (hostname, 443)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(target)

    draft_version = 18

    # cpkt = TLSRecord() / TLSHandshakes(handshakes=[TLSHandshake() /
    #                                             TLSClientHello(
    #                                                            # cipher_suites=cipher_list,
    #                                                            cipher_suites=list(range(0xff)),
    #                                                            compression_methods=list(range(0xff)),
    #                                                            extensions=[TLSExtension() /
    #                                                                         TLSExtSupportedVersions(versions=[
    #                                                                                                           tls_draft_version(draft_version),
    #                                                                                                           # TLSVersion.TLS_1_3,
    #                                                                                                           TLSVersion.TLS_1_2,
    #                                                                                                           TLSVersion.TLS_1_1,
    #                                                                                                           TLSVersion.TLS_1_0
    #                                                                         ])
    #                                                                        ]
    #                                                            )])

    cpkt = TLSRecord() / TLSHandshakes(handshakes=[TLSHandshake() /
                                                   TLSClientHello(
                                                       version=TLSVersion.TLS_1_3,
                                                       # cipher_suites=cipher_list,
                                                       cipher_suites=list(range(0xff)),
                                                       compression_methods=list(range(0xff)),
                                                       extensions=[TLSExtension() /
                                                                       TLSExtSupportedVersions(versions=[tls_draft_version(draft_version)])]
                                                   )])

    # print("sending TLS payload")
    # cpkt.show()
    s.sendall(bytes(cpkt))
    resp = s.recv(1024 * 8)
    # print("received, %d --  %s" % (len(resp), repr(resp)))
    spkt = SSL(resp)
    # spkt.show()
    s.close()
    return cpkt, spkt

def featureFun(cpkt,spkt):
    # cpkt.show()
    # spkt.show()
    if spkt.haslayer(TLSServerHello):
        print("yes")
        spkt[TLSServerHello].show()
    else:
        print(spkt.show())


    # print(SSL(resp).haslayer(TLSAlert))
    # print(SSL(resp)[TLSAlert].level)
    # print(SSL(resp)[TLSAlert].description)
    # if SSL(resp).haslayer(TLSAlert)and SSL(resp)[TLSAlert].level == 2 and SSL(resp)[TLSAlert].description == 70:
    #     p_0.show()
    #     s.sendall(bytes(p_0))
    #     resp = s.recv(1024 * 8)
    #     print("received, %d --  %s" % (len(resp), repr(resp)))
    #     SSL(resp).show()
    # else:
    #     print("received, %d --  %s" % (len(resp), repr(resp)))
    #     # p_3.show()
    #     SSL(resp).show()
    # s.close()


    # p_0.show()
    # print("sending TLS payload")
    # s.sendall(bytes(p_0))
    # resp = s.recv(1024 * 8)
    # print("received, %d --  %s" % (len(resp), repr(resp)))
    # SSL(resp).show()
    # s.close()



# sock = ssl.wrap_socket(sock,
#                        ciphers="HIGH:-aNULL:-eNULL:-PSK:RC4-SHA:RC4-MD5",
#                        ssl_version=ssl.PROTOCOL_TLSv1,
#                        cert_reqs=ssl.CERT_REQUIRED,
#                        ca_certs='/etc/ssl/certs/ca-bundle.crt')
# # getpeercert() triggers the handshake as a side effect.
# if not check_host_name(sock.getpeercert(), host):
#     raise IOError("peer certificate does not match host name")
#
# sock.write("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
# print sock.read()

# sock.close()

if __name__ == "__main__":
    items_list = readfile(r"C:\Users\ipc\Desktop\TLS_Project\filetest.txt")
    for item in items_list:
        dname_target = item.get('dname')
        IPs = item.get('IP')
        print(dname_target)
        # print(IPs)
        cpkt, spkt =connectFun(dname_target)
        featureFun(cpkt, spkt)

    # cpkt,spkt =connectFun('www.cloudflare.com')
    # featureFun(cpkt,spkt)
