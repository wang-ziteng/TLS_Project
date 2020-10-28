#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import ssl
# import OpenSSL
import re
from readfile import *
import datetime
import time
# from socket import AF_INET, AF_INET6, SOCK_STREAM, error, MSG_PEEK, SHUT_RDWR
# from errno import EAFNOSUPPORT, ECONNREFUSED, EINPROGRESS, EWOULDBLOCK, EPIPE, ESHUTDOWN
# from OpenSSL.SSL import Error, SysCallError, WantReadError, WantWriteError, ZeroReturnError
# from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM
# from OpenSSL.crypto import PKey, X509, X509Extension, X509Store
from pprint import pprint



# print(OpenSSL.SSL.SSLeay_version)
# print( OpenSSL.SSL.OPENSSL_VERSION_NUMBER)
# print( OpenSSL.SSL.OP_NO_TLSv1_3)
# print(OpenSSL.SSL.TLSv1_2_METHOD)
# print(OpenSSL.SSL.TLS_METHOD)


use_ssl=True
# hostname = 'www.cloudflare.com'

with open(r'/home/ziteng/Documents/TLS_Project/ciphers_list.txt')as f:
    ciphers = f.readlines()
    cipher_list = []
    for item in ciphers:
        cipher = re.split('\s+', item)[0]
        cipher_list.append(cipher)
    # print(cipher_list)

def connFun(hostname, IPs):
#     context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_SSLv2
    context.set_ciphers(', '.join(cipher_list))
    context.verify_mode = ssl.CERT_REQUIRED
    # context.verify_mode = ssl.CERT_NONE
    context.check_hostname = True
    context.load_default_certs()
    # ssl.get_server_certificate()函数获取服务器证书，以PEM格式返回
    # cert = ssl.get_server_certificate((hostname, 443))

    # x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

    # ctime = time.strftime("%Y/%m/%d  %I:%M:%S")
    ctime = time.time()
    s = socket.socket()
    sock = context.wrap_socket(s, server_hostname=hostname)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # sock.setblocking(False)
    sock.connect((hostname, 443))

    # result = {
    #     'subject': dict(x509.get_subject().get_components()),
    #     'issuer': dict(x509.get_issuer().get_components()),
    #     'serialNumber': x509.get_serial_number(),
    #     'version': x509.get_version(),
    #     'notBefore': x509.get_notBefore(),
    #     'notAfter': x509.get_notAfter(),
    # }
    #
    # extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
    # extension_data = {e.get_short_name(): str(e) for e in extensions}
    # result.update(extension_data)

    # print(hostname)
    # print(IPs)
    # print(sock.version())
    item['version'] = sock.version()
    # print(sock.cipher()[0])
    item['cipher'] = sock.cipher()[0]
    # stime = time.strftime("%Y/%m/%d  %I:%M:%S")
    stime = time.time()
    # print(ctime)
    item['ctime'] = ctime
    # print(stime)
    item['stime'] = stime
    # print(x509.get_subject().get_components())
    # c.getpeercert(True)，以二进制DER格式返回证书
    # pprint(sock.getpeercert())
    # print(cert)
    # pprint(result)
    # item['cert'] = result
    item['cert'] = sock.getpeercert()

    # print(item)

    sock.close()


def httpsFun(hostname):
    s = socket.socket()
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # s.setblocking(False)
    s.connect((hostname, 80))
    headers = {
        'User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36',
        'Accept-Language:zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding:gzip, deflate, br',
        'Cache-Control:max-age=0',
        'Connection:keep-alive',
        'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    }
    s.send(('GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % (hostname)).format(headers).encode())
    resp = s.recv(1024*8).decode()
    # print(resp)
    pat = re.search("200 OK", resp)
    if pat is not None:
        # print('https, http')
        item['proto'] = 'https, http'
    else:
        # print('https')
        item['proto'] = 'https'
    # print('normal:')
    print(item)

def httpFun(hostname):
    s = socket.socket()
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # s.setblocking(False)
    s.connect((hostname, 80))
    headers = {
        'User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36',
        'Accept-Language:zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding:gzip, deflate, br',
        'Cache-Control:max-age=0',
        'Connection:keep-alive',
        'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    }
    s.send(('GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % (hostname)).format(headers).encode())
    resp = s.recv(1024*8).decode()
    # print(resp)
    pat = re.search("200 OK", resp)
    if pat is not None:
        item['proto'] = 'http'
    else:
        item['proto'] = ''
    # print('exception:')
    print(item)


def main(hostname,IPs):
    try:
        connFun(hostname, IPs)
        httpsFun(hostname)
    except Exception as e:
        print(e)
        httpFun(hostname)

# raisedonors.com		2606:4700::6810:4687	2606:4700::6810:4387	2606:4700::6810:4587	2606:4700::6810:4487	104.16.71.135	104.16.68.135	104.16.69.135	104.16.67.135	104.16.70.135
# [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired (_ssl.c:1108)

if __name__ == "__main__":
    items_list = readfile(r"/home/ziteng/Documents/TLS_Project/filetest.txt")
    starttime = time.time()
    for item in items_list:
        dname_target = item.get('dname')
        IPs = item.get('IP')
        # print(dname_target)
        # print(IPs)
        main(dname_target, IPs)
    # main('www.goodjd.com',['104.16.71.135'])

    endtime = time.time()
    print(starttime)
    print(endtime)


    # connFun('www.cloudflare.com')