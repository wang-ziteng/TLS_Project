#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import ssl
# import OpenSSL
import re
from readfile import *
import datetime
import time
import select
import random
import threading
import multiprocessing
import numpy

with open(r'/home/ziteng/Documents/TLS_Project/ciphers_list.txt')as f:
    ciphers = f.readlines()
    cipher_list = []
    for item in ciphers:
        cipher = re.split('\s+', item)[0]
        cipher_list.append(cipher)
    # print(cipher_list)


def s1():
    for i in range(len(h1)):
        s = socket.socket()
        s = context.wrap_socket(s, do_handshake_on_connect=True)
        s.setblocking(False)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, True)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        s.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
        epoll1.register(s.fileno(), select.EPOLLOUT)
        ss1.append(s)


def s2():
    for i in range(len(h2)):
        s = socket.socket()
        s.setblocking(False)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, True)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        s.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
        epoll2.register(s.fileno(), select.EPOLLOUT)
        ss2.append(s)


def c(s1, s2):
    s1()
    s2()
    while True:
        events1 = epoll1.poll(1)
        events2 = epoll2.poll(1)
        print(events1)
        print(events2)
        # time.sleep(1)
        for fileno, event in events1:
            print(ss1)
            s = [s for s in ss1 if s.fileno() == fileno][0]
            hostname = random.choice(h1)
            print(hostname)
            print('s.fileno()')
            print(s.fileno())
            print(fileno)
            if event != select.EPOLLOUT:
                try:
                    # epoll1.unregister(s.fileno())
                    # s = context.wrap_socket(s, do_handshake_on_connect=True)
                    print('socksocksocksocksocksocksock')
                    # print(s)
                    # print('sock.fileno')
                    # print(s.fileno())

                    # epoll1.register(s.fileno())
                    # print(s.fileno())
                    # err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    # print(err)
                    s.connect((hostname, 443))
                    print('okokokokokokokokokokokokokok')
                    time.sleep(3)
                    # n = s.connect_ex((hostname, 443))
                    # print(n)
                    # while n:
                    #     time.sleep(1)
                    #     print('sleep')
                    #     n = s.connect_ex((hostname, 443))
                    # if not s.connected:
                    #     err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    #     print(err)
                    # print('connected')
                    # print(s.fileno())
                    # # s.do_handshake()
                    # # s.setblocking(False)
                    # sock_ready[s.fileno()] = True
                    # print(sock_ready[s.fileno()])
                    # print(s.fileno())
                    # epoll1.modify(s.fileno(), select.EPOLLIN)
                    h1.remove(hostname)
                    print('remove')
                    print(hostname)
                except BlockingIOError:
                    print('BlockingIOError')
                    continue
                except ssl.SSLWantReadError:
                    print('ssl.SSLWantReadError')
                    continue
                except Exception as e:
                    print(e)
                    continue
                    # if e == "attempt to connect already-connected SSLSocket!":
                    #     print('attempt to')
                    #     item['version'] = s.version()
                    #     print(item['version'])
                    # else:
                    #     print(e)
                    #     v = s.version()
                    #     print(v)

            if event == select.EPOLLOUT and event != select.EPOLLIN:
                v = s.version()
                print(v)
                cip = s.cipher()
                print(cip)
                # item['ctime'] = ctime
                # item['stime'] = stime
                # item['ssl_time'] = ssl_time
                print(s)
                # cer = s.getpeercert(True)
                # print(cer)
                # item['https'] = 'Y'
                # print(item)
                s.close()
            else:
                continue
        for fileno, event in events2:
            print(ss2)
            s = [s for s in ss2 if s.fileno() == fileno][0]
            hostname = random.choice(h2)
            print(hostname)
            print('s.fileno()')
            print(s.fileno())
            print(fileno)
            try:
                s.connect((hostname, 80))
                print('connected')
                s.setblocking(False)
                s_ready[s.fileno()] = True
                print(s_ready[s.fileno()])
                h2.remove(hostname)
            except:
                if s_ready[s.fileno()]:
                    if event == select.EPOLLOUT:
                        headers = {
                            'User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36',
                            'Accept-Language:zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                            'Accept-Encoding:gzip, deflate, br',
                            'Cache-Control:max-age=0',
                            'Connection:keep-alive',
                            'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
                        }
                        s.sendall(('GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % hostname).format(headers).encode())
                        print('send it')
                        epoll2.modify(fileno, select.EPOLLIN)
                    elif event == select.EPOLLIN:
                        while True:
                            try:
                                resp = s.recv(1024).decode()
                                # print(resp)
                                if resp:
                                    # print(data)
                                    res[s.fileno()] = str(res[s.fileno()]) + resp
                                    if len(str(res[s.fileno()])) < set_size:
                                        print('ccccccccccccccccccc')
                                        continue
                                    else:
                                        print('iiiiiiiiiiiiiiiiiii')
                                        print('fileno:')
                                        print(s.fileno())
                                        print(hostname)
                                        # print(res[sock.fileno()])
                                        pat = re.search("200 OK", str(res[s.fileno()]))
                                        if pat is not None:
                                            item['http'] = 'Y'
                                            epoll2.unregister(s.fileno())
                                            s.close()
                                        else:
                                            item['http'] = 'N'
                                            epoll2.unregister(s.fileno())
                                            s.close()
                                        print(item)
                                        break
                                else:
                                    print('------------------------')
                                    print('fileno:')
                                    print(s.fileno())
                                    print(hostname)
                                    # print(res[s.fileno()])
                                    pat = re.search("200 OK", str(res[s.fileno()]))
                                    if pat is not None:
                                        item['http'] = 'Y'
                                        epoll2.unregister(s.fileno())
                                        s.close()
                                    else:
                                        item['http'] = 'N'
                                        epoll2.unregister(s.fileno())
                                        s.close()
                                    print(item)
                                    break
                            except BlockingIOError:
                                print('nonononononononononononononononono')
                                res[s.fileno()] = res[s.fileno()]
                                print('fileno:')
                                print(s.fileno())
                                print(hostname)
                                # print(res[s.fileno()]
                                break
                            except ssl.SSLWantReadError:
                                print('yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy')
                                res[s.fileno()] = res[s.fileno()]
                                print('fileno:')
                                print(s.fileno())
                                print(hostname)
                                # print(res[s.fileno()]
                                break
                else:
                    continue
        print(h1)
        print(h2)


def t(c):
    for i in range(10):
        print("Thread %d Start" % i)
        t = threading.Thread(target=c, args=(s1,s2))
        t.start()


def p(t):
    for i in range(2):
        print("Process %d Start" %i)
        p = multiprocessing.Process(target=t, args=(c,))
        p.start()


if __name__ == "__main__":
    items_list = readfile(r"/home/ziteng/Documents/TLS_Project/filetest.txt")

    # import ssl
    # print(ssl.HAS_SNI)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_SSLv2
    context.set_ciphers(', '.join(cipher_list))
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    context.load_default_certs()

    # context = ssl.create_default_context()
    # context.check_hostname = False

    epoll1 = select.epoll()
    epoll2 = select.epoll()

    sock_ready = [False] * 100
    s_ready = [False] * 100
    # res = [0] * 100
    set_size = 256
    ss1 = []
    ss2 = []

    h1 = []
    h2 = []

    for item in items_list:
        h1.append(item.get('dname'))
        h2.append(item.get('dname'))
    # print(h1)
    # print(h2)
    res = [[] for _ in items_list]
    # p(t)
    c(s1, s2)
    # t(c)

    # ssock = []
    #
    # for item in items_list:
    #     dname_target = item.get('dname')
    #     hostname = dname_target
    #     try:
    #         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     except:
    #         s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    #     # s.setblocking(False)
    #
    #     s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #     s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 * 1024)
    #     s.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
    #
    #     # sock = context.wrap_socket(s, server_hostname=hostname,  do_handshake_on_connect=False)
    #
    #     s.setblocking(False)
    #     # sock.connect((hostname, 443))
    #     ssock.append(s)
    #     item['fileno'] = s.fileno()
    #     epoll.register(s.fileno(), select.EPOLLOUT)
    #
    # print(ssock)
    # print(epoll.fileno())
    # print(items_list)
    #
    # # for sock in ssock:
    # #     sock.setblocking(False)
    #
    # # epoll.register(sock.fileno() for sock in ssock, select.EPOLLOUT)
    # # epoll.register(*ssock, select.EPOLLOUT)
    # # epoll.register(map(regi, ssock), select.EPOLLOUT)
    #
    # res = [0] * 100
    # set_size = 10000
    #
    # ready = [False] * 100
    #
    # while True:
    #     events = epoll.poll(1)
    #     print(events)
    #     # break
    #
    #     for fileno, event in events:
    #         for item in items_list:
    #             if fileno == item.get('fileno'):
    #                 hostname = item.get('dname')
    #                 print(hostname)
    #                 # items_list.remove(item)
    #                 break
    #             continue
    #         for s in ssock:
    #             if fileno == s.fileno():
    #                 s = s
    #                 # print('sock.fileno()')
    #                 print(s.fileno())
    #                 # ssock.remove(sock)
    #                 break
    #             continue
    #         item = {}
    #
    #         if not ready[fileno]:
    #             # if event & select.EPOLLHUP:
    #             ctime = time.time()
    #             print(ctime)
    #             try:
    #                 sock = context.wrap_socket(s, server_hostname=hostname, do_handshake_on_connect=True)
    #                 sock.connect((hostname, 443))
    #                 # sock.do_handshake()
    #                 stime = time.time()
    #                 ssl_time = stime - ctime
    #                 ready[fileno] = True
    #                 sock.setblocking(False)
    #                 # item = {}
    #                 item['dname'] = hostname
    #                 item['version'] = sock.version()
    #                 item['cipher'] = sock.cipher()[0]
    #                 # item['ctime'] = ctime
    #                 # item['stime'] = stime
    #                 item['ssl_time'] = ssl_time
    #                 item['cert'] = sock.getpeercert()
    #                 item['https'] = 'Y'
    #                 print(item)
    #                 epoll.modify(fileno, select.EPOLLOUT)
    #             except ssl.SSLWantReadError:
    #                 pass
    #             except BlockingIOError:
    #                 pass
    #         if ready[fileno] == True:
    #             if event & select.EPOLLOUT:
    #                 headers = {
    #                             'User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36',
    #                             'Accept-Language:zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    #                             'Accept-Encoding:gzip, deflate, br',
    #                             'Cache-Control:max-age=0',
    #                             'Connection:keep-alive',
    #                             'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    #                             }
    #                 sock.sendall(('GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % hostname).format(headers).encode())
    #                 print('send it')
    #                 epoll.modify(fileno, select.EPOLLIN)
    #             elif event & select.EPOLLIN:
    #                 while True:
    #                     try:
    #                         resp = sock.recv(1024).decode()
    #                         # print(resp)
    #                         if resp:
    #                             # print(data)
    #                             res[sock.fileno()] = str(res[sock.fileno()]) + resp
    #                             if len(str(res[sock.fileno()])) < set_size:
    #                                 print('ccccccccccccccccccc')
    #                                 continue
    #                             else:
    #                                 print('iiiiiiiiiiiiiiiiiii')
    #                                 print('fileno:')
    #                                 print(sock.fileno())
    #                                 print(hostname)
    #                                 # print(res[sock.fileno()])
    #                                 pat = re.search("200 OK", str(res[sock.fileno()]))
    #                                 if pat is not None:
    #                                     item['http'] = 'Y'
    #                                     epoll.unregister(sock.fileno())
    #                                     sock.close()
    #                                 else:
    #                                     item['http'] = 'N'
    #                                     epoll.unregister(sock.fileno())
    #                                     sock.close()
    #                                 print(item)
    #                                 break
    #                         else:
    #                             print('------------------------')
    #                             print('fileno:')
    #                             print(sock.fileno())
    #                             print(hostname)
    #                             # print(res[sock.fileno()])
    #                             pat = re.search("200 OK", str(res[sock.fileno()]))
    #                             if pat is not None:
    #                                 item['http'] = 'Y'
    #                                 epoll.unregister(sock.fileno())
    #                                 sock.close()
    #                             else:
    #                                 item['http'] = 'N'
    #                                 epoll.unregister(sock.fileno())
    #                                 sock.close()
    #                             print(item)
    #                             break
    #                     except BlockingIOError:
    #                         print('nonononononononononononononononono')
    #                         res[sock.fileno()] = res[sock.fileno()]
    #                         print('fileno:')
    #                         print(sock.fileno())
    #                         print(hostname)
    #                         # print(res[sock.fileno()]
    #                         break
    #                     except ssl.SSLWantReadError:
    #                         print('yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy')
    #                         res[sock.fileno()] = res[sock.fileno()]
    #                         print('fileno:')
    #                         print(sock.fileno())
    #                         print(hostname)
    #                         # print(res[sock.fileno()]
    #                         break




                # # print(sock.read(resp))
                # print('fileno:')
                # print(sock.fileno())
                # print(hostname)
                # print(data)
                #
                #
                # pat = re.search("200 OK", resp)
                # if pat is not None:
                #     item['http'] = 'Y'
                #     epoll.unregister(sock.fileno())
                #     sock.close()
                # else:
                #     item['http'] = 'N'
                #     epoll.unregister(sock.fileno())
                #     sock.close()
                # print(item)

        # items.append(item)
        # print(items)
    # epoll.close()







    # for i in range(len(items_list)):
    #     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, True)
    #     # s.setblocking(False)
    #     # s.ioctl(socket.SIO_KEEPALIVE_VALS,
    #     #         (1,
    #     #          60*1000,
    #     #          30*1000)
    #     #         )
    #     ssock.append(s)
    #     epoll.register(s.fileno(), select.EPOLLIN | select.EPOLLOUT)
    #
    # print(ssock)
    # print(epoll.fileno())
    #
    # # for s in ssock:
    # #     print(s.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR))
    # # print('-------------------')
    # # for s in ssock:
    # #     print(s.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE))
    #
    # i = 0
    #
    # while True:
    #     events = epoll.poll(1)
    #     print(events)
    #     for fileno, event in events:
    #         s = ssock[i]
    #         if fileno == s.fileno():
    #             print('fileno:')
    #             print(fileno)
    #             print('s.fileno:')
    #             print(s.fileno())
    #             # print(s.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR))
    #             hostname = items_list[i].get('dname')
    #             ctime = time.time()
    #             sock = context.wrap_socket(s, server_hostname=hostname)
    #             sock.connect((hostname, 443))
    #             sock.setblocking(False)
    #             item = {}
    #             item['dname'] = hostname
    #             item['version'] = sock.version()
    #             item['cipher'] = sock.cipher()[0]
    #             stime = time.time()
    #             item['ctime'] = ctime
    #             item['stime'] = stime
    #             item['cert'] = sock.getpeercert()
    #             item['https'] = 'Y'
    #             print(item)
    #             # epoll.unregister(fileno)
    #             i += 1







        # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # sock.connect((hostname, 443))
        # sock.setblocking(False)
        # epoll = select.epoll()
        # epoll.register(sock.fileno(), select.EPOLLIN | select.EPOLLOUT)


    #     while True:
    #         events = epoll.poll(1)
    #         print('start')
    #         print(events)
    #         for fileno, event in events:
    #             if fileno == sock.fileno():
    #                 print(events)
    #                 item['version'] = sock.version()
    #                 item['cipher'] = sock.cipher()[0]
    #                 stime = time.time()
    #                 item['ctime'] = ctime
    #                 item['stime'] = stime
    #                 item['cert'] = sock.getpeercert()
    #                 item['https'] = 'Y'
    #                 print(item)
    #             #     sock = context.wrap_socket(s, server_hostname=hostname)
    #             #     sock.connect((hostname, 443))
    #             #     sock.setblocking(False)
    #             #     print(sock.fileno)
    #                 epoll.modify(sock.fileno(), select.EPOLLOUT)
    #                 print(events)
    #                 # epoll.register()
    #             #     # epoll = select.epoll()
    #             #     epoll.register(sock.fileno(), select.EPOLLIN)
    #             if fileno == sock.fileno() and event & select.EPOLLOUT:
    #                 print(events)
    #                 # print(sock.fileno)
    #                 headers = {
    #                             'User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36',
    #                             'Accept-Language:zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    #                             'Accept-Encoding:gzip, deflate, br',
    #                             'Cache-Control:max-age=0',
    #                             'Connection:keep-alive',
    #                             'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    #                             }
    #                 sock.sendall(('GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % hostname).format(headers).encode())
    #                 epoll.modify(fileno, select.EPOLLIN)
    #                 print('out')
    #                 print(sock.fileno())
    #                 print(events)
    #             if fileno == sock.fileno() and event & select.EPOLLIN:
    #                 print('in')
    #                 print(sock.fileno)
    #                 print(events)
    #                 resp = sock.recv(1024*8).decode()
    #                 if not len(resp):
    #                     break
    #                 pat = re.search("200 OK", resp)
    #                 if pat is not None:
    #                     item['http'] = 'Y'
    #                 else:
    #                     item['http'] = 'N'
    #             epoll.unregister(sock.fileno())
    #             sock.close()
    #             print('close')
    #             print(sock.fileno())
    #
    #         print('for')
    #         print(sock.fileno())
    #         print('end')
    #         print(events)
    #
    #         break
    # epoll.close()
    # print(epoll.fileno())







    # starttime = time.time()
    # # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ep = select.epoll()
    # for item in items_list:
    #     dname_target = item.get('dname')
    #     IPs = item.get('IP')
    #     try:
    #         context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    #         context.minimum_version = ssl.TLSVersion.TLSv1
    #         context.options |= ssl.OP_NO_SSLv3
    #         context.options |= ssl.OP_NO_SSLv2
    #         context.set_ciphers(', '.join(cipher_list))
    #         context.verify_mode = ssl.CERT_REQUIRED
    #         context.check_hostname = True
    #         context.load_default_certs()
    #
    #         ctime = time.time()
    #         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #         sock = context.wrap_socket(s, server_hostname=dname_target)
    #         sock.connect((dname_target, 443))
    #         sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #         sock.setblocking(False)
    #
    #         ep.register(sock.fileno(), select.EPOLLOUT)
    #         while True:
    #             events = ep.poll(1)
    #             for fileno, event in events:
    #                 if fileno == sock.fileno():
    #                     item['version'] = sock.version()
    #                     item['cipher'] = sock.cipher()[0]
    #                     stime = time.time()
    #                     item['ctime'] = ctime
    #                     item['stime'] = stime
    #                     item['cert'] = sock.getpeercert()
    #                     item['https'] = 'Y'
    #                     # print(item)
    #                 break
    #             sock.close()
    #             break
    #
    #     except Exception as e:
    #         print(e)
    #
    #     finally:
    #         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #         s.connect((dname_target, 80))
    #         s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #         # s.setblocking(False)
    #
    #         ep.register(s.fileno(), select.EPOLLOUT)
    #         while True:
    #             events = ep.poll(1)
    #             for fileno, event in events:
    #                 if fileno == s.fileno():
    #                     headers = {
    #                         'User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36',
    #                         'Accept-Language:zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    #                         'Accept-Encoding:gzip, deflate, br',
    #                         'Cache-Control:max-age=0',
    #                         'Connection:keep-alive',
    #                         'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    #                     }
    #                     s.send(('GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % (dname_target)).format(headers).encode())
    #                     resp = s.recv(1024*8).decode()
    #                     # print(resp)
    #                     pat = re.search("200 OK", resp)
    #                     if pat is not None:
    #                         item['http'] = 'Y'
    #                     else:
    #                         item['http'] = 'N'
    #                     print(item)
    #                 break
    #             s.close()
    #             break
    #
    # endtime = time.time()
    # print(starttime)
    # print(endtime)
