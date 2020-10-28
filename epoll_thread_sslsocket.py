# !/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import ssl
import re
from readfile import *
import datetime
import time
import select
import random
import threading
from queue import Queue


def s():
    for i in range(50):
        s = socket.socket()
        sock = context.wrap_socket(s, do_handshake_on_connect=False)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, True)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
        # epoll.register(sock.fileno(), select.EPOLLOUT|select.EPOLLIN)
        ssock.put(sock)
    # print('ssock', ssock.qsize(), ssock)


def startQ(h):
    while len(h):
        hostname = random.choice(h)
        hhost.put(hostname)
        h.remove(hostname)
        # print('hhost', hhost.qsize(), hhost.queue)
        # print('h', len(h), h)
    return hhost


def startConn(hhost):
    while hhost.qsize():
        # print('startConn', hhost.qsize())
        d = {}
        sock = ssock.get()
        # print('startConn', sock)
        d['sock'] = sock
        hostname = hhost.get()
        d['hostname'] = hostname
        # print(hostname)
        d['count'] = 1
        while True:
            try:
                # n = sock.connect_ex((hostname, 443))
                sock.connect((hostname, 443))
                epoll.register(sock.fileno(), select.EPOLLOUT | select.EPOLLIN)
                # print('000000000000000000000000000000000000000')
                # d['connected'] = n
                # print('dict', d)
                # res.put(d)
                # print('startconn:  res', res.qsize(), res.queue)
                res.append(d)
                print('startconn:  res', len(res), res)
                break
            except BlockingIOError:
                # print('111111111111111111111111111111111111')
                continue
            except Exception as e:
                # print('startconn:  e', e)
                # print('dict', d)
                err.put(d)
                print('startconn:  err', err.qsize(), err.queue)
                break
    return res, err


def reConn(err, resdict, errhost):
    while True:
        while err.qsize():
            d = err.get()
            sock = d.get('sock')
            hostname = d.get('hostname')
            count = d.get('count') + 1
            if count <= 3:
                sock = ssock.get()
                d['sock'] = sock
                d['count'] = count
                while True:
                    try:
                        sock.connect((hostname, 443))
                        epoll.register(sock.fileno(), select.EPOLLOUT | select.EPOLLIN)
                        # print('000000000000000000000000000000000000000')
                        res.append(d)
                        print('reconn:  res', len(res), res)
                        break
                    except BlockingIOError:
                        # print('111111111111111111111111111111111111')
                        continue
                    except Exception as e:
                        # print('reconn:  e', e)
                        err.put(d)
                        print('reconn:  err', err.qsize(), err.queue)
                        break
            else:
                sock.close()
                errhost.append(hostname)
                print('reconn:  errhost', len(errhost), errhost)
        # if err.qsize() == 0 and res.qsize() == 0 and hhost.qsize() == 0 and len(h) == 0:
        if len(resdict) + len(errhost) == num:
            print('--------------------------------')
            break


def extractProc(res, errhost, resdict):
    while True:
        # while not len(res):
        #     # print('sleepsleepsleepsleepsleepsleepsleepsleep')
        #     time.sleep(1)
        while len(res):
            events = epoll.poll(1)
            print(events)
            for fileno, event in events:
                # if event == select.EPOLLOUT:
                # print('EPOLLOUT', fileno, event)
                try:
                    dict = [dict for dict in res if dict.get('sock').fileno() == fileno][0]
                    # print(dict)
                except:
                    continue
                sock = dict.get('sock')
                try:
                    stime = time.time()
                    sock.do_handshake()
                    etime = time.time()
                    print('3333333333333333333333333333333333333333333')
                    # print('stime:', stime)
                    # print('etime:', etime)
                    # hostname = dict.get('hostname')
                    dict['ttime'] = etime - stime
                    dict['version'] = sock.version()
                    dict['cipher'] = sock.cipher()[0]
                    dict['cert'] = sock.getpeercert()
                    # print(dict)
                    res.remove(dict)
                    resdict.append(dict)
                    print('extractproc:  resdict', len(resdict), resdict)
                    epoll.unregister(sock.fileno())
                    sock.close()
                    # time.sleep(3)
                    continue
                except ssl.SSLWantReadError:
                    # print('22222222222222222222222222222222222222222')
                    continue
                except ssl.SSLWantWriteError:
                    # print('22222222222222222222222222222222222222222')
                    continue
                except Exception as e:
                    print('extractproc: ', e, dict)
                    epoll.unregister(sock.fileno())
                    sock.close()
                    res.remove(dict)
                    err.put(dict)
                    # time.sleep(5)
                    continue
        # # if res.qsize() == 0 and err.qsize() == 0 and hhost.qsize() == 0 and len(h) == 0:
        if len(resdict) + len(errhost) == num:
            print('+++++++++++++++++++++++++++++++++++++++++')
            break


if __name__ == "__main__":
    items_list = readfile(r"/home/ziteng/Documents/TLS_Project/filetest.txt")

    with open(r'/home/ziteng/Documents/TLS_Project/ciphers_list.txt')as f:
        ciphers = f.readlines()
        cipher_list = []
        for item in ciphers:
            cipher = re.split('\s+', item)[0]
            cipher_list.append(cipher)

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

    epoll = select.epoll()

    set_size = 256
    ssock = Queue(maxsize=0)

    h = []

    for item in items_list:
        h.append(item.get('dname'))

    num = len(h)

    hhost = Queue(maxsize=3)
    res = []
    err = Queue(maxsize=0)
    errhost = []
    resdict = []

    s()

    t1 = threading.Thread(target=startQ, args=(h,))
    t2 = threading.Thread(target=startConn, args=(hhost,))
    t3 = threading.Thread(target=extractProc, args=(res, errhost, resdict))
    t4 = threading.Thread(target=reConn, args=(err, resdict, errhost))

    t1.start()
    t2.start()
    t3.start()
    t4.start()
