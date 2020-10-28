# !/usr/bin/python
# -*- coding: utf-8 -*-

import socket
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
        sock = socket.socket()
        sock.setblocking(False)
        # epoll.register(sock.fileno(), select.EPOLLOUT)
        ssock.put(sock)
    # print('ssock', ssock.qsize(), ssock)


def startQ(h):
    while len(h):
        hostname = random.choice(h)
        hhost.put(hostname)
        h.remove(hostname)
    return hhost


def startConn(hhost):
    while hhost.qsize():
        d = {}
        sock = ssock.get()
        d['sock'] = sock
        hostname = hhost.get()
        d['hostname'] = hostname
        # print(hostname)
        d['count'] = 1
        d['resp'] = ''
        while True:
            try:
                sock.connect((hostname, 80))
                epoll.register(sock.fileno(), select.EPOLLOUT | select.EPOLLIN)
                # print('000000000000000000000000000000000000000')
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


def reConn(err):
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
                        sock.connect((hostname, 80))
                        epoll.register(sock.fileno(), select.EPOLLOUT | select.EPOLLIN)
                        # print('000000000000000000000000000000000000000')
                        res.append(d)
                        print('reconn:  res', len(res), res)
                        break
                    except BlockingIOError:
                        # print('111111111111111111111111111111111111')
                        continue
                    except Exception as e:
                        # print('startconn:  e', e)
                        # print('dict', d)
                        err.put(d)
                        print('reconn:  err', err.qsize(), err.queue)
                        break
            else:
                epoll.unregister(sock.fileno())
                sock.close()
                errhost.append(hostname)
                print('errhost', len(errhost), errhost)
        if len(resdict) + len(errhost) == num:
            print('------------------------------------------------------------------------------')
            break


def workProc(res):
    while True:
        while len(res):
            events = epoll.poll(1)
            print(events)
            for fileno, event in events:
                # print(fileno, event)
                if event == select.EPOLLOUT:
                    try:
                        dict = [dict for dict in res if dict.get('sock').fileno() == fileno][0]
                        sock = dict.get('sock')
                        hostname = dict.get('hostname')
                        headers = {
                            'User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36',
                            'Accept-Language:zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                            'Accept-Encoding:gzip, deflate, br',
                            'Cache-Control:max-age=0',
                            'Connection:keep-alive',
                            'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
                        }
                        sock.sendall(('GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % hostname).format(headers).encode())
                        print(hostname)
                        print('send it')
                        epoll.modify(fileno, select.EPOLLIN)
                    except:
                        continue
                if event == select.EPOLLIN:
                    try:
                        dict = [dict for dict in res if dict.get('sock').fileno() == fileno][0]
                    except:
                        continue
                    sock = dict.get('sock')
                    hostname = dict.get('hostname')
                    try:
                        resp = sock.recv(256).decode()
                        if resp:
                            dict['resp'] = dict.get('resp') + resp
                            if len(dict.get('resp')) < set_size:
                                print('ccccccccccccccccccc')
                                # print(dict['resp'])
                                continue
                            else:
                                rresp.put(dict)
                                print('ininininininininininnininininininininininininin')
                                print(hostname)
                                print(dict.get('resp'))
                                print('work:  rresp', rresp.qsize(), rresp.queue)
                                res.remove(dict)
                                epoll.unregister(sock.fileno())
                                sock.close()
                                continue
                        else:
                            print('++++++++++++++++++++++++++++++++')
                            print(hostname)
                            print(dict.get('resp'))
                            rresp.put(dict)
                            print('work:  rresp', rresp.qsize(), rresp.queue)
                            res.remove(dict)
                            epoll.unregister(sock.fileno())
                            sock.close()
                            continue
                    except Exception as e:
                        print('work', e)
                        continue
            if not events:
                print('lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllen(res)', len(res))
        if len(resdict) + len(errhost) == num:
            print('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
            break


def judgeProc(rresp):
    while True:
        while rresp.qsize():
            # print('judge:  rresp', rresp.qsize())
            dict = rresp.get()
            resp = dict.get('resp')
            pat200 = re.search("200 OK", resp)
            pat301 = re.search("301 Moved Permanently", resp)
            pathttps = re.search("Location: https://", resp)
            p = re.compile('(?<=Location: )[a-zA-Z]+://[^\s]*/')
            if pat200 is not None:
                dict['http'] = 'Y'
            elif pat301 is not None:
                if pathttps is not None:
                    print('pathttps')
                    dict['http'] = 'N'
                else:
                    try:
                        m = p.search(resp)
                        rehost = m.group()
                        print('rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrehost', rehost)
                        dict['http'] = 'Y'
                        dict['rehost'] = rehost
                    except:
                        dict['http'] = 'N'
            else:
                dict['http'] = 'N'
            resdict.append(dict)
            print('uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu')
            print('resdict', len(resdict), resdict)
        if len(resdict) + len(errhost) == num:
            print('ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo')
            break
    return resdict




if __name__ == "__main__":
    items_list = readfile(r"/home/ziteng/Documents/TLS_Project/filetest.txt")

    with open(r'/home/ziteng/Documents/TLS_Project/ciphers_list.txt')as f:
        ciphers = f.readlines()
        cipher_list = []
        for item in ciphers:
            cipher = re.split('\s+', item)[0]
            cipher_list.append(cipher)

    epoll = select.epoll()

    set_size = 300
    ssock = Queue(maxsize=0)

    h = []

    for item in items_list:
        h.append(item.get('dname'))

    num = len(h)

    hhost = Queue(maxsize=5)
    err = Queue(maxsize=0)
    rresp = Queue(maxsize=0)
    res = []
    errhost = []
    resdict = []

    s()

    t1 = threading.Thread(target=startQ, args=(h,))
    t2 = threading.Thread(target=startConn, args=(hhost,))
    t3 = threading.Thread(target=reConn, args=(err,))
    t4 = threading.Thread(target=workProc, args=(res,))
    t5 = threading.Thread(target=judgeProc, args=(rresp,))

    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t5.start()
