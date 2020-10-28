#!/usr/bin/python
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.layers.ssl_tls import *
# try:
#     from scapy_ssl_tls.ssl_tls import *
# except ImportError:
#     from scapy.layers.ssl_tls import *
from readfile import *
import os
import logging
import pymysql.cursors


load_layer("tls")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
warnings.filterwarnings("default", category=DeprecationWarning)

ciphernum_list = []
with open(r'C:\Users\ipc\Desktop\TLS_Project\cipher_number.txt')as f:
    ciphers = f.readlines()
    for item in ciphers:
        ciphernum_dict = {}
        cipher = re.split('\s+', item)[0]
        number = re.split('\s+', item)[1]
        ciphernum_dict['cipher'] = cipher
        ciphernum_dict['number'] = number
        ciphernum_list.append(ciphernum_dict)
    # print(ciphernum_list)

with open(r'C:\Users\ipc\Desktop\TLS_Project\ciphers_list.txt')as f:
    ciphers = f.readlines()
    cipher_list = []
    for item in ciphers:
        cipher = re.split('\s+', item)[0]
        cipher_list.append(cipher)
    # print(cipher_list)

version_list = [{'number': 769, 'version': 'TLS1.0'}, {'number': 770, 'version': 'TLS1.1'},{'number': 771, 'version': 'TLS1.2'}]

def parseFun(filepath, item):
    pkts = rdpcap(filepath)
    for pkt in pkts:
    #     if pkt['TCP'].sport<1000:
    #         print(pkt['TCP'].sport)
    #     print(pkt.show())
        if pkt['TCP'].dport == 443:
            if pkt.haslayer(TLSClientHello):
                item['proto'] = 'https'
                clienthello = pkt.getlayer(TLSClientHello)
                # print(clienthello.show())
                clienttime = pkt.time
                # print(clienttime)
                item['ctime'] = clienttime
                # print(item)
                break
            else:
                continue
        elif pkt['TCP'].dport == 80:
            item['proto'] = 'http'
            # print(item)
            break
        else:
            continue


    for pkt in pkts:
        if pkt['TCP'].sport == 443:
            if pkt.haslayer(TLSServerHello):
                # print(pkt[TLSServerHello].show())
                item['proto'] = 'https'
                serverhello = pkt.getlayer(TLSServerHello)
                # print(serverhello.show())
                servertime = pkt.time
                # print(servertime)
                item['stime'] = servertime
                # tls_version = pkt.version
                # print(tls_version)
                num = pkt[TLSServerHello].cipher_suite
                # print(type(num))
                for ciphernum_dict in ciphernum_list:
                    # print(type(ciphernum_dict['number']))
                    if int(ciphernum_dict['number']) == num:
                        # print(ciphernum_dict['number'])
                        cipher = ciphernum_dict['cipher']
                        item['cipher_suit'] = cipher
                        # print(item['cipher_suit'])
                        if cipher in cipher_list[0:5:1]:
                            item['version'] = 'TLS1.3'
                        else:
                            num = pkt[TLSServerHello].version
                            for version_dict in version_list:
                                if version_dict['number'] == num:
                                    item['version'] = version_dict['version']
                                else:
                                    continue
                        # print(item['version'])
                    else:
                        continue
                print(item)
                break
            else:
                continue
        elif pkt['TCP'].sport == 80:
            item['proto'] = 'http'
            print(item)
            break
        else:
            continue

def domain_analysis(dname):
    try:
        domain_str = "curl -Ivs https://%s --connect-timeout 10" % dname.encode("UTF-8")
        return_code, output = subprocess.getstatusoutput(domain_str)

        m = re.search('SSL connection using (.*?)\n.*?start date: (.*?)\n.*?expire date: (.*?)\n.*?issuer: (.*?)\n.*?',output, re.S)
        if m:
            # print('------------')
            start_date = m.groups()[1]
            expire_date = m.groups()[2]
            issuer = m.groups()[3]
            agreement = m.groups()[0]
            # time 字符串转时间数组
            start_date = time.strptime(start_date, "%b %d %H:%M:%S %Y GMT")
            start_date_st = time.strftime("%Y-%m-%d %H:%M:%S", start_date)
            # datetime 字符串转时间数组
            expire_date = datetime.strptime(expire_date, "%b %d %H:%M:%S %Y GMT")
            expire_date_st = datetime.strftime(expire_date, "%Y-%m-%d %H:%M:%S")

            # 剩余天数
            # remaining = (expire_date-datetime.now()).days
            version = ''
            encryption = ''
            if agreement:
                version = agreement.split(' / ')[0]
                encryption = agreement.split(' / ')[1]

            dic = {i.split("=")[0]: i.split("=")[1] for i in issuer.split("; ")}
            print(dname)
            print(start_date_st)
            print(expire_date_st)
            print(dic['CN'])
            print(version)
            print(encryption)
            return {
                "domain": dname,
                "start_date": start_date_st,
                "expire_date": expire_date_st,
                "issuer": dic['CN'],
                "tls_version": version,
                "encryption": encryption
            }
    except Exception as e:
        logger.error(u'域名获取证书异常:%s' % e)
    return {
        "domain": dname,
        "start_date": '',
        "expire_date": '',
        "issuer": '',
        "tls_version": '',
        "encryption": ''
    }

def saveInfo(item):
    # 连接数据库
    connect = pymysql.Connect(
        host='127.0.0.1',
        # port=3306,
        user='root',
        passwd='wang10221720',
        db='tls_project',
        charset='utf8'
    )

    # 获取游标
    cursor = connect.cursor()

    # # 删除表
    # sql = 'DROP TABLE IF EXISTS student'
    # cursor.execute(sql)
    # connect.commit()
    # print('如果存在表就删除表格')
    #
    # # 创建表格
    # sql = "CREATE TABLE student(id INTEGER PRIMARY KEY,name TEXT)"
    # try:
    #     cursor.execute(sql)
    #     connect.commit()
    # except:
    #     print("表已存在")
    # print('成功创建表格')

    # 插入数据
    sql = "INSERT INTO tls_project VALUES(%s,%s,%s,%s,%s,%s,%s,%s) WHERE not exists (SELECT item.get('dname') FROM tls_project)"
    data = (item.get('dname'), item.get('IP'), item.get('proto'), item.get('ctime'), item.get('stime'), item.get('TLS_version'), item.get('cipher_suit'), item.get('VPS'))
    cursor.execute(sql % data)
    connect.commit()
    print('成功插入', cursor.rowcount, '条数据')

    # # 查询数据方法2，注意这种方式会自动帮你添加引号
    # sql = "INSERT INTO student VALUES(%s,%s)"
    # data = (1, 'student1')
    # cursor.execute(sql, data)
    # connect.commit()
    # print('成功插入', cursor.rowcount, '条数据')

    # # 修改数据
    # sql = "UPDATE student SET name = '%s' WHERE id = %d "
    # data = ('student2', 1)
    # cursor.execute(sql % data)
    # connect.commit()
    # print('成功修改', cursor.rowcount, '条数据')

    # # 查询数据
    # sql = "SELECT * FROM student WHERE id=%d"
    # data = (1,)
    # cursor.execute(sql % data)
    # for row in cursor.fetchall():
    #     print("%s" % str(row))
    # print('共查找出', cursor.rowcount, '条数据')
    #
    # # 删除数据
    # sql = "DELETE FROM student WHERE id = %d LIMIT %d"
    # data = (1, 1)
    # cursor.execute(sql % data)
    # connect.commit()
    # print('成功删除', cursor.rowcount, '条数据')

    # # 事务处理
    # sql_1 = "UPDATE student SET name = name + '1' WHERE id = 1 "
    #
    # try:
    #     cursor.execute(sql_1)
    # except Exception as e:
    #     connect.rollback()  # 事务回滚
    #     print('事务处理失败', e)
    # else:
    #     connect.commit()  # 事务提交
    #     print('事务处理成功', cursor.rowcount)

    # 关闭连接
    cursor.close()
    connect.close()


if __name__ == "__main__":
    items_list = readfile(r"C:\Users\ipc\Desktop\TLS_Project\filetest.txt")
    # print(items_list)
    path = r"C:\Users\ipc\Desktop\TLS_Project\datapackets"

    files = os.listdir(path)
    # print(files)
    for file in files:
        filepath = path + "\\" + file
        # print(filepath)
        for item in items_list:
            if file.replace('_', '.')[:-5] == item.get('dname'):
                dname = item.get('dname')
                IPs = item.get('IP')
                # print(IPs)
                # item = parseFun(filepath, item)
                # domain_analysis(dname)
                # saveInfo(item)
                parseFun(filepath, item)
                break
            else:
                continue
