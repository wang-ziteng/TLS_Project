<<<<<<< HEAD
import re

# 读取文件，去掉分隔符，得到域名IP键值对
def readfile(filepath):
    with open(filepath)as f:
        items = f.readlines()
        items_list = []
        for item in items:
            item_data_list = re.split('\s+',item.strip('\n'))
            # print(item_data_list)
            item_dict = {}
            IP_list = []
            for item_data in item_data_list:
                # 匹配域名
                if re.match(r'[a-z]+(.[a-z])+',item_data):
                    item_dict['dname'] = item_data
                # 匹配IPV4地址
                elif re.match(r'(\d){1,3}(.(\d){1,3}){1,3}',item_data):
                    IP_list.append(item_data)
                # 匹配未简化的IPV6地址
                elif re.match(r'[A-Za-z0-9]{1,4}(:[A-Za-z0-9]{1,4}){7}',item_data):
                    IP_list.append(item_data)
                # 匹配使用“::”简化的IPV6地址
                elif re.match(r'[A-Za-z0-9]{0,4}(:[A-Za-z0-9]{1,4})*::[A-Za-z0-9]{0,4}(:[A-Za-z0-9]{1,4})*',item_data):
                    IP_list.append(item_data)
                else:
                    continue
            item_dict['IP'] = IP_list
            items_list.append(item_dict)
        # print(items_list)
    f.close()
    return items_list
    # print(items_list)

# # 提取域名以便访问
# def getdname(items_list):
#     for item in items_list:
#         dname_target = item.get('dname')
#         print(dname_target)
#
# # 提取IP以便访问
# def getIP(items_list):
#     for item in items_list:
#         IP_list = item.get('IP')
#         for IP_target in IP_list:
#             print(IP_target)

if __name__ == "__main__":
    items_list = readfile(r"C:\Users\ipc\Desktop\TLS_Project\filetest.txt")
    # print(items_list)
    # getdname(items_list)
    # getIP(items_list)
=======
import re

# 读取文件，去掉分隔符，得到域名IP键值对
def readfile(filepath):
    with open(filepath)as f:
        items = f.readlines()
        items_list = []
        for item in items:
            item_data_list = re.split('\s+',item.strip('\n'))
            # print(item_data_list)
            item_dict = {}
            IP_list = []
            for item_data in item_data_list:
                # 匹配域名
                if re.match(r'[a-z]+(.[a-z])+',item_data):
                    item_dict['dname'] = item_data
                # 匹配IPV4地址
                elif re.match(r'(\d){1,3}(.(\d){1,3}){1,3}',item_data):
                    IP_list.append(item_data)
                # 匹配未简化的IPV6地址
                elif re.match(r'[A-Za-z0-9]{1,4}(:[A-Za-z0-9]{1,4}){7}',item_data):
                    IP_list.append(item_data)
                # 匹配使用“::”简化的IPV6地址
                elif re.match(r'[A-Za-z0-9]{0,4}(:[A-Za-z0-9]{1,4})*::[A-Za-z0-9]{0,4}(:[A-Za-z0-9]{1,4})*',item_data):
                    IP_list.append(item_data)
                else:
                    continue
            item_dict['IP'] = IP_list
            items_list.append(item_dict)
        print(items_list)
    f.close()
    return items_list
    # print(items_list)

# 提取域名以便访问
def getdname(items_list):
    for item in items_list:
        dname_target = item.get('dname')
        print(dname_target)

# 提取IP以便访问
def getIP(items_list):
    for item in items_list:
        IP_list = item.get('IP')
        for IP_target in IP_list:
            print(IP_target)

if __name__ == "__main__":
    items_list = readfile(r"C:\Users\ipc\Desktop\filetest.txt")
    # print(items_list)
    getdname(items_list)
    getIP(items_list)
>>>>>>> 651607dbcebe078af50a71c17ee01854a8c2f56c
