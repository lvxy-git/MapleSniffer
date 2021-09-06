import socket
import threading
import time
import ip_parser

activeDegree = dict()
flag = 1


def printPacket(package, showPort=True, showRawData=True):
    dataIndex = 0

    headerIndex = 1

    ipAddressIndex = 0

    portIndex = 1

    print('IP:', package[headerIndex][ipAddressIndex], end=' ')

    if (showPort):
        print('Port:', package[headerIndex][portIndex], end=' ')

    print('')  # newline

    if (showRawData):
        print('Data:', package[dataIndex])

def main():
    global activeDegree
    global glag
    # 获取本机IP地址
    HOST = socket.gethostbyname(socket.gethostname())
    print('本机的IP为：%s' % HOST)
    # 创建原始套接字，适用于Windows平台
    # 对于其他系统，要把socket.IPPROTO_IP替换为socket.IPPROTO_ICMP
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((HOST, 0))
    # 设置在捕获数据包中含有IP包头
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # 启用混杂模式，捕获所有数据包
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    # 开始捕获数据包
    while flag:
        c = s.recvfrom(65535)
        host = c[1][0]
        activeDegree[host] = activeDegree.get(host, 0) + 1
        # 假设本机ip地址为10.2.1.8
        if c[1][0] != HOST:
            print(c[0])
            #print(ip_parser.IPParser.parse(c[0]))
    # 关闭混杂模式
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    s.close()


t = threading.Thread(target=main)
t.start()
time.sleep(60)
flag = 0
t.join()
for item in activeDegree.items():
    print(item)
