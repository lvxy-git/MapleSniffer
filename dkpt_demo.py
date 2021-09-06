import sys
import os
import dpkt


def checkIfHTTPRes(data):  # 检查是否为HTTP协议

    if len(data) < 4:
        return False

    if data[:4] == str.encode('HTTP'):
        return True

    return False


def httpPacketParser(http):  # 分析流

    if checkIfHTTPRes(http):  # 检查是否为HTTP协议
        try:
            response = dpkt.http.Response(http)  # 尝试以HTTP读取响应
            print(response.status)

        except Exception as e:
            # print(e)
            pass
    # else:
    #     print("Not HTTP")


def tcpPacketParser(tcp):  # 获取流

    stream = tcp.data
    if len(stream):
        httpPacketParser(stream)  # 尝试以HTTP分析流


def ipPacketParser(ip):  # 获取TCP包
    if isinstance(ip.data, dpkt.tcp.TCP):
        """这里也许可以考虑一下加一条来读UDP包？"""
        tcpPacketParser(ip.data)  # 分析tcp包


def decodePacket(packet):  # 解码获取以太网包
    eth = dpkt.ethernet.Ethernet(packet)
    if isinstance(eth.data, dpkt.ip.IP):
        ipPacketParser(eth.data)  # 分析ip包


def pcapReader(filename):  # 打开.pcap文件
    try:
        with open(filename, 'rb') as f:
            capture = dpkt.pcap.Reader(f)
            i = 1
            for timestamp, packet in capture:  # 键值对，提取packet进行解码
                decodePacket(packet)
                i += 1

    except Exception as e:
        print('parse {}, error:{}'.format(filename, e))


if __name__ == "__main__":
    # if len(sys.argv) < 2:
    #     print('HELP: python {} <PCAP_PATH>'.format(sys.argv[0]))
    #     sys.exit(0)
    #     # _EXIT_
    # filename = sys.argv[1]
    #
    # if filename:
    #     pcapReader(filename)
    print(str.encode('HTTP'))
