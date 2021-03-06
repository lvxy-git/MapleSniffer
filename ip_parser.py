import socket
import struct

class IPParser:

    IP_HEADER_LENGTH = 20  # 报文前二十字节为ip头部

    @classmethod
    def parse_ip_header(cls, ip_header):
        """
        IP报文格式
        1. 4位IP-version 4位IP头长度 8位服务类型 16位报文总长度
        2. 16位标识符 3位标记位 13位片偏移 暂时不关注此行
        3. 8位TTL 8位协议 16位头部校验和
        4. 32位源IP地址
        5. 32位目的IP地址
        :param ip_header:
        :return:
        """
        line1 = struct.unpack('>BBH', ip_header[:4])  # 先按照8位、8位、16位解析
        ip_version = line1[0] >> 4  # 通过右移4位获取高四位
        # 报文头部长度的单位是32位 即四个字节
        iph_length = (line1[0] & 15) * 4  # 与1111与运算获取低四位
        packet_length = line1[2]
        line3 = struct.unpack('>BBH', ip_header[8: 12])
        TTL = line3[0]
        protocol = line3[1]
        iph_checksum = line3[2]
        line4 = struct.unpack('>4s', ip_header[12: 16])
        src_ip = socket.inet_ntoa(line4[0])
        line5 = struct.unpack('>4s', ip_header[16: 20])
        dst_ip = socket.inet_ntoa(line5[0])

        # 返回结果
        # ip_version ip版本
        # iph_length ip头部长度
        # packet_length 报文长度
        # TTL 报文寿命
        # protocol 协议号 1 ICMP协议 6 TCP协议 17 UDP协议
        # iph_checksum ip头部的校验和
        # src_ip 源ip
        # dst_ip 目的ip
        return {
            'ip_version': ip_version,
            'iph_length': iph_length,
            'packet_length': packet_length,
            'TTL': TTL,
            'protocol': protocol,
            'iph_checksum': iph_checksum,
            'src_ip': src_ip,
            'dst_ip': dst_ip
        }

    @classmethod
    def parse(cls, packet):
        ip_header = packet[:cls.IP_HEADER_LENGTH]

        return cls.parse_ip_header(ip_header)

if __name__ == '__main__':
    print(IPParser.parse(b'E\x00\x00\x92ST\x00\x00@\x11\x10\\\nG\x0ce\xff\xff\xff\xff\x04\x00\x13\x89\x00~\xd0\xbd\x01\x01\x0e\x00\xe1+\x83\xc7\x8f\xde\x00h\x00\x00\x00\x06\x00\nTL-WDR5670\x00\x0b\x00\x031.0\x00\x07\x00\x01\x01\x00\x05\x00\x11D0-76-E7-00-5A-C9\x00\x08\x00\x0c10.71.12.101\x00\t\x00\ntplogin.cn\x00\n\x00\x0eTL-WDR5670 1.0\x00\x0c\x00\x051.7.4'))