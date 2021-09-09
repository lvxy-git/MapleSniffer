from scapy.all import wrpcap, sniff, Raw, hexdump
from scapy.layers.inet import IP, UDP, TCP, Ether,raw
from scapy.packet import Raw

import threading
import time


def packet_callback(packet):
    # if packet[IP]:
    #     print("%s -> %s" % (packet[IP].src, packet[IP].dst))
    #hexdump(packet)
    if packet[IP].len > 40:
        print(bytes(packet.payload.payload.payload).hex())
        hexdump(packet)
        #print(len(bytes(packet.payload.payload.payload)))
    #wrpcap("test.pcap", packet)

def main():
    a = sniff(filter='dst net 47.96.82.201', prn=packet_callback, count=100)
    print(a)

def get_packet_length(packet_header):
    packet_length = (packet_header >> 16) ^ (packet_header & 0xFFFF)
    packet_length = ((packet_length << 8) & 0xFF00) | ((packet_length >> 8) & 0xFF)
    return packet_length

def roll_left(data, count):
    tmp = data & 0xFF
    tmp = tmp << (count % 8)

    return (tmp & 0xFF) | (tmp >> 8)

def roll_right(data, count):
    tmp = data & 0xFF
    tmp = (tmp<<8) >> (count % 8)

    return (tmp & 0xFF) | (tmp >> 8)

def decrypt_data(data):
    for i in range(1,7):
        remember = 0x00
        length = len(data)
        data_length = length & 0xFF
        next_remember = 0x00
        if i % 2 == 0:
            for j in range(length):
                cur = data[j]
                cur -= 0x48
                cur = (~cur) & 0xFF
                cur = roll_left(cur, data_length & 0xFF)
                next_remember = cur
                cur ^= remember
                remember = next_remember
                cur -= data_length
                cur = roll_right(cur, 3)
                data[j] = cur
                data_length -= 1
        else:
            for j in range(length-1, -1, -1):
                cur = data[j]
                cur = roll_left(cur, 3)
                cur ^= 0x13
                next_remember = cur
                cur ^= remember
                remember = next_remember;
                cur -= data_length;
                cur = roll_right(cur, 4);
                data[j] = cur;
                data_length -= 1;
    return data
            

if __name__ == '__main__':
    data = '34254425f47eca3fedfe71dda2febe200fa89ab45063af0a98320bde5b0cdfd00631235bdaf4e621647b225d0b3f0b920446543960d47be9121e88238f2120b7fe4ed4329975670297491c34e906453b2d122fc173b622fa7637bdd76ecac669b3d528e111a22c4c54a1b8cbd9c750f4e6c5aef9'
    data = data[8:]
    datas = []
    for i in range(len(data)//2):
        datas.append(int(data[2*i:2*i+2],16))
    print(datas)
    res = decrypt_data(datas)
    a = ''.join([hex(i) for i in res])
    #a = bytes.fromhex(a)
    print(a)
    print(res[1]<<8 + res[0])
    #t = threading.Thread(target=main)
    #t.start()
    #t.join()

