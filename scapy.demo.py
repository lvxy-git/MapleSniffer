from scapy.all import wrpcap, sniff, Raw, hexdump
from scapy.layers.inet import IP, UDP, TCP

import threading
import time


def packet_callback(packet):
    print("%s -> %s" % (packet[IP].src, packet[IP].dst))
    hexdump(packet)
    #print(packet[Raw])
    # wrpcap("test.pcap", packet)
    print("--------------------------")

def main():
    a = sniff(filter='udp', prn=packet_callback, count=10)
    print(a)

if __name__ == '__main__':
    t = threading.Thread(target=main)
    t.start()
    t.join()

