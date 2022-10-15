#! /usr/bin/python

from scapy.all import *

src_port = RandShort()
dst_ip = "172.16.111.136"
dst_port = 80

ret = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags=0x2),timeout=10)
if ret is None:
    print("Filtered")
elif ret.haslayer(TCP):
    if ret[1].flags == 0x12:
        print("Open")
    elif ret[1].flags == 0x14:
        print("Closed")