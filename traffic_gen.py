import sys

from scapy.all import *

if __name__ == "__main__":
	sr(IP(dst="192.168.1.*")/ICMP())