import sys
import netifaces
import argparse
from constants import *
from scapy.all import *


def configureArgs():
	parser = argparse.ArgumentParser()
	group_iface_or_PCAP = parser.add_mutually_exclusive_group()
	group_iface_or_PCAP.add_argument("-i","--interface",
		help = "[DEFAULT] Select a network interface")
	group_iface_or_PCAP.add_argument("-p","--pcap-dump",
		help = "Select a PCAP packet dump file")
	# parser.add_argument("-d","--dns-blacklist",
	# 	help = "[REQUIRED] You must provide a DNS blacklist configuration file\n" + ERROR_CONFIG_EXAMPLES,
	# 	required = True)
	# parser.add_argument("-a","--ip-blacklist",
	# 	help = "[REQUIRED] You must provide an IP address blacklist\n" + ERROR_CONFIG_EXAMPLES,
	# 	required = True)
	return parser

if __name__ == "__main__":
	parser = configureArgs()
	args = parser.parse_args()

	iface = None
	if args.interface and netifaces.ifaddresses(args.interface):
		iface = args.interface
		print "Monitoring selected interface: " + iface
	else:
		iface = netifaces.interfaces()
		iface = iface[0]
		print "Monitoring default interface: " + iface
