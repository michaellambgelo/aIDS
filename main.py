import sys
import argparse
import json
from pprint import pprint
from constants import *
from scapy.all import *
from netifaces import *

import netifaces as ni

'''
configureArgs() sets up all command line arguments.
-i and -p are mutually exclusive: a user either scans a network
interface in promiscuous mode or provides a PCAP dump file for
scanning

-d specifies a DNS blacklist
-a specifies an IP/domain blacklist
-s specifies a detection signature file for TCP/UDP payloads
'''
def configureArgs():
	parser = argparse.ArgumentParser()
	group_iface_or_PCAP = parser.add_mutually_exclusive_group()
	group_iface_or_PCAP.add_argument("-i","--interface",
		help = "[DEFAULT] Select a network interface")
	group_iface_or_PCAP.add_argument("-p","--pcap-dump",
		help = "Select a PCAP packet dump file")
	parser.add_argument("-c","--config",
		help = "[REQUIRED] You must provide a config file\n" + ERROR_CONFIG_EXAMPLES,
		required = False)
	parser.add_argument("-d","--dns-blacklist",
		help = "[REQUIRED] You must provide a DNS blacklist configuration file\n" + ERROR_CONFIG_EXAMPLES,
		required = False)
	parser.add_argument("-a","--ip-blacklist",
		help = "[REQUIRED] You must provide an IP address blacklist\n" + ERROR_CONFIG_EXAMPLES,
		required = False)
	parser.add_argument("-s","--signature",
		help = "[REQUIRED] You must provide a detection signature file\n" + ERROR_CONFIG_EXAMPLES,
		required = False)
	return parser.parse_args()

'''
defineInterface()
'''
def defineInterface(iface_arg):
	if iface_arg and ni.ifaddresses(iface_arg):
		iface = iface_arg
		print "Monitoring selected interface: " + iface + "\n"
	else:
		iface = ni.interfaces()
		iface = iface[0]
		print "Monitoring default interface: " + iface + "\n"

	return iface

'''
main

Everything happens here
'''
if __name__ == "__main__":
	# get all our arguments
	args = configureArgs()

	# get our interface
	iface = defineInterface(args.interface)

	# get our pcap packet dump
	if args.pcap_dump is not None:
		pcap = rdpcap(args.pcap_dump)

	# get our files
	if args.dns_blacklist is not None:
		dns_blacklist = json.load(open(args.dns_blacklist))
	if args.ip_blacklist is not None:
		#file = open(args.ip_blacklist)
		with open(args.ip_blacklist) as ip_blacklist:
			ip_blacklist = json.load(ip_blacklist)
		# how many IPs are blacklisted?
		numOfblacklistedIP = len(ip_blacklist['ip'])
		# how to access the elements
		# ip_blacklist['ip'][0]['addr']
	if args.signature is not None:
		payloads_signature = json.load(open(args.signature))

	# how to print my IP address
	# addr = ni.ifaddresses(iface)[AF_INET][0]['addr']
	# print addr

	pkt = sniff(iface = iface, count = 0, filter = "ip")

	while True:
		# print type(pkt[0][IP].src)   #type str
		# print type(ip_blacklist['ip'][0]['addr'])    #type unicode
		for i in range(len(ip_blacklist['ip'])):
		 	if pkt[0][IP].src == str(ip_blacklist['ip'][i]['addr']):
		 		print "Blacklisted IP detected"
