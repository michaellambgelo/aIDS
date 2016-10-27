import sys
import argparse
import json
import time
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
		help = "Select a custom config file\n" + ERROR_CONFIG_EXAMPLES)
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
logPacketWithTimestamp()
'''
def logPacketWithTimestamp(pkt, alertType):
	out_file = open("log.log","a")
	out_file.write(time.strftime('%a %H:%M:%S') + " " 
		+ alertType + " : "
		+ str(pkt[0].summary()) + "\n")

'''
ip_alert()
'''
def ip_alert(pkt):
	print ALERT_MATCHED_BLACKLISTED_IP
	print str(pkt[0].summary()) + "\n"
	logPacketWithTimestamp(pkt,ALERT_IP_LOG_MESSAGE)

'''
main
'''
if __name__ == "__main__":
	# get all our arguments
	args = configureArgs()

	# get our interface
	iface = defineInterface(args.interface)

	# get our pcap packet dump
	if args.pcap_dump is not None:
		pcap = rdpcap(args.pcap_dump)

	# get our config file
	config_file = args.config if args.config is not None else "config.json"
	with open(config_file) as config:
		try:
			config = json.load(config)
		except:
			print ERROR_INVALID_JSON
			sys.exit()
		ip_blacklist = config['ip']
		dns_blacklist = config['dns']
		string_blacklist = config['string']
		signature_blacklist = config['signature']


	# how to print my IP address
	# addr = ni.ifaddresses(iface)[AF_INET][0]['addr']
	# print addr


	while True:
		pkt = sniff(iface = iface, count = 1, filter = "ip")
		# print type(pkt[0][IP].src)   #type str
		# print type(ip_blacklist['ip'][0]['addr'])    #type unicode
		for i in range(len(ip_blacklist)):
		 	if pkt[0][IP].src == str(ip_blacklist[i]['addr']):
		 		ip_alert(pkt)







