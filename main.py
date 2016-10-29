import sys
import argparse
import json
import time
import signal
from pprint import pprint
from constants import *
from scapy.all import *
from netifaces import *
from scapy.layers import http
from threading import Timer
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
	group_iface_or_PCAP.add_argument('-i','--interface',
		help = '[DEFAULT] Select a network interface')
	group_iface_or_PCAP.add_argument('-p','--pcap-dump',
		help = 'Select a PCAP packet dump file')
	parser.add_argument('-c','--config',
		help = 'Select a custom config file\n' + ERROR_CONFIG_EXAMPLES)
	return parser.parse_args()

'''
defineInterface()
'''
def defineInterface(iface_arg):
	try:
		if iface_arg and ni.ifaddresses(iface_arg):
			iface = iface_arg
			print 'Monitoring selected interface: ' + iface + '\n'
		else:
			iface = ni.interfaces()
			iface = iface[0]
			print 'Monitoring default interface: ' + iface + '\n'
	except:
		print "There was an error getting an interface."
		sys.exit()

	return iface

'''
logPacketWithTimestamp()
'''
def logPacketWithTimestamp(pkt, alertType):
	out_file = open('log.log','a')
	out_file.write(time.strftime('%a %H:%M:%S') + ' ' 
		+ alertType + ' : '
		+ pkt[0].sprintf("{IP:%IP.src% -> %IP.dst%\n}")
		+ pkt[0].sprintf("{IP:len: %IP.len% id: %IP.id% ttl: %IP.ttl% chksum: %IP.chksum%\n}")
		+ "Raw: " + pkt[0].sprintf("{Raw:%Raw.load%\n}") + '\n')

'''
ip_alert()
'''
def ip_alert(pkt):
	print ALERT_MATCHED_BLACKLISTED_IP
	print str(pkt[0].summary()) + '\n'
	logPacketWithTimestamp(pkt,ALERT_IP_LOG_MESSAGE)

'''
dns_alert(pkt)
'''
def dns_alert(pkt):
	print ALERT_MATCHED_BLACKLISTED_DNS
	print str(pkt[0].summary()) + '\n'
	logPacketWithTimestamp(pkt,ALERT_DNS_LOG_MESSAGE)

'''
string_alert(pkt)
'''
def string_alert(pkt):
	print ALERT_MATCHED_BLACKLISTED_STRING_IN_URL
	print str(pkt[0].summary()) + '\n'
	logPacketWithTimestamp(pkt,ALERT_STRING_LOG_MESSAGE)

'''
signature_alert(pkt)
'''
def signature_alert(pkt):
	print ALERT_MATCHED_PAYLOAD_SIGNATURE
	print str(pkt[0].summary()) + '\n'
	logPacketWithTimestamp(pkt,ALERT_SIGNATURE_LOG_MESSAGE)

'''
handler()
'''
def handler(signal,frame):
	print 'Quitting...\n'
	sys.exit(0)

'''
suppress_alert()
'''
def suppress_alert():
	None
'''
main
'''
if __name__ == '__main__':
	# handle SIGINT
	# signal.signal(signal.SIGINT,handler)

	# get all our arguments
	args = configureArgs()

	# get our interface
	iface = defineInterface(args.interface)

	# get our pcap packet dump
	if args.pcap_dump is not None:
		pcap = rdpcap(args.pcap_dump)

	# get our config file
	config_file = args.config if args.config is not None else 'config.json'
	with open(config_file) as config:
		try:
			config = json.load(config)
		except:
			print ERROR_INVALID_JSON
			sys.exit()
		ip_blacklist = config['ip']
		dns_blacklist = config['dns']
		string_blacklist = config['string']
		hex_signature_blacklist = config['signature_hex']
		string_signature_blacklist = config['signature_string']


	# how to print my IP address
	# addr = ni.ifaddresses(iface)[AF_INET][0]['addr']
	# print addr

	#print signature_blacklist[0]['string']
	
	while True:
		pkt = sniff(iface = iface, count = 1)#, filter = 'ip')
		wrpcap("dump.pcap",pkt)
		# print type(pkt[0][IP].src)   #type str
		# print type(ip_blacklist['ip'][0]['addr'])    #type unicode

		# detecting blacklisted strings in URL
		if pkt[0].haslayer(http.HTTPRequest):
			http_layer = pkt[0].getlayer(http.HTTPRequest)
			for i in range(len(string_blacklist)):
				if str(string_blacklist[i]['str']) in http_layer.fields['Host'] or str(string_blacklist[i]['str']) in http_layer.fields['Path']:
					None # string_alert(pkt)

		# detecting blacklisted IP addresses
		if pkt[0].haslayer(IP):
			for i in range(len(ip_blacklist)):
			 	if pkt[0][IP].src == str(ip_blacklist[i]['addr']):
			 		None # ip_alert(pkt)

		# detecting blacklisted DNS servers
		if pkt[0].haslayer(DNSQR):
			dns_query = pkt[0][DNSQR].qname
			for i in range(len(dns_blacklist)):
				if str(dns_blacklist[i]['addr']) in dns_query:
					None # dns_alert(pkt)

		# detecting payload signatures

		for i in range(len(hex_signature_blacklist)):
			if str(hex_signature_blacklist[i]['hex']) in str(pkt[0]).encode("hex"):
				None #signature_alert(pkt)
		for i in range(len(string_signature_blacklist)):
			if bytes(string_signature_blacklist[i]['string']) in str(pkt[0]).encode("hex"):
				signature_alert(pkt)






