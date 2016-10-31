import sys
import time 	# for getting the current time
import argparse # for command line options
import json 	# for config files
import signal 	# for handling ctrl + c gracefully
from constants import * 		# let there be strings
from scapy.all import * 		# main scapy library
from netifaces import * 		# not really useful for more than getting my IP
from scapy.layers import http 	# used for processing HTTP requests
from threading import Timer 	# for suppressing alerts
import netifaces as ni 			# create an alias for netifaces

'''
global variables suck, but they work
'''
# alert suppression variables
suppressFlag = { 
	ALERT_IP_LOG_MESSAGE : False, 
	ALERT_DNS_LOG_MESSAGE : False,
	ALERT_STRING_LOG_MESSAGE : False,
	ALERT_SIGNATURE_LOG_MESSAGE : False,
	ALERT_PORT_SCAN_LOG_MESSAGE : False }
t = None

'''
configureArgs() 
sets up all command line arguments.
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
	parser.add_argument('-l','--log',
		help = 'Specify a filename for log generation (the default is \'log.log\')')
	return parser.parse_args()

'''
defineInterface()
get an interface. if the user specified an interface, make sure it's
real. otherwise, just get the first interface we can find.
'''
def defineInterface(iface_arg):
	try:
		if iface_arg and ni.ifaddresses(iface_arg):
			iface = iface_arg
			print 'Monitoring selected interface: ' + iface + '\n'
		elif iface_arg is not None:
			print 'The specified interface does not exist.\n'
			sys.exit()
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
open a log file and append the formatted string of the packet provided
'''
def logPacketWithTimestamp(pkt, alertType):
	out_file = open(logFile,'a')
	out_file.write(time.strftime('%a %H:%M:%S') + ' ' 
		+ alertType + ' : '
		+ pkt[0].sprintf("{IP:%IP.src% -> %IP.dst%\n}")
		+ pkt[0].sprintf("{IP:len: %IP.len% id: %IP.id% ttl: %IP.ttl% chksum: %IP.chksum%\n}")
		+ "Raw: " + pkt[0].sprintf("{Raw:%Raw.load%\n}") + '\n')

'''
alert()
check to see if an alert can be displayed. if it can, start a timer
to suppress the alert. always pass the packet to be logged.
'''
def alert(pkt,alert,logType):
	global suppressFlag
	if suppressFlag[logType] == False:
		print alert
		print str(pkt[0].summary()) + '\n'
		suppressFlag[logType] = True
		global t
		t = Timer(SUPPRESS_ALERT_TIME_CONSTANT, suppress_alert, [logType])
		t.start()

	logPacketWithTimestamp(pkt,logType)

'''
handler()
if there's a timer active, kill it. 
'''
def handler(signal,frame):
	global t
	if t is not None:
		t.cancel()
	print 'Quitting...\n'
	sys.exit(0)

'''
suppress_alert()
reset the given key's value to false
'''
def suppress_alert(alertType):
	global suppressFlag
	suppressFlag[alertType] = False

'''
scanForBlacklistedStringInURL()
parse an HTTP request for strings given in the config file
'''
def scanForBlacklistedStringInURL(pkt):
	# detecting blacklisted strings in URL
	if pkt[0].haslayer(http.HTTPRequest):
		http_layer = pkt[0].getlayer(http.HTTPRequest)
		for i in range(len(string_blacklist)):
			if str(string_blacklist[i]['str']) in http_layer.fields['Host'] or str(string_blacklist[i]['str']) in http_layer.fields['Path']:
				alert(pkt, ALERT_MATCHED_BLACKLISTED_STRING_IN_URL, ALERT_STRING_LOG_MESSAGE)

'''
scanForBlacklistedIP()
parse a packet for source or destination IP addresses given in the config file
'''
def scanForBlacklistedIP(pkt):
	# detecting blacklisted IP addresses
	if pkt[0].haslayer(IP):
		for i in range(len(ip_blacklist)):
		 	if pkt[0][IP].src == str(ip_blacklist[i]['addr']) or pkt[0][IP].dst == str(ip_blacklist[i]['addr']):
		 		alert(pkt, ALERT_MATCHED_BLACKLISTED_IP, ALERT_IP_LOG_MESSAGE)

'''
scanForBlacklistedDNSQuery()
parse a DNS request for a DNS address given in the config file
'''
def scanForBlacklistedDNSQuery(pkt):
	# detecting blacklisted DNS servers
	if pkt[0].haslayer(DNSQR):
		dns_query = pkt[0][DNSQR].qname
		for i in range(len(dns_blacklist)):
			if str(dns_blacklist[i]['addr']) in dns_query:
				alert(pkt, ALERT_MATCHED_BLACKLISTED_DNS, ALERT_DNS_LOG_MESSAGE)

'''
scanForPayloadSignature()
parse a packet's payload for signatures given in the config file
'''
def scanForPayloadSignature(pkt):
	# detecting payload signatures
	if pkt[0].haslayer(Raw):
		for i in range(len(string_signature_blacklist)):
			if str(string_signature_blacklist[i]['string']) in repr(str(pkt[0]).encode('hex')):
				alert(pkt, ALERT_MATCHED_PAYLOAD_SIGNATURE, ALERT_SIGNATURE_LOG_MESSAGE)

'''
detectPortScanning()
to detect a port scan, check if a packet is destined for this machine.
keep a dictionary where the source IP address is the key and the ports it has
accessed are stored in a list as its matched value. if the source IP connects
to a certain number of ports (defined in the constants file) then it triggers
an alert. those ports are removed from the key-value pair. 

a user can define a port scan by setting the number of packets in a certain 
amount of time. these variables can be set in the constants file.
'''
def detectPortScanning(pkt):
	if pkt[0].haslayer(IP):
		if pkt[0][IP].dst == ni.ifaddresses(iface)[AF_INET][0]['addr']:
			if pkt[0].haslayer(TCP) or pkt[0].haslayer(UDP):
				dport = pkt[0][TCP].dport if pkt[0].haslayer(TCP) else pkt[0][UDP].dport
				src = pkt[0][IP].src
				sourcePorts = []
				if portScanningLog.has_key(src):
					sourcePorts = portScanningLog[src]
					if dport not in sourcePorts:
						sourcePorts.append(dport)
						portScanningLog[src] = sourcePorts
					if len(sourcePorts) >= PORT_SCAN_UNIQUE_PORTS_CONSANT:
						if time.time() - portScanningTimestamp[src] >= PORT_SCAN_TIME_CONSTRAINT_CONSTANT:
							alert(pkt, ALERT_PORT_SCANNING_MESSAGE + str(src), ALERT_PORT_SCAN_LOG_MESSAGE)
						del sourcePorts[:]
						portScanningLog[src] = sourcePorts
				else:
					sourcePorts.append(dport)
					portScanningLog[src] = sourcePorts
					portScanningTimestamp[src] = time.time()

'''
processPacket()
send a packet to all of our good friends at home
'''
def processPacket(pkt):
	scanForBlacklistedIP(pkt)
	scanForBlacklistedStringInURL(pkt)
	scanForBlacklistedDNSQuery(pkt)
	scanForPayloadSignature(pkt)
	detectPortScanning(pkt)

'''
main
set up from command line arugments, then we sniff
'''
if __name__ == '__main__':
	# handle SIGINT
	signal.signal(signal.SIGINT,handler)

	# get all our arguments
	args = configureArgs()

	# get our interface
	if args.interface is not None:
		iface = defineInterface(args.interface)

	# get our pcap packet dump
	if args.pcap_dump is not None:
		pcap = rdpcap(args.pcap_dump)

	# get our log file
	logFile = args.log if args.log is not None else 'log.log'
	
	# dictionaries used in port scanning
	portScanningLog = {}
	portScanningTimestamp = {}

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
		string_signature_blacklist = config['signature']
	
	while True:
		if args.pcap_dump is not None:
			pkt = sniff(offline = args.pcap_dump, prn = processPacket)
		else:
			pkt = sniff(iface = iface, count = 0, prn = processPacket)