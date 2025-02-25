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
t = { 
	ALERT_IP_LOG_MESSAGE : None, 
	ALERT_DNS_LOG_MESSAGE : None,
	ALERT_STRING_LOG_MESSAGE : None,
	ALERT_SIGNATURE_LOG_MESSAGE : None,
	ALERT_PORT_SCAN_LOG_MESSAGE : None }

'''
configureArgs() 
sets up all command line arguments.
-i and -p are mutually exclusive: a user either scans a network
interface in promiscuous mode or provides a PCAP dump file for
scanning
'''
def configureArgs():
	parser = argparse.ArgumentParser()
	group_iface_or_PCAP = parser.add_mutually_exclusive_group()
	group_iface_or_PCAP.add_argument('-i','--interface',
		help = '[DEFAULT] Select a network interface')
	group_iface_or_PCAP.add_argument('-p','--pcap-dump',
		help = 'Select a PCAP packet dump file')
	parser.add_argument('-c','--config',
		help = 'Select a custom config file.\n ' + ERROR_CONFIG_EXAMPLES)
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
		t[logType] = Timer(SUPPRESS_ALERT_TIME_CONSTANT, suppress_alert, [logType])
		t[logType].start()

	logPacketWithTimestamp(pkt,logType)
'''
cancelTimers()
'''
def cancelTimers():
	global t
	if t[ALERT_IP_LOG_MESSAGE] is not None:
		t[ALERT_IP_LOG_MESSAGE].cancel()
	if t[ALERT_STRING_LOG_MESSAGE] is not None:
		t[ALERT_STRING_LOG_MESSAGE].cancel()
	if t[ALERT_DNS_LOG_MESSAGE] is not None:
		t[ALERT_DNS_LOG_MESSAGE].cancel()
	if t[ALERT_SIGNATURE_LOG_MESSAGE] is not None:
		t[ALERT_SIGNATURE_LOG_MESSAGE].cancel()
	if t[ALERT_PORT_SCAN_LOG_MESSAGE] is not None:
		t[ALERT_PORT_SCAN_LOG_MESSAGE].cancel()

'''
handler()
if there's a timer active, kill it. 
'''
def handler(signal,frame):
	cancelTimers()
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
			if str(string_signature_blacklist[i]['string']) in repr(str(pkt[0][Raw].load)):
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
	if pkt[0].haslayer(IP): # every packet that has an IP layer
		if pkt[0][IP].dst == ni.ifaddresses(iface)[AF_INET][0]['addr']: # every packet whose destination is this machine
			if pkt[0].haslayer(TCP) or pkt[0].haslayer(UDP): # every packet with either a TCP or UDP layer
				dport = pkt[0][TCP].dport if pkt[0].haslayer(TCP) else pkt[0][UDP].dport # get the destination port
				src = pkt[0][IP].src # get the source IP
				sourcePorts = [] # make an empty list
				if portScanningLog.has_key(src): # if we've seen this IP before
					sourcePorts = portScanningLog[src] # get all the ports it's accessed
					if dport not in sourcePorts: # if the port it's accessing now is new
						sourcePorts.append(dport) # add it to the existing list
						portScanningLog[src] = sourcePorts # and send it back to the dictionary
					if len(sourcePorts) >= PORT_SCAN_UNIQUE_PORTS_CONSANT: # if there are more ports accessed than defined by the constant
						if time.time() - portScanningTimestamp[src] <= PORT_SCAN_TIME_CONSTRAINT_CONSTANT: # and if these ports have been accessed quickly enough
							alert(pkt, ALERT_PORT_SCANNING_MESSAGE + str(src), ALERT_PORT_SCAN_LOG_MESSAGE) # print the alert
						del sourcePorts[:] # no matter what, remove all the ports we've recorded
						portScanningLog[src] = sourcePorts # and add the empty list back
						portScanningTimestamp[src] = time.time() # update the time to now
				else: # we haven't seen this IP before
					sourcePorts.append(dport) # add the port to the list
					portScanningLog[src] = sourcePorts # put the list in the dictionary
					portScanningTimestamp[src] = time.time() # log the time we've first seen this guy

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
	if args.pcap_dump is None:
		iface = defineInterface(args.interface)

	# get our pcap packet dump
	if args.pcap_dump is not None:
		try:
			pcap = rdpcap(args.pcap_dump)
		except:
			print "An error occurred when reading the PCAP file provided"
			sys.exit()

	# check the constants configurations
	if type(SUPPRESS_ALERT_TIME_CONSTANT) != type(0) or type(PORT_SCAN_UNIQUE_PORTS_CONSANT) != type(0) or type(PORT_SCAN_TIME_CONSTRAINT_CONSTANT) != type(0.0):
		print "One or more of the parameters in \"constants.py\" is invalid."
		sys.exit()

	# get our log file
	logFile = args.log if args.log is not None else DEFAULT_LOG_FILE_NAME
	
	# dictionaries used in port scanning
	portScanningLog = {}
	portScanningTimestamp = {}

	# get our config file
	config_file = args.config if args.config is not None else DEFAULT_CONFIG_FILE_NAME
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