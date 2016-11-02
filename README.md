# aIDS
aIDS is an intrusion detection system

# Introduction
You can use aIDS to detect, log, and alert:
1. Any traffic to or from a blacklisted IP
2. DNS requests for blacklisted domain names
3. Unencrypted web traffic to URLs containing a set of blacklisted strings
4. TCP or UDP payloads containing any of a set of simple signatures 
5. Network port scanning activity

# System Requirements and Dependencies
* aIDS requires Python 2.7
* Please ensure the following Python modules are installed and available:
	* scapy
	* scapy-http
	* netifaces
* aIDS requires the following files to function:
	* `constants.py`
	* a configuration file in JSON format (`config.json` is provided)

# Command Line
The command line arguments for aIDS are as follows:
usage: aIDS.py [-h] [-i INTERFACE | -p PCAP_DUMP] [-c CONFIG] [-l LOG]

optional arguments:
  -h, --help            show this help message and exit

  -i INTERFACE, --interface INTERFACE
                        [DEFAULT] Select a network interface

  -p PCAP_DUMP, --pcap-dump PCAP_DUMP
                        Select a PCAP packet dump file

  -c CONFIG, --config CONFIG
                        Select a custom config file View an example
                        configuration in the README

  -l LOG, --log LOG     Specify a filename for log generation (the default is
                        'log.log')

aIDS will run if no arguments are provided, however, this is unlikely to be helpful. It is highly recommended to provide an active interface as aIDS will use the first interface it can find otherwise. A PCAP file can be provided instead of an interface.

Custom config and log filenames can be provided. A sample configuration can be found in Appendix I. 

# Getting Started
The first and most important part of getting aIDS running is to ensure that your configuration file is complete. The config.json file provided with aIDS has some default values for examples, and those same values are provided in Appendix I. Without a configuration file, aIDS won't know what to look for when it's analyzing packets. 

There are four fields that are required for the configuration file: ip, dns, string, and signature. Even if you aren't going to use one of those fields, it must still be defined in the configuration file. An example of this type of configuration file can be found in Appendix I. 

Running aIDS is a relatively simple task. There's no compiling necessary, so just point your terminal to the directory where aIDS is located and try running
	`python aIDS.py -i en1`
where `en1` is the interface you are wanting to detect intrusions. If you don't know what interface to use, try using the command `ifconfig` to get a list of available interfaces. 

Once aIDS is up and running, it will start scanning packets. If aIDS encounters any packets that contain blacklisted values, an alert will be printed to the console and the packet is logged.

Alerts are suppressed for a certain period of time. aIDS ships with a 5 minute (300 second) suppression, however, this can be customized in the `constants.py` file by updating the SUPRESS_ALERT_TIME_CONSTANT value in seconds. 

Please note than any changes made in `constants.py` or any configuration file used by aIDS must be saved before aIDS is run.

# Understanding the Log Files
When aIDS detects a packet with blacklisted values, the packet is logged and timestamped. A log will include the type of intrusion that was detected:

 * `[BLIP]` : a packet was sent to or from a blacklisted IP
 * `[BDNS]` : a packet contained a DNS request for a blacklisted domain
 * `[BURL]` : a packet contained an HTTP request with blacklisted strings
 * `[PSIG]` : a packet whose payload contained a user-defined signature was found
 * `[PSCN]` : a port scan was detected

# Appendix I

The default config.json file:

{
	"ip" : 
	[
		{ "addr" : "127.0.0.1" },
		{ "addr" : "192.168.0.1" }
	],
	"dns" :
	[
		{ "addr" : "8.8.8.8" },
		{ "addr" : "google.com" }
	],
	"string" :
	[
		{ "str" : "google" },
		{ "str" : "facebook" }
	],
	"signature" :
	[
		{ "string" : "this is a test string" }
	]
}

An example of a configuration file where one or more field is empty (be certain to note that empty brackets are necessary):

{
	"ip" : 
	[
		{ "addr" : "127.0.0.1" },
		{ "addr" : "192.168.0.1" }
	],
	"dns" :
	[ ],
	"string" :
	[
		{ "str" : "google" },
		{ "str" : "facebook" }
	],
	"signature" :
	[ ]
}
