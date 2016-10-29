import socket 
import random
import time

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # Creates a socket
string = "this is a test string"
# hex_string = string.join("{:02x}".format(ord(c)) for c in string)
ip = raw_input('Target IP: ') # send IP
#port = input('Port: ') # send port

while True: 
	port = random.randint(1025,65535)
	sock.sendto(string,(ip,port))
	print "Sent %s to %s at port %s." % (string,ip,port)
	time.sleep(5)