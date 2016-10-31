import socket 
import random
import time

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # Creates a socket
string = 'this is a test string' #Creates packet
# hex_string = string.join("{:02x}".format(ord(c)) for c in string)
ip = raw_input('Target IP: ') # send IP
#port = input('Port: ') # send port
num = 0
while True: 
	num = num + 1
	port = random.randint(1024,65535)
	sock.sendto(string,(ip,port))
	time.sleep(0)
	if num == 50:
		break