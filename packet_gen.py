import socket 
import random
import time

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) 
string = 'this is a test string' 
ip = raw_input('Dest IP: ') 
num = 0
while True: 
	num = num + 1
	port = random.randint(1024,65535)
	sock.sendto(string,(ip,port))
	time.sleep(0)
	# if num == 50:
	# 	break