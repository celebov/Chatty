# Server program

from socket import *
import Utils as Util

# Set the socket parameters
host = "localhost"

port = 21567

buf = 1024

addr = (host,port)

# Create socket and bind to address
UDPSock = socket(AF_INET,SOCK_DGRAM)

UDPSock.bind(addr)

# Receive messages
while 1:

	data,addr = UDPSock.recvfrom(buf)

	if not data:

		print "Client has exited!"

		break

	else:
		Packet = Util.Unpack(Util.message, data)
		print "Received message '", Packet.payload,"'"

# Close socket
UDPSock.close()