# Server program

from socket import *
import Utils as Util


# Set the socket parameters
host = "localhost"
port = 21567
buf = 8192
addr = (host,port)

# Create socket and bind to address
UDPSock = socket(AF_INET,SOCK_DGRAM)


while 1:
	#Send Message
	datatosend = raw_input('>> ')
	if not datatosend:
		break
	else:
		messagetosend = Util.ChunkMessages(datatosend)
		for message in messagetosend:
			if (UDPSock.sendto(message, addr)):
				print "Sending message '", message, "'....."
	#End Send Message



# Close socket
UDPSock.close()