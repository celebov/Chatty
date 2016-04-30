# Client program

from socket import *
import Utils as Util

# Set the socket parameters
host = "localhost"

port = 21567

buf = 1024

addr = (host,port)

# Create socket
UDPSock = socket(AF_INET,SOCK_DGRAM)

def_msg = "===Enter message to send to server===";
print "",def_msg

# Send messages
while (1):

	data = raw_input('>> ')

	if not data:

		break

	else:
		temp = Util.message()
		temp.version = 1
		temp.source = "A1DB1329"
		temp.destination = "A1DB1329"
		temp.type = 4
		temp.flag = 255
		temp.hop_count = 15
		temp.payload = data
		packet = Util.Pack(temp)
		if(UDPSock.sendto(temp,addr)):

			print "Sending message '",data,"'....."

# Close socket
UDPSock.close()