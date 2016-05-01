# Server program

from socket import *
import Utils as Util
import gnupg
from pprint import pprint

# Set the socket parameters
host = "localhost"
port = 21567
buf = 8192
addr = (host,port)
challenge = 'elma'

# Create socket and bind to address
UDPSock = socket(AF_INET,SOCK_DGRAM)

rec_id = raw_input('Type recipients public key id >> ')
myKeyid = raw_input('Type your private key id >> ')
myPP = raw_input('Type your passphrase to sign >> ')


aut_msg_tosend = Util.ChunkMessages(Util.sendEncMsg(challenge,rec_id,myKeyid,myPP))
for aut_msg in aut_msg_tosend:
    if (UDPSock.sendto(aut_msg, addr)):
        print "Sending enc message '", aut_msg, "'....."


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