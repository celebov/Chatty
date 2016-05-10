# Main program

from socket import *
import Utils as Util
import time

# Set the socket parameters Manually
# host = "localhost"
# port = 21567
# buf = 1024
# addr = (host, port)
# End Setting Socket parameters manually

# Set Socket Parameters Dynamically
# host = Util.Validate_IPV4(raw_input('>>HostName: '))
# port = Util.Port_Input_Validator()
# buf = 1024
# addr = (host, port)

host = "127.0.0.1"
port = 9999
buf = 1024
addr = (host, port)
# End Socket Parameters Dynamically
# Create socket and bind to address
UDPSock = socket(AF_INET, SOCK_DGRAM)
UDPSock.bind(addr)

while 1:
    # Receive Message
    received_data = Util.recv_flag(UDPSock, buf)
    if not received_data:
        print "Client has exited!"
        break
    else:
        received_messages = Util.UnpackArray(received_data)

        if received_messages[0].type == 16:
            Util.WritePacketsToFile(received_messages)
        elif received_messages[0].type == 64:
            Util.Get_RoutingTable(Util.ConcatMessages(received_messages), received_messages[0].source)
            print "Received message '", Util.ConcatMessages(received_messages), "'"
            # End Receiving Message
# Close socket

UDPSock.close()
