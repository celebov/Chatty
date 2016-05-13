# Main program

from socket import *
import Utils as Util
import gnupg
import time


host = "192.168.0.18"
port = 6666
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
        print("Client has exited!")
        break
    else:
        received_messages = Util.UnpackArray(received_data)
        if received_messages[0].type == 1 and received_messages[0].flag == 16:
            rec_pass_phr = input("Enter sender passphrase >> ")
            all_msg = Util.ConcatMessages(received_messages)
            Util.Get_AuthMessage(all_msg,rec_pass_phr)
        if received_messages[0].type == 16:
            Util.WritePacketsToFile(received_messages)
        elif received_messages[0].type == 64:
            Util.Get_RoutingTable(Util.ConcatMessages(received_messages), received_messages[0].source)
            print("Received message '", Util.ConcatMessages(received_messages), "'")
            # End Receiving Message
# Close socket
UDPSock.close()