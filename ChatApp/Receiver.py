# Main program

from socket import *
import Utils as Util
import gnupg
import time


SocketData = Util.PrepareSocket()


while 1:
    # Receive Message
    received_data = Util.recv_flag(SocketData['UDPSocket'], SocketData['UDPBuff'])
    if not received_data:
        print("Client has exited!")
        break
    else:
        received_messages = Util.UnpackArray(received_data)
        if received_messages[0].type == 1 and received_messages[0].flag == 16:
            rec_pass_phr = input("Enter sender passphrase >> ")
            all_msg = Util.ConcatMessages(received_messages)
            source_UUID = bytearray(received_messages[0].source).hex().upper()
            Util.Get_AuthMessage(SocketData['UDPSocket'], SocketData['UDPaddr'],SocketData['remote_addr'],all_msg,rec_pass_phr, source_UUID)
        if received_messages[0].type == 16:
            Util.WritePacketsToFile(received_messages)
        elif received_messages[0].type == 64:
            Util.Get_RoutingTable(Util.ConcatMessages(received_messages), received_messages[0].source)
            print("Received message '", Util.ConcatMessages(received_messages), "'")
            # End Receiving Message
# Close socket
Util.Connections['Host1']['UDPSocket'].close()