# Main program

from socket import *
import Utils as Util
import time
import getpass
import Configs as Config

SocketData = Util.PrepareSocket()

print("Ready to Chat! Type #HELP for manual.")
print("#To send file => #FILE <path> ")
print("#To send text message, enter the desired text directly.")
if len(Config.NeighborTable) == 0:
    print("You dont have any Neighbour, to add use #ADDNEIGH")
while 1:

    user_input = Util.getLine();
    # Send Message
    if user_input is not None :
        if "#HELP" in user_input:
            Util.Help()
        elif "#ADDNEIGH" in user_input:
            remote_ip = input('Type Remote Ip Address >>')
            header = Util.PrepareNeighborMessage(0x01) #0x01 => Initiation flag
            UDPaddr = (remote_ip, SocketData['UDPaddr'][1])
            Util.Send_Message(SocketData['UDPSocket'], UDPaddr, None, header)
        elif "#FILE" in user_input:
            Util.Send_File(SocketData['UDPSocket'], SocketData['remote_addr'], user_input[5:].strip())
        elif "#AUTH" in user_input:
            if Config.passphrase is None:
                Config.passphrase =  getpass.getpass('Enter the PassPhrase>>')
            Util.Send_AuthMessage(SocketData['UDPSocket'], SocketData['remote_addr'])
        elif "#ROUT" in user_input:
            Util.Send_RoutingTable(SocketData['UDPSocket'], SocketData['remote_addr'])
        elif user_input:
            header = Util.PrepareRandomMessage(None,None)
            Util.Send_Message(SocketData['UDPSocket'],SocketData['remote_addr'], user_input, header)

            # else:
            # print "Session has not been established!"

    # Receive Message
    received_data,remote_addr = Util.recv_flag(SocketData['UDPSocket'], SocketData['UDPBuff'])
    if not received_data:
        continue
    else:
        received_messages = Util.UnpackArray(received_data)

        #ADDNEIGH Message
        if received_messages[0].type == Util.MessageTypes.Auth.value and received_messages[0].flag == 0x01:
            Util.Send_ACKMessage(SocketData['UDPSocket'], remote_addr, Config.RoutingTable[0]['UUID'])
            header = Util.PrepareNeighborMessage(0x02)  # 0x02 => AuthSuccess flag
            Util.Send_Message(SocketData['UDPSocket'], remote_addr, None, header)
            print('Success Message Sent')

        #AUTH Message
        if received_messages[0].type == 1 and received_messages[0].flag == 16:
            rec_pass_phr = input("Enter sender passphrase >> ")
            all_msg = Util.ConcatMessages(received_messages)
            source_UUID = bytearray(received_messages[0].source).hex().upper()
            Util.Get_AuthMessage(SocketData['UDPSocket'], SocketData['UDPaddr'], SocketData['remote_addr'], all_msg,
                                 rec_pass_phr, source_UUID)
        #ACK0 Message (NEIGH)
        if received_messages[0].type == Util.MessageTypes.Control.value and received_messages[0].flag == 0x04:
            if Util.SearchDictionary(Config.NeighborTable,bytearray(received_messages[0].source).hex().upper(), 'UUID') is None:
                remote_UUID = bytearray(received_messages[0].source).hex().upper()
                Util.Add_KeyIDTable(remote_UUID)
                neighbour_newline = {'UUID': remote_UUID, 'Socket': remote_addr,
                        'PassiveTimer': time.time()}
                Config.NeighborTable.append(dict(neighbour_newline))
                Util.Send_ACKMessage(SocketData['UDPSocket'], remote_addr, Config.RoutingTable[0]['UUID'])
                print('Added to Neigh. Table.')
                Util.Print_Table(Config.KeyIDs)
            print('ACK0 Received')

            #ACK1 Message (NEIGH)
            if len(received_messages) > 1 and received_messages[1].type == Util.MessageTypes.Auth.value and received_messages[1].flag == 0x02:
                remote_UUID = bytearray(received_messages[0].source).hex().upper()
                Util.Add_KeyIDTable(remote_UUID)
                newline = {'UUID':bytearray(received_messages[0].source).hex().upper(), 'Socket': remote_addr, 'PassiveTimer': time.time()}
                Config.NeighborTable.append(dict(newline))
                print('Added to Neigh. Table.')
                Util.Send_ACKMessage(SocketData['UDPSocket'], remote_addr, Config.RoutingTable[0]['UUID'])
                print('Session Established')
                continue
        if received_messages[0].type == 16:
            Util.WritePacketsToFile(received_messages)
            continue
        elif received_messages[0].type == 64:
            Util.Get_RoutingTable(Util.ConcatMessages(received_messages), received_messages[0].source)
            print("Received message '", Util.ConcatMessages(received_messages), "'")
            continue
            # End Receiving Message
        elif received_messages[0].type == Util.MessageTypes.Data.value :
            print("Received message '", Util.ConcatMessages(received_messages), "'")
            continue

SocketData['UDPSocket'].close()