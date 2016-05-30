# Main program

from socket import *
import Utils as Util
import time
import getpass,re, logging, logging.config
import Configs as Config

print("Welcome to Ultra Needlessly Secure Chat APP.")
print("This is Demonstration Only version. You can Change The logger settings via Logs/Log-Config.json.")

SocketData = Util.PrepareSocket()
Util.Prepare_GnuPG(None)

Util.Help()
if len(Config.NeighborTable) == 0:
    print("You dont have any Neighbour, to add use #ADDNEIGH")
while 1:
    if Config.Tokens[0]["WaitForListening"] != 1:
        user_input = Util.getLine();
        # Send Message
        if user_input is not None :
            if "#HELP" in user_input:
                Util.Help()
            elif "#ADDNEIGH" in user_input:
                remote_ip = input('Type Remote Ip Address >>')
                if Util.SearchDictionary(Config.NeighborTable,(remote_ip,SocketData['UDPaddr'][1]), 'Socket'):
                    print('This address already exists.')
                else:
                    header = Util.PrepareNeighborMessage(0x01)  # 0x01 => Initiation flag
                    UDPaddr = (remote_ip, SocketData['UDPaddr'][1])
                    Util.Send_Message(SocketData['UDPSocket'], UDPaddr, None, header)
            elif "#FILE" in user_input:
                 user = input("Which User Will Receive the File => ")
                 path = input("Enter File Path =>")
                 Recipient_Info, isNode = Util.Get_RecipientInfoFromNick(user, SocketData['UDPSocket'])
                 if Recipient_Info is None or isnode == False:
                     logging.warning("Recipient can not be found.")
                     print("Wrong User Info. Please Check username or establish Session...")
                 else:
                    Util.Send_File(SocketData['UDPSocket'], Recipient_Info['Socket'], user_input[5:].strip())
            elif "#ROUT" in user_input:
                destination = input('»Destination Username: ')
                Entry, isnode = Util.Get_RecipientInfoFromNick(destination, SocketData['UDPSocket'])
                Util.Send_RoutingTable(SocketData['UDPSocket'], Entry['Socket'], Entry['UUID'])
            elif user_input:
                if user_input.split(' ')[0].startswith('#'):
                    recipient_ID = user_input.split(' ')[0].split('#')[1]
                else:
                    print('Type #<Nick> to identify the receiver')
                    continue
                Recipient_Info, isNode = Util.Get_RecipientInfoFromNick(recipient_ID, SocketData['UDPSocket'])
                if isNode:
                    message_text = user_input[len(user_input.split(' ')[0]):].strip()
                    header = Util.PrepareRandomMessage(None, 0x04, Recipient_Info['UUID'])
                    Util.Send_Message(SocketData['UDPSocket'], Recipient_Info['Socket'], message_text, header)
                else:
                    logging.info('AUTH Protocol is taking place for : ' + recipient_ID)

                # else:
                # print "Session has not been established!"
    else:
        logging.info(Config.Tokens[0]["WaitReason"] + " Please Wait.")
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
            logging.info('Success Message Sent')

        #AUTH Message
        if received_messages[0].type == 1 and received_messages[0].flag == 16:
            Util.Set_Passphrase()
            all_msg = Util.ConcatMessages(received_messages)
            source_UUID = bytearray(received_messages[0].source).hex().upper()
            source_info = Util.SearchDictionary(Config.NeighborTable, source_UUID, 'UUID')
            Util.Get_AuthMessage(SocketData['UDPSocket'], SocketData['UDPaddr'], source_info['Socket'], all_msg,
                                 source_UUID)
        #ACK0 Message (NEIGH)
        if received_messages[0].type == Util.MessageTypes.Control.value and received_messages[0].flag == 0x04:
            logging.debug("Neighboring ACK Message received from: " + bytearray(received_messages[0].source).hex().upper())
            if Util.SearchDictionary(Config.NeighborTable,bytearray(received_messages[0].source).hex().upper(), 'UUID') is None:
                remote_UUID = bytearray(received_messages[0].source).hex().upper()
                Util.Add_KeyIDTable(remote_UUID)
                neighbour_newline = {'UUID': remote_UUID, 'Socket': remote_addr,
                        'PassiveTimer': time.time()}
                Config.NeighborTable.append(dict(neighbour_newline))
                Util.Send_ACKMessage(SocketData['UDPSocket'], remote_addr, Config.RoutingTable[0]['UUID'])
                logging.debug("KeyID Table : " + str(Config.KeyIDs))
            Config.Tokens[0]["WaitForListening"] = 0;
            Config.Tokens[0]["WaitReason"] = None;
            logging.info("SESSION ACK Message from " + bytearray(received_messages[0].source).hex().upper() + " Processsed!." )
            if Util.SearchDictionary(Config.SessionKeyTable, bytearray(received_messages[0].source).hex().upper(), 'UUID') is None:
                logging.info("You can start Session Initialization Process with: " + bytearray(received_messages[0].source).hex().upper())
            else:
                logging.info("You can start Conversation with: " + bytearray(received_messages[0].source).hex().upper())

            #ACK1 Message (NEIGH)
            if len(received_messages) > 1 and received_messages[1].type == Util.MessageTypes.Auth.value and received_messages[1].flag == 0x02:
                remote_UUID = bytearray(received_messages[0].source).hex().upper()
                Util.Add_KeyIDTable(remote_UUID)
                newline = {'UUID':bytearray(received_messages[0].source).hex().upper(), 'Socket': remote_addr, 'PassiveTimer': time.time()}
                Config.NeighborTable.append(dict(newline))
                logging.debug("Neigh Table : " + str(Config.NeighborTable))
                Util.Send_ACKMessage(SocketData['UDPSocket'], remote_addr, Config.RoutingTable[0]['UUID'])
                logging.info('Session Established with ' + bytearray(received_messages[1].source).hex().upper() + " Waiting For ACK Message...") #WAITING ACK!!!!
                continue
        #Receive File
        if received_messages[0].type == 1 and (received_messages[0].flag == 8 or received_messages[0].flag == 9):
            Util.WritePacketsToFile(received_messages)
            continue

        elif received_messages[0].type == 1 and (received_messages[0].flag == 33 or received_messages[0].flag == 32):
            Util.Get_RoutingTable(Util.ConcatMessages(received_messages),bytearray(received_messages[0].source).hex().upper())
            continue

        elif received_messages[0].type == Util.MessageTypes.Data.value and received_messages[0].flag != 16:
            encrypted_text = Util.ConcatMessages(received_messages)
            print("Received message '", encrypted_text, "'")
            continue
# End Receiving Message
SocketData['UDPSocket'].close()