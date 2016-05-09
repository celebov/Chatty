# Main program

from socket import *
import Utils as Util
import time

# Set the socket parameters Manually
host = "localhost"
port = 21567
buf = 1024
addr = (host, port)
# End Setting Socket parameters manually

# Set Socket Parameters Dynamically
host = Util.Validate_IPV4(raw_input('>>HostName: '))
port = Util.Port_Input_Validator()

# End Socket Parameters Dynamically
# Create socket and bind lto address
UDPSock = socket(AF_INET, SOCK_DGRAM)
UDPSock.bind(addr)

SessionKey = Util.sessionKeyControl("localhost",UDPSock,addr)

if SessionKey != "":

    print "Ready to Chat! Type #HELP for manual."
    print "#To send file => #FILE <path> "
    print "#To send text message, enter the desired text directly."

    while 1:
        # Send Message
        user_input = raw_input('>> ')

        if "#HELP" in user_input:
            Util.Help()
            continue
        elif "#FILE" in user_input:
            Util.Send_File(UDPSock, addr, user_input[5:].strip())
        elif "#AUTH" in user_input:
            Util.Send_Auth(UDPSock,addr)
        elif user_input:
            Util.SendMessage(UDPSock, user_input, addr)
        # End Sending Message

        # Receive Message
        received_data = Util.recv_flag(UDPSock, buf)
        if not received_data:
            print "Client has exited!"
            break
        if "PGP" not in received_data:
            received_messages = Util.UnpackArray(received_data)
            if received_messages[0].type == 16:
                Util.WritePacketsToFile(received_messages)
            elif received_messages[0].type == 64:
                print "Received message '", Util.ConcatMessages(received_messages), "'"
        # End Receiving Message
    #  Close socket
    UDPSock.close()
else:
    print "Session has not been established!"
    UDPSock.close()