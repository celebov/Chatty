# Server program

from socket import *
import Utils as Util
import time


def recv_timeout(the_socket, timeout=2):
    # make socket non blocking
    the_socket.setblocking(0)

    # total data partwise in an array
    total_data = [];
    data = '';
    # beginning time
    begin = time.time()
    while 1:
        # if you got some data, then break after timeout
        if total_data and time.time() - begin > timeout:
            break

        # if you got no data at all, wait a little longer, twice the timeout
        elif time.time() - begin > timeout * 2:
            break
        # recv something
        try:
            data = the_socket.recv(8192)
            if data:
                total_data.append(data)
                # change the beginning time for measurement
                begin = time.time()
            else:
                # sleep for sometime to indicate a gap
                time.sleep(0.1)
        except:
            pass
        # join all parts to make final string
    return total_data


def recv_flag(the_socket):
    # make socket non blocking
    the_socket.setblocking(0)

    # total data partwise in an array
    total_data = [];
    data = '';
    # beginning time
    while 1:
        # if you got some data, then break after timeout
        if total_data and Util.Unpack(Util.message, total_data[-1]).flag == 1:
            break

        # recv something
        try:
            data = the_socket.recv(8192)
            if data:
                total_data.append(data)
        except:
            pass
        # join all parts to make final string
    return total_data


# Set the socket parameters
host = "localhost"
port = 21567
buf = 8192
addr = (host, port)

# Create socket and bind to address
UDPSock = socket(AF_INET, SOCK_DGRAM)
UDPSock.bind(addr)

while 1:

    # Receive Message
    received_data = recv_flag(UDPSock)
    if not received_data:
        print "Client has exited!"
        break
    else:
        Packet = Util.UnpackArray(received_data)
        print "Received message '", Util.ConcatMessages(Packet), "'"

    # End Receive Message

# Close socket
UDPSock.close()
