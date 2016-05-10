
from ctypes import *
from struct import *
from socket import *
from os import urandom
from Crypto.Cipher import AES
import binascii,time,sys,scapy.all,gnupg,os,TableScript


#gpg paramaters
gpg = gnupg.GPG(gnupghome='/home/raziel/.gnupg') #TYPE YOUR OWN .GNUPG PATH
gpg.encoding = 'utf-8'

#AES parameters
blockSize = 16
padValue= '#'
myAESKey = urandom(blockSize)

#AES padding & unpadding part
padStr = lambda s: s + ((blockSize - len(s) % blockSize) * padValue)
unpadStr = lambda s: s.rstrip(padValue)

class message(Structure):
    _pack_ = 1
    _fields_ = [
        ("version", c_int8 ),
        ("source", c_char * 4),
        ("destination", c_char * 4),
        ("type", c_int8 ),
        ("flag", c_int8 ),
        ("hop_count", c_int8  ),
        ("length", c_int8),
        ("payload", c_char * 87)
    ]


def Chunk(lst, n):
    "Yield successive n-sized chunks from lst"
    for i in xrange(0, len(lst), n):
        if len(lst) - i < n:
            yield lst[i:i + n], True
        else :
            yield lst[i:i + n], False


def Dump(obj):
   for attr in dir(obj):
       if hasattr( obj, attr ):
           print( "obj.%s = %s" % (attr, getattr(obj, attr)))

def Pack(ctype_instance):
    buf = string_at(byref(ctype_instance), sizeof(ctype_instance))
    return buf


def Unpack(ctype, buf):
    # type: (object, object) -> object
    cstring = create_string_buffer(buf)
    ctype_instance = cast(pointer(cstring), POINTER(ctype)).contents
    return ctype_instance

def UnpackArray(messagearray):
    # type: (object, object) -> object
    messagelist = []
    for i in messagearray:
        cstring = create_string_buffer(i)
        ctype_instance = cast(pointer(cstring), POINTER(message)).contents
        messagelist.append(ctype_instance)
    return messagelist

def PrepareMessage(version, source, destination, type, flag, hop_count):
    Message = message()
    Message.version = version
    Message.source = source
    Message.destination = destination
    Message.type = type
    Message.flag = flag
    Message.hop_count = hop_count
    packet = Pack(Message)
    return packet;

def PrepareRandomMessage(payload, flag):
    Message = message()
    Message.version = 1
    Message.source = "A1DB"
    Message.destination = "A1DB"
    Message.type = 64
    Message.flag = flag
    Message.hop_count = 15
    Message.payload = payload
    packet = Pack(Message)
    return packet;

def PrepareFileMessage(payload, flag):
    Message = message()
    Message.version = 1
    Message.source = "A1DB"
    Message.destination = "A1DB"
    Message.type = 16
    Message.flag = flag
    Message.hop_count = 15
    Message.payload = payload
    packet = Pack(Message)
    return packet;

def PrepareAuthenticationPayload(challenge):
   # challenge = raw_input('Type challenge >> ')
    rec_id = raw_input('Type recipients public key id >> ')
    myKeyid = raw_input('Type your private key id >> ')
    myPP = raw_input('Type your passphrase to sign >> ')
    AuthMessagetoSend = PGPEncMsg(challenge, rec_id, myKeyid, myPP)
    return AuthMessagetoSend;

def SendMessage(socket, payload, addr):
    messagetosend = ChunkMessages(payload)
    for message in messagetosend:
        if (socket.sendto(message, addr)):
            print "Sending message '", message, "'....."

def ChunkMessages(payload):

    payload = str(payload)
    chunklist = Chunk(payload, message.payload.size)
    MessageList = []

    for chunks,islast in chunklist:
        if islast:
            Message = PrepareRandomMessage(chunks, 1)
            MessageList.append(Message)
        else:
            Message = PrepareRandomMessage(chunks, 0)
            MessageList.append(Message)

    return MessageList

def ConcatMessages(MessageList):
    Final_Text = '';
    for message in MessageList:
        Final_Text = Final_Text + message.payload
        if message.flag == 1:
            break
    return Final_Text

def PGPEncMsg(challenge,rec_id, myKeyid,myPP):
    enc_aut_msg = str(gpg.encrypt(data=challenge, recipients=rec_id, sign=myKeyid, passphrase=myPP))
    return enc_aut_msg

def PGPDecMsg(enc_aut_msg,recPP):
    dec_msg = gpg.decrypt(enc_aut_msg,passphrase=recPP)
    return dec_msg

def AESEncMSg(AESkey, plainMsg):
    plainMsg = padStr(plainMsg)
    # document states that IV shall be the first 16 bits of payload
    iv = plainMsg[:16]
    cipher = AES.new(AESkey, AES.MODE_CBC, iv)
    return (iv + cipher.encrypt(plainMsg)).encode("hex")

def AESDecMSg(AESkey, cipherMsg):
    cipherMsg = cipherMsg.decode("hex")
    iv = cipherMsg[:16]
    cipherMsg = cipherMsg[16:]
    cipher = AES.new(AESkey, AES.MODE_CBC, iv)
    return cipher.decrypt(cipherMsg)

import sqlite3
conn = sqlite3.connect('networkTables.db')
conn.text_factory = str
curs = conn.cursor()

def sessionKeyControl(recUuId,UDPSock,addr):
    curs.execute("SELECT sessionKey FROM sessionKeyTable WHERE UUID = ?", (recUuId,))
    record = curs.fetchall()
    if len(record) == 0:
        SessId = raw_input("Enter a session key for user %s >>" %recUuId)
        encSessId = PrepareAuthenticationPayload(SessId)
        SendMessage(UDPSock, encSessId, addr)
        curs.execute("INSERT INTO sessionKeyTable (sessionKey, UUID) VALUES (?,?)", (SessId, recUuId,))
        conn.commit()
        return SessId
    else:
        return record
    curs.close()

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


def recv_flag(the_socket, buf):
    # make socket non blocking
    the_socket.setblocking(0)

    # total data partwise in an array
    total_data = [];
    data = '';
    # beginning time
    while 1:
        # if you got some data, then break after timeout
        if total_data and Unpack(message, total_data[-1]).flag == 1:
            break

        # recv something
        try:
            data = the_socket.recv(buf)
            if data:
                total_data.append(data)
        except:
            pass
            # join all parts to make final string
    return total_data

def Send_File(socket, addr, path):
    try:
        statinfo = os.stat(path)
        bar_rate = 100/(statinfo.st_size / message.payload.size)
        progress = bar_rate
        f = open(path, "rb")
        data = f.read(message.payload.size)
        while (data):
            Message = PrepareFileMessage(data, 0)
            if (socket.sendto(Message, addr)):
                print "Sending ..."
                data = f.read(message.payload.size)
                progress = progress + bar_rate
                Update_Progress(progress / 100.0)
        Message = PrepareFileMessage("", 1)
        socket.sendto(Message, addr)
        progress = progress + bar_rate
        Update_Progress(progress / 100.0)
        print "File Sent."
    except IOError:
        print path + " is not valid."
        pass

def Send_Auth(socket,addr):
    auth_payload = PrepareAuthenticationPayload()
    SendMessage(socket, auth_payload, addr)

def WritePacketsToFile(Packets):
    f = open("ChatAppFile", 'wb')
    for packets in Packets:
        f.write(packets.payload)
    f.close()
    print "File Downloaded"

def Update_Progress(progress):
    barLength = 10 # Modify this to change the length of the progress bar
    status = ""
    if isinstance(progress, int):
        progress = float(progress)
    if not isinstance(progress, float):
        progress = 0
        status = "error: progress var must be float\r\n"
    if progress < 0:
        progress = 0
        status = "Halt...\r\n"
    if progress >= 1:
        progress = 1
        status = "Done...\r\n"
    block = int(round(barLength*progress))
    text = "\rPercent: [{0}] {1}% {2}".format( "#"*block + "-"*(barLength-block), progress*100, status)
    sys.stdout.write(text)
    sys.stdout.flush()

def Validate_IPV4(address):
    try:
        inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            inet_aton(address)
        except error:
            return False
        return address.count('.') == 3
    except:  # not a valid address
        return False

    return True

def Validate_IPV6(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

def Port_Input_Validator():
    temp = raw_input('>>Port Number: ')
    if temp.isdigit():
        return temp
    else:
        print "Please enter a valid port number."
        Port_Input_Validator()

def SearchDictionary(values, searchFor):
    for k in values:
        for v in values[k]:
            if searchFor in v:
                return k
    return None

def Send_RoutingTable(socket,addr):
    SendMessage(socket,RoutingTable,addr);
    print "Routing Table Sent."

def Get_RoutingTable(data, sender_UUID):
    received_RT = eval(data)
    for received_line in enumerate(received_RT):
        for existing_line in enumerate(RoutingTable):
            if received_line[0]['UUID'] == existing_line[0]['UUID']:
                if received_line[0]['Cost'] + 1 < existing_line[0]['Cost']:
                    existing_line[0]['ViaUUID'] = sender_UUID
            else:
                newline = {'UUID': received_line[0]['UUID'], 'ViaUUID': sender_UUID, 'Cost': received_line[0]['Cost'] + 1}
                RoutingTable.append(dict(newline))
    for line in enumerate(RoutingTable):
        print line




def Help():
    print "#To send file => #FILE <path> "
    print "#To send text message, enter the desired text directly."

RoutingTable = [
	{'UUID':'EC8AF480', 'ViaUUID':'EC8AF480', 'Cost': 0},
	{'UUID':'A1DB1329', 'ViaUUID':'A1DB1329', 'Cost': 1}
	]