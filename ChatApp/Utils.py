from ctypes import *
from struct import *
from socket import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from enum import Enum
from os import urandom
from bitstring import *
import sys, select,binascii, time, sys, os, getpass
import Configs as Config



padStr = lambda s: s + ((Config.blockSize - len(s) % Config.blockSize) * Config.padValue)
unpadStr = lambda s: s.rstrip(Config.padValue)

def Prepare_EncryptionVariables():
    Aeskey = get_random_bytes(16) #SessionKey koyacann
    iv = get_random_bytes(16)
    return Aeskey,iv

def AESEncMSg(AESkey, plainMsg):
    AESkey,iv = Prepare_EncryptionVariables()
    padMsg = padStr(plainMsg)
    cipher = AES.new(AESkey, AES.MODE_CBC, iv)
    return (iv + cipher.encrypt(padMsg))

def AESDecMSg(AESkey, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    decipher = AES.new(AESkey, AES.MODE_CBC, iv)
    deciphertext = decipher.decrypt(ciphertext)
    deciphertext = unpadStr(deciphertext)
    return(deciphertext)



# Read a line. Using select for non blocking reading of sys.stdin
def getLine():
    i,o,e = select.select([sys.stdin],[],[],0.0001)
    for s in i:
        if s == sys.stdin:
            input = sys.stdin.readline()
            return input
    return None

class MessageClass(Structure):
    _pack_ = 1
    _fields_ = [
        ("version", c_int8),
        ("source", c_byte * 4),
        ("destination", c_byte * 4),
        ("type", c_byte),
        ("flag", c_byte),
        ("hop_count", c_int8),
        ("length", c_int8),
        ("payload", c_char * 87)
    ]

def PrepareSocket():
    if len(Config.Connections) == 0:
        port = 6666
        # Host Parameters
        host = "192.168.0.18"
        UDPBuff = 1024
        UDPaddr = (host, port)

        UDPSocket = socket(AF_INET, SOCK_DGRAM)
        UDPSocket.bind(UDPaddr)
        Config.ConnectionsEntry = {'UDPSocket': UDPSocket, 'UDPaddr': UDPaddr, 'UDPBuff':UDPBuff}
        Config.Connections['Host1'] = Config.ConnectionsEntry
    else:
        Config.ConnectionsEntry = Config.Connections[0]
    return Config.ConnectionsEntry;


def DumpObject(obj):
    for attr in dir(obj):
        if hasattr(obj, attr):
            print("obj.%s = %s" % (attr, getattr(obj, attr)))


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
        ctype_instance = cast(pointer(cstring), POINTER(MessageClass)).contents
        messagelist.append(ctype_instance)
    return messagelist


def UUIDtoMessageSource(UUID):
    return (c_byte * 4).from_buffer(bytearray.fromhex(UUID))


def PrepareMessage(version, source, destination, type, flag, payload, hop_count):
    Message = MessageClass()
    Message.version = version
    Message.source = source
    Message.destination = destination
    Message.type = type
    Message.flag = flag
    Message.hop_count = hop_count
    if payload is None:
        Message.payload = bytes('', 'utf8')
    else:
        Message.payload = bytes(str(payload), 'utf8')
    packet = Pack(Message)
    return packet;


def PrepareRandomMessage(payload, flag):
    Message = MessageClass()
    Message.version = 1
    Message.source = UUIDtoMessageSource(Config.RoutingTable[0]['UUID'])
    Message.destination = UUIDtoMessageSource(Config.RoutingTable[0]['UUID'])
    Message.type = MessageTypes.Data.value
    if flag is None:
        Message.flag = 0x10
    else:
        Message.flag = flag
    Message.hop_count = 15
    if payload is None:
        Message.payload = bytes('', 'utf8')
    else:
        Message.payload = bytes(str(payload), 'utf8')
    #packet = Pack(Message)
    return Message;


def PrepareFileMessage(payload, flag):
    Message = MessageClass()
    Message.version = 1
    Message.source = UUIDtoMessageSource(Config.RoutingTable[0]['UUID'])
    Message.destination = UUIDtoMessageSource(Config.RoutingTable[0]['UUID'])
    Message.type = 0x01
    Message.flag = flag
    Message.hop_count = 15
    Message.payload = payload
    packet = Pack(Message)
    return packet;


def Send_AuthMessage(socket, addr, destination):
    auth_payload = PrepareAuthenticationPayload()
    header = PrepareAuthMessage(None, destination, None)
    Send_Message(socket, addr, auth_payload, header)


def PrepareAuthenticationPayload():
    rec_id = Config.KeyIDs[0]['UUID']  # input('Type recipients public key id >> ')
    myKeyid = Config.gpg.list_keys(True)[0]['fingerprint'][-8:]  # Private Key
    myPP = Config.passphrase
    AuthMessagetoSend = PGPEncMsg(rec_id, myPP)
    return AuthMessagetoSend;


def PGPEncMsg(rec_id, myPP):
    challenge = os.urandom(16)
    encrypted_challenge = Config.gpg.encrypt(challenge, rec_id).data
    signed_encrypted_challenge = Config.gpg.sign(encrypted_challenge, passphrase=myPP).data
    return str(signed_encrypted_challenge, 'utf-8')


def PGPDecMsg(enc_aut_msg, recPP):
    dec_msg = Config.gpg.decrypt(enc_aut_msg, passphrase=recPP)
    return dec_msg


def PrepareAuthMessage(payload, destination, flag):
    Message = MessageClass()
    Message.version = 1
    Message.source = UUIDtoMessageSource(Config.RoutingTable[0]['UUID'])
    Message.destination = UUIDtoMessageSource(destination)
    Message.type = MessageTypes.Data.value
    if flag is None:
        Message.flag = 0x10
    else:
        Message.flag = flag
    Message.hop_count = 15
    if payload is None:
        Message.payload = bytes(str(''), 'utf8')
    else:
        Message.payload = bytes(str(payload), 'utf8')
    return Message;

def PrepareNeighborMessage(flag):
    Message = MessageClass()
    Message.version = 1
    Message.source = UUIDtoMessageSource(Config.RoutingTable[0]['UUID'])
    Message.destination = UUIDtoMessageSource('FFFFFFFF')
    Message.type = MessageTypes.Auth.value
    Message.flag = flag
    Message.hop_count = 15
    Message.payload = bytes(str(''), 'utf8')
    return Message;


def PrepareACKMessage(destination):
    Message = MessageClass()
    Message.version = 1
    Message.source = UUIDtoMessageSource(Config.RoutingTable[0]['UUID'])
    Message.destination = UUIDtoMessageSource(destination)
    Message.type = MessageTypes.Control.value
    Message.flag = 0x04
    Message.hop_count = 15
    Message.payload = bytes(0x00)
    return Message;


def Send_Message(socket, addr, payload, header):
    messagetosend = ChunkMessages(payload, header)
    for message in messagetosend:
        if (socket.sendto(message, addr)):
            #print("Sending message '", message, "'.....")
            print("\nSending to: '", addr[0],'=>',addr[1])


def ChunkMessages(payload, header):
    MessageList = []
    if payload is None:
        header_flag = BitArray(bin=format(header.flag, '08b'))
        if header.type != MessageTypes.Control.value and header.type != MessageTypes.Auth.value:
            header_flag[7] = 1
        Message = PrepareMessage(header.version, header.source, header.destination, header.type, header_flag.int, '',
                                 header.hop_count)
        MessageList.append(Message)
    else:
        chunklist = Chunk(payload, MessageClass.payload.size)

        for chunks, islast in chunklist:
            if islast:
                header_flag = BitArray(bin=format(header.flag, '08b'))
                header_flag[7] = 1
                Message = PrepareMessage(header.version, header.source, header.destination, header.type,
                                         header_flag.int, chunks, header.hop_count)
            else:
                Message = PrepareMessage(header.version, header.source, header.destination, header.type, header.flag,
                                         chunks, header.hop_count)
            MessageList.append(Message)

    return MessageList


def Chunk(lst, n):
    "Yield successive n-sized chunks from lst"

    for i in range(0, len(lst), n):
        if len(lst) - i < n:
            yield lst[i:i + n], True
        else:
            yield lst[i:i + n], False


def ConcatMessages(MessageList):
    Final_Text = '';
    for message in MessageList:
        Final_Text = Final_Text + str(message.payload, 'utf-8')
        if message.flag == 1:
            break
    return Final_Text


def recv_timeout(the_socket,timeout=2):
    the_socket.setblocking(0)
    total_data=[];data='';begin=time.time()
    while 1:
        #if you got some data, then break after wait sec
        if total_data and time.time()-begin>timeout:
            break
        #if you got no data at all, wait a little longer
        elif time.time()-begin>timeout*2:
            break
        try:
            data=the_socket.recv(8192)
            if data:
                total_data.append(data)
                begin=time.time()
            else:
                time.sleep(0.1)
        except:
            pass
    return ''.join(total_data)

def recv_flag(the_socket, buf, timeout=2):
    # make socket non blocking
    the_socket.setblocking(0)

    # total data partwise in an array
    total_data = [];
    data = '';
    # beginning time
    begin = time.time()
    addr = {}
    while 1:
        # if you got some data, then break after timeout
        if total_data and Unpack(MessageClass, total_data[-1]).flag == 17 and time.time()-begin>timeout:
            break
        elif time.time() - begin > timeout * 2:
            break
        # recv something
        try:
            data,addr = the_socket.recvfrom(buf)
            if data:
                total_data.append(data)
                begin = time.time()
        except:
            pass
            # join all parts to make final string
    return total_data,addr


def Send_File(socket, addr, path):
    try:
        statinfo = os.stat(path)
        bar_rate = 100 / (statinfo.st_size / MessageClass.payload.size)
        progress = bar_rate
        f = open(path, "rb")
        data = f.read(MessageClass.payload.size)
        while (data):
            Message = PrepareFileMessage(data, 0)
            if (socket.sendto(Message, addr)):
                print("Sending ...")
                data = f.read(MessageClass.payload.size)
                progress = progress + bar_rate
                Update_Progress(progress / 100.0)
        Message = PrepareFileMessage("", 1)
        socket.sendto(Message, addr)
        progress = progress + bar_rate
        Update_Progress(progress / 100.0)
        print("File Sent.")
    except IOError:
        print(path + " is not valid.")
        pass


def WritePacketsToFile(Packets):
    f = open("ChatAppFile", 'wb')
    for packets in Packets:
        f.write(packets.payload)
    f.close()
    print("File Downloaded")


def Update_Progress(progress):
    barLength = 10  # Modify this to change the length of the progress bar
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
    block = int(round(barLength * progress))
    text = "\rPercent: [{0}] {1}% {2}".format("#" * block + "-" * (barLength - block), progress * 100, status)
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
    temp = input('>>Port Number: ')
    if temp.isdigit():
        return temp
    else:
        print("Please enter a valid port number.")
        Port_Input_Validator()


def SearchDictionary(values, searchFor, key):
    for k in values:
        if searchFor == k[key]:
                return k
    return None


def Send_RoutingTable(socket, addr):
    destination = input('>>Destination: ')
    message = PrepareAuthMessage(None,destination, None)
    Send_Message(socket,addr, Config.RoutingTable,message);
    print("Routing Table Sent.")


def Get_RoutingTable(data, sender_UUID):
    received_RT = eval(data)
    for received_line in enumerate(received_RT):
        try:
            line = (item for item in Config.RoutingTable if item["UUID"] == received_line[1]['UUID']).next()
        except:
            line = None

        if line is not None:
            if received_line[1]['Cost'] + 1 < line['Cost']:
                line['ViaUUID'] = sender_UUID
                line['Cost'] = received_line[1]['Cost'] + 1
        else:
            newline = {'UUID': received_line[1]['UUID'], 'ViaUUID': sender_UUID, 'Cost': received_line[1]['Cost'] + 1}
            Config.RoutingTable.append(dict(newline))
    Print_Table(Config.RoutingTable)


def Get_AuthMessage(UDPSocket,UDPaddr,remote_addr,msg, rec_passphrase, sender_UUID):
    decrypted_sign = Config.gpg.decrypt(message=str(msg), passphrase=rec_passphrase)
    decrypted_data = Config.gpg.decrypt(message=decrypted_sign.data, passphrase=Config.passphrase)
    if decrypted_data.ok:
        Session_Key_Entry = {'Key': decrypted_data.data, 'UUID': sender_UUID}
        Config.SessionKeyTable.append(dict(Session_Key_Entry))
        Print_Table(Config.SessionKeyTable)
        Send_ACKMessage(UDPSocket, remote_addr, sender_UUID)
    else:
        print('Session couldnt established')

def Send_ACKMessage(UDPSocket, remote_addr,sender_UUID):
    ackmessage = PrepareACKMessage(sender_UUID)
    Send_Message(UDPSocket, remote_addr, None, ackmessage)

def Send_AUTHSUCCEEDEDMessage(UDPSocket, remote_addr,sender_UUID):
    ackmessage = PrepareACKMessage(sender_UUID)
    Send_Message(UDPSocket, remote_addr, None, ackmessage)

def Add_KeyIDTable(remote_UUID):
    if SearchDictionary(Config.KeyIDs, remote_UUID, 'UUID') is None:
        username = input('Enter Username for this IP>>')
        keyID_newline = {'User': username, 'UUID': remote_UUID}
        Config.KeyIDs.append(dict(keyID_newline))
    else:
        print('This UUID Already Exists')

def Help():
    print("#To send file => #FILE <path> ")
    print("#To send text message, enter the desired text directly.")


def Print_Table(table):
    for line in enumerate(table):
        print(line)

def Get_RecipientInfoFromNick(NickName, SocketData):
    KeyID_Entry = SearchDictionary(Config.KeyIDs, NickName, 'User')
    Neighbor_Entry = ''
    isNode = False
    if KeyID_Entry:
        SessionKey_Entry = SearchDictionary(Config.SessionKeyTable, KeyID_Entry['UUID'], 'UUID' )
        if SessionKey_Entry:
            Neighbor_Entry = SearchDictionary(Config.NeighborTable, NickName, 'UUID')
            isNode = True;
        else:
            print('Initialising AUTH...')
            if Config.passphrase is None:
                Config.passphrase = getpass.getpass('Enter the PassPhrase>>')
            Neighbor_entry = SearchDictionary(Config.NeighborTable,KeyID_Entry['UUID'],'UUID' )
            Send_AuthMessage(SocketData, Neighbor_entry['Socket'], Neighbor_entry['UUID'] )
            Tokens[0]["WaitForListening"] = 1;
            Tokens[0]["WaitReason"] = "AUTH Message sent. Waiting for ACK.";
            print('AUTH Sent')
            isNode = False
    return Neighbor_Entry, isNode

Tokens = [
    {"WaitForSending":0, "WaitForListening":0, "WaitReason":''}
]
# MessageType Enum class
class MessageTypes(Enum):
    Data = 0x01
    Control = 0x02
    Auth = 0x04

