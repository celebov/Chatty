from ctypes import *
from struct import *
from socket import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from enum import Enum
from os import urandom
from bitstring import *
import sys, select,binascii, time, sys, os, getpass, fcntl, json, logging, logging.config, gnupg, sys, getpass, traceback
import Configs as Config

gpg = None
def Prepare_GnuPG(path):
    try:
        global gpg
        if path is None:
            logging.info("Preparing GnuPG...")
            path = '/home/'+ getpass.getuser() +'/.gnupg'
            gpg = gnupg.GPG(gnupghome=path)  # TYPE YOUR OWN .GNUPG PATH
            gpg.encoding = 'utf-8'
        else:
            gpg = gnupg.GPG(gnupghome=path)  # TYPE YOUR OWN .GNUPG PATH
            gpg.encoding = 'utf-8'
        return gpg
    except PermissionError:
        logging.error("GNUPG couldn't find base files in : " + path)
        path = input("Enter The Path for GnuPG Base Files => ")
        Prepare_GnuPG(path)


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

def setup_logging(default_path='Logs/Log-Config.json',default_level=logging.INFO,env_key='LOG_CFG'):
    try:
        path = default_path
        value = os.getenv(env_key, None)
        if value:
            path = value
        if os.path.exists(path):
            with open(path, 'rt') as f:
                config = json.load(f)
            logging.config.dictConfig(config)
        else:
            logging.basicConfig(level=default_level)
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        raise

def Prepare_Debugstring(list):
    try:
        string = "Variables "
        for str in list:
            string = string + "{},"

        string = string[:len(string) -1]
        string = string.format(*list)
        return string;
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        return "Error Occured on DebugString Preparation"

setup_logging()

def SearchDictionary(values, searchFor, key):
    variable_list = [values, searchFor, key]
    logging.debug('Searching Dictionary : ' + Prepare_Debugstring(variable_list))
    try:
        for k in values:
            if searchFor == k[key]:
                    return k
        return None
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        logging.error("Variables : " + values +"\n"+ searchFor + "\n" + key)
        return None

#padStr = lambda s: s + ((Config.blockSize - len(s) % Config.blockSize) * Config.padValue)
def padStr(str):
    try:
        logging.debug("Padding string : " + str.decode('utf-8'))
        str = str + ((Config.blockSize - len(str) % Config.blockSize) * Config.padValue)
        logging.debug("Padded string : " + str.decode('utf-8'))
        return str
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        logging.error("Variables : " + str.decode('utf-8'))
        raise

#unpadStr = lambda s: s.rstrip(Config.padValue)
def unpadStr(str):
    try:
        logging.debug("UnPadding string : " + str.decode('utf-8'))
        str = str.rstrip(Config.padValue)
        logging.debug("UnPadded string : " + str.decode('utf-8'))
        return str
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        logging.error("\n" + "Variables : " + str.decode('utf-8'))
        raise


def Prepare_EncryptionVariables(receiver_UUID):
    logging.info("Preparing Encryption Variables for :" + receiver_UUID)
    try:
        SessionKey_Entry = SearchDictionary(Config.SessionKeyTable, receiver_UUID, 'UUID')
        Aeskey = SessionKey_Entry['Key']#get_random_bytes(16)
        iv = get_random_bytes(16)
        variable_list = [SessionKey_Entry, str(Aeskey), str(iv)]
        debugstring = Prepare_Debugstring(variable_list)
        logging.debug("Encryption " + debugstring)
        return Aeskey,iv
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))


def AESEncMSg(plainMsg, receiver_UUID):
    receiver_UUID = bytearray(receiver_UUID).hex().upper()
    variable_list = [plainMsg, receiver_UUID]
    logging.info("Encrypting Message For : " + receiver_UUID)
    try:
        logging.debug("Encrypting Message... " + Prepare_Debugstring(variable_list))
        AESkey,iv = Prepare_EncryptionVariables(receiver_UUID)
        padMsg = padStr(bytes(plainMsg, 'utf-8'))
        cipher = AES.new(AESkey, AES.MODE_CBC, iv)
        variable_list = [AESkey,iv,padMsg,cipher]
        logging.debug("Encrypted with : " + Prepare_Debugstring(variable_list))
        return (iv + cipher.encrypt(padMsg))
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        logging.error(Prepare_Debugstring(variable_list))
        raise

def AESDecMSg(sender_UUID, ciphertext):
    sender_UUID = bytearray(sender_UUID).hex().upper()
    variable_list = [sender_UUID, ciphertext]
    logging.info("Decrypting Message From : " + sender_UUID)
    try:
        logging.debug("Decrypting Message... " + Prepare_Debugstring(variable_list))
        SessionKey_Entry = SearchDictionary(Config.SessionKeyTable, sender_UUID, 'UUID')
        Aeskey = SessionKey_Entry['Key']
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        decipher = AES.new(Aeskey, AES.MODE_CBC, iv)
        deciphertext = decipher.decrypt(ciphertext)
        deciphertext = unpadStr(deciphertext)
        variable_list = [SessionKey_Entry, Aeskey, ciphertext, decipher, deciphertext]
        logging.debug("Encrypted with : " + Prepare_Debugstring(variable_list))
        return(deciphertext)
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        logging.error("\n" + Prepare_Debugstring(variable_list))
        raise



# Read a line. Using select for non blocking reading of sys.stdin
def getLine():
    try:
        i,o,e = select.select([sys.stdin],[],[],0.0001)
        for s in i:
            if s == sys.stdin:
                input = sys.stdin.readline()
                return input
        return None
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        raise




def Get_LocalIP():
    try:
        import netifaces
        interfaces = netifaces.interfaces();
        for str in interfaces:
            print(str)
        chosen_interface = input('Please Choose The Network Interface From List Above =>')
        if chosen_interface not in interfaces:
            print('Wrong Input. Please Choose From List.')
            Get_LocalIP()
        else:
            try:
                ip = netifaces.ifaddresses(chosen_interface)[netifaces.AF_INET][0]['addr']
                if ip == None:
                    print("Wrong Interface. Please Select Another One...")
                else:
                    return netifaces.ifaddresses(chosen_interface)[netifaces.AF_INET][0]['addr']
            except KeyError:
                print("Wrong Interface. Please Select Another One...")
                Get_LocalIP()
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        raise

def Get_Port():
    try:
        temp = input('>>Port Number: ')
        if temp.isdigit() and int(temp) < 65535:
            return int(temp)
        else:
            print("Please enter a valid port number.")
            logging.warning("Entered Port number is not Valid...")
            Get_Port()
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                              exc_traceback)))
        logging.info("Because of Errors PORT 6666 is assigned.")
        return 6666

def PrepareSocket():
    try:
        if len(Config.Connections) == 0:

            port = Get_Port()
            # Host Parameters
            host = Get_LocalIP()

            UDPBuff = 1024
            UDPaddr = (host, port)

            UDPSocket = socket(AF_INET, SOCK_DGRAM)
            UDPSocket.bind(UDPaddr)

            Config.ConnectionsEntry = {'UDPSocket': UDPSocket, 'UDPaddr': UDPaddr, 'UDPBuff':UDPBuff}
            Config.Connections['Host1'] = Config.ConnectionsEntry
        else:
            Config.ConnectionsEntry = Config.Connections[0]
        logging.info("Socket Information: " + str(UDPaddr))
        return Config.ConnectionsEntry;
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        raise


def Pack(ctype_instance):
    try:
        buf = string_at(byref(ctype_instance), sizeof(ctype_instance))
        return buf
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        raise


def Unpack(ctype, buf):
    try:
        # type: (object, object) -> object
        cstring = create_string_buffer(buf)
        ctype_instance = cast(pointer(cstring), POINTER(ctype)).contents
        return ctype_instance
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        raise


def UnpackArray(messagearray):
    logging.info("Unpacking Message Array...")
    try:
        # type: (object, object) -> object
        messagelist = []
        for i in messagearray:
            #cstring = create_string_buffer(i)
            #ctype_instance = cast(pointer(cstring), POINTER(MessageClass)).contents
            #messagelist.append(ctype_instance)
            messagelist.append(Unpack(MessageClass, i))
        return messagelist
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        raise

def UUIDtoMessageSource(UUID):
    try:
        return (c_byte * 4).from_buffer(bytearray.fromhex(UUID))
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        raise


def PrepareMessage(version, source, destination, _type, flag, payload, hop_count):
    try:
        logging.debug("Preparing Message for :" + bytearray(destination).hex().upper())
        logging.debug("Payload Type: " + str(type(payload)))
        Message = MessageClass()
        Message.version = version
        Message.source = source
        Message.destination = destination
        Message.type = _type
        Message.flag = flag
        Message.hop_count = hop_count
        if payload is None:
            Message.payload = bytes('', 'utf8')
        else:
            if Message.type == MessageTypes.Data.value and ( Message.flag == 4 or Message.flag == 5 or Message.flag == 8 or Message.flag == 9):
                payload = AESEncMSg(payload, Message.destination)
            else:
                payload = str(payload)
        if isinstance(payload,str):
            Message.payload = bytes(payload, 'utf8')
        elif isinstance(payload,bytes):
            Message.payload = payload
        packet = Pack(Message)
        return packet;
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        raise


def PrepareRandomMessage(payload, flag , destination):
    try:
        variable_list = [payload, flag,destination]
        logging.debug("Preparing Random Message Packet Header with " + Prepare_Debugstring(variable_list))
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
            Message.payload = bytes('', 'utf8')
        else:
            Message.payload = bytes(str(payload), 'utf8')
        #packet = Pack(Message)
        return Message;
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        raise


def PrepareFileMessage(payload, flag):
    try:
        logging.info('Preparing File Message Packet...')
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
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        raise


def Send_AuthMessage(socket, addr, destination):
    try:
        variable_list = [socket, addr,destination]
        logging.debug("Auth Message Sending Protocol Initialized with " + Prepare_Debugstring(variable_list))

        auth_payload = PrepareAuthenticationPayload(destination)
        header = PrepareAuthMessage(None, destination, None)
        Send_Message(socket, addr, auth_payload, header)
        logging.info("Auth Message Sent to: " + destination)
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))



def PrepareAuthenticationPayload(receiver_UUID):
    try:
        logging.info("Auth Payload is being prepared...")
        # input('Type recipients public key id >> ')
        myPP = Config.passphrase
        AuthMessagetoSend, challenge = PGPEncMsg(receiver_UUID, myPP)
        Session_Key_Entry = {'Key': challenge, 'UUID': receiver_UUID}
        Config.SessionKeyTable.append(dict(Session_Key_Entry))
        logging.debug("SessionKeyTable : " + str(Config.SessionKeyTable))
        return AuthMessagetoSend;
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))


def PGPEncMsg(rec_id, myPP):
    try:
        logging.info("PGP Challenge Encryption Process started...")
        challenge = os.urandom(16)
        encrypted_challenge = gpg.encrypt(challenge, rec_id).data
        signed_encrypted_challenge = gpg.sign(encrypted_challenge, passphrase=myPP).data
        return str(signed_encrypted_challenge, 'utf-8'), challenge
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))


def PGPDecMsg(enc_aut_msg, recPP):
    try:
        logging.info("PGP Challenge Decryption Process started...")
        dec_msg = gpg.decrypt(enc_aut_msg, passphrase=recPP)
        logging.debug(str(dec_msg))
        return dec_msg
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))


def PrepareAuthMessage(payload, destination, flag):
    try:
        variable_list = [payload,destination,flag]
        logging.debug("Auth Message is being prepared with " + Prepare_Debugstring(variable_list))
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
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))

def PrepareNeighborMessage(flag):
    try:
        logging.info("Neighboring Message is being prepared...")
        Message = MessageClass()
        Message.version = 1
        Message.source = UUIDtoMessageSource(Config.RoutingTable[0]['UUID'])
        Message.destination = UUIDtoMessageSource('FFFFFFFF')
        Message.type = MessageTypes.Auth.value
        Message.flag = flag
        Message.hop_count = 15
        Message.payload = bytes(str(''), 'utf8')
        return Message;
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))



def PrepareACKMessage(destination):
    try:
        logging.debug("ACK Message is being prepared for : " + destination)
        Message = MessageClass()
        Message.version = 1
        Message.source = UUIDtoMessageSource(Config.RoutingTable[0]['UUID'])
        Message.destination = UUIDtoMessageSource(destination)
        Message.type = MessageTypes.Control.value
        Message.flag = 0x04
        Message.hop_count = 15
        Message.payload = bytes(0x00)
        return Message;
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))



def Send_Message(socket, addr, payload, header):
    try:
        logging.info("Message Sending Protocol Initialized...")
        variable_list = [socket, addr, payload, header]
        logging.debug(Prepare_Debugstring(variable_list))
        messagetosend = ChunkMessages(payload, header)
        for message in messagetosend:
            if not (socket.sendto(message, addr)):
                logging.warning("Couldn't Send a packet!: " + addr[0] +"=>" + addr[1])
                #print("Sending message '", message, "'.....")
        logging.debug("Sent to: " + str(addr[0]) +"=>" + str(addr[1]))

    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        logging.error("Couldn't send messages...")
        pass


def ChunkMessages(payload, header):
    try:
        variable_list = [payload,header]
        logging.debug("Chunking Procedure started for: " + Prepare_Debugstring(variable_list))
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
        logging.debug("Chunking completed with:" + str(len(MessageList)) + " Packets.")
        return MessageList
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        return []


def Chunk(lst, n):
    "Yield successive n-sized chunks from lst"
    try:
        for i in range(0, len(lst), n):
            if len(lst) - i < n:
                yield lst[i:i + n], True
            else:
                yield lst[i:i + n], False
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        raise


def ConcatMessages(MessageList):
    try:
        logging.info("Message Concatenation Process Started...")
        Final_Text = '';
        for message in MessageList:
            if message.type == MessageTypes.Data.value and (message.flag == 4 or message.flag == 5 or message.flag == 8 or message.flag == 9 ):
                Final_Text = Final_Text + str(AESDecMSg(message.source,message.payload), 'utf-8')
            else:
                try:
                    Final_Text = Final_Text + str(message.payload, 'utf-8')
                except UnicodeDecodeError:
                    Final_Text = Final_Text + str(message.payload)
            if message.flag == 1:
                break
        return Final_Text
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        return "---Messages Couldnt be Concatenated!!---"


def recv_flag(the_socket, buf, timeout=2):
    try:
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
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        pass


def Send_File(socket, addr, path):
    try:
        variable_list = [socket, addr, path]
        logging.debug("File Sending Protocol initialized with: "+ Prepare_Debugstring(variable_list))
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
        logging.error(path + " is not valid.")
        pass
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        logging.error("File Couldn't be Send.")
        pass

def WritePacketsToFile(Packets):
    try:
        logging.debug("Writing packets to File...")
        f = open("ChatAppFile", 'wb')
        for packets in Packets:
            f.write(packets.payload)
        f.close()
        logging.info("File Downloaded!")
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        logging.error("File Couldn't be Received.")
        pass



def Update_Progress(progress):
    try:
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
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        pass


def Validate_IPV4(address):
    logging.info("Validating IPV4 address...")
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
    logging.info("Validating IPV6 address...")
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def Send_RoutingTable(socket, addr, receiver_UUID):
    try:
        variable_list = [socket, addr, receiver_UUID]
        logging.debug("Sending Routing Table Protocol initialized with: " + Prepare_Debugstring(variable_list))
        message = PrepareAuthMessage(None, receiver_UUID, 0x20)
        Send_Message(socket, addr, Config.RoutingTable, message)
        logging.info("Routing Table Sent!")
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        pass



def Get_RoutingTable(data, sender_UUID):
    try:
        variable_list = [eval(data), sender_UUID]
        logging.debug("Receiving Routing Table Protocol initialized with: " + Prepare_Debugstring(variable_list))
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
        logging.debug(Config.RoutingTable)
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        logging.info("Routing Table Couldn't be Received...")
        pass





def Get_AuthMessage(UDPSocket,UDPaddr,remote_addr,msg, sender_UUID):
    try:
        decrypted_sign = gpg.decrypt(message=str(msg), passphrase=Config.passphrase)
        decrypted_data = gpg.decrypt(message=decrypted_sign.data, passphrase=Config.passphrase)
        if decrypted_data.ok:
            Session_Key_Entry = {'Key': decrypted_data.data, 'UUID': sender_UUID}
            Config.SessionKeyTable.append(dict(Session_Key_Entry))
            logging.debug(Config.SessionKeyTable)
            Send_ACKMessage(UDPSocket, remote_addr, sender_UUID)
        else:
            logging.warning("Data Couldn't be Decrypted...")
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        logging.info("Auth Message Couldn't be received!...")
        pass
    finally:
        logging.info("Waiting Token Changed to 0")
        Config.Tokens[0]["WaitForListening"] = 0;
        Config.Tokens[0]["WaitReason"] = None;

def Send_ACKMessage(UDPSocket, remote_addr,sender_UUID):
    try:
        variable_list = [UDPSocket, remote_addr,sender_UUID]
        logging.debug("ACK Message Sending Protocol Initialized with: " + Prepare_Debugstring(variable_list))
        ackmessage = PrepareACKMessage(sender_UUID)
        Send_Message(UDPSocket, remote_addr, None, ackmessage)
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        logging.info("ACK Message Couldn't be Send!...")
        pass

def Send_AUTHSUCCEEDEDMessage(UDPSocket, remote_addr,sender_UUID):
    try:
        variable_list = [UDPSocket, remote_addr, sender_UUID]
        logging.debug("ACK Message Sending Protocol Initialized with: " + Prepare_Debugstring(variable_list))
        ackmessage = PrepareACKMessage(sender_UUID)
        Send_Message(UDPSocket, remote_addr, None, ackmessage)
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        logging.info("AUTHSUCCEEDED Message Couldn't be Send!...")
        pass

def Add_KeyIDTable(remote_UUID):
    try:
        logging.debug(remote_UUID + "will be added to KeyID Table...")
        if SearchDictionary(Config.KeyIDs, remote_UUID, 'UUID') is None:
            username = input('Enter Username for this IP>>')
            keyID_newline = {'User': username, 'UUID': remote_UUID}
            Config.KeyIDs.append(dict(keyID_newline))
            logging.debug(str(keyID_newline) + " has been added to KeyID Table...")
        else:
            logging.warning('This UUID Already Exists')
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        pass

def Help():
    try:
        print("Ready to Chat! Type #HELP for manual.")
        print("To Initialize Neighboring => #ADDNEIGH")
        print("To Initialize Routing Table Exchange => #ROUT")
        print("To send file => #FILE <path> ")
        print("To send text message, enter the desired text directly.")

    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        pass


def Print_Table(table):
    try:
        for line in enumerate(table):
            print(line)
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        logging.info("Couldn't Print Table!...")
        pass

def Get_RecipientInfoFromNick(NickName, SocketData):
    try:
        variable_list = [NickName, SocketData]
        logging.debug("Checking Info on Typed User: " + Prepare_Debugstring(variable_list))
        KeyID_Entry = SearchDictionary(Config.KeyIDs, NickName, 'User')
        Neighbor_Entry = ''
        isNode = False
        if KeyID_Entry:
            SessionKey_Entry = SearchDictionary(Config.SessionKeyTable, KeyID_Entry['UUID'], 'UUID' )
            if SessionKey_Entry:
                Neighbor_Entry = SearchDictionary(Config.NeighborTable, KeyID_Entry['UUID'], 'UUID')
                isNode = True;
            else:
                logging.info('SessionKey Entry cannot be Found...Initialising AUTH Protocol...')
                Set_Passphrase()
                Neighbor_entry = SearchDictionary(Config.NeighborTable,KeyID_Entry['UUID'],'UUID' )
                Send_AuthMessage(SocketData, Neighbor_entry['Socket'], Neighbor_entry['UUID'])
                Config.Tokens[0]["WaitForListening"] = 1;
                Config.Tokens[0]["WaitReason"] = "AUTH Message sent. Waiting for ACK.";
                logging.info('AUTH Sent to: ' + Neighbor_entry['UUID'])
                isNode = False
        return Neighbor_Entry, isNode
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        return {}, False





def Set_Passphrase():
    try:
        logging.info("Setting Passphrase.. This Procedure is one time only...")
        if Config.passphrase is None:
            Config.passphrase = input('Enter the PassPhrase>>')
            logging.info("PassPhrase is set!")
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.error(repr(traceback.format_exception(exc_type, exc_value,
                                                      exc_traceback)))
        print("Error Occured.. Please Try Again.")
        Set_Passphrase()

# MessageType Enum class
class MessageTypes(Enum):
    Data = 0x01
    Control = 0x02
    Auth = 0x04

