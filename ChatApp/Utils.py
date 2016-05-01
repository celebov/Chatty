from ctypes import *
from struct import *
from socket import *
import binascii
import scapy.all
import gnupg

gpg = gnupg.GPG(gnupghome='/home/neslic/.gnupg') #TYPE YOUR OWN .GNUPG PATH
gpg.encoding = 'utf-8'

class message(Structure):
    _pack_ = 1
    _fields_ = [
        ("version", c_byte ),
        ("source", c_char * 4),
        ("destination", c_char * 4),
        ("type", c_byte ),
        ("flag", c_byte ),
        ("hop_count", c_byte ),
        ("length", c_byte),
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
    Message.type = 4
    Message.flag = flag
    Message.hop_count = 15
    Message.payload = payload
    packet = Pack(Message)
    return packet;



def ChunkMessages(payload):
    chunklist = Chunk(payload, 87)
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

def sendEncMsg(challenge,rec_id, myKeyid,myPP):
    enc_aut_msg = str(gpg.encrypt(data=challenge, recipients=rec_id, sign=myKeyid, passphrase=myPP))
    return enc_aut_msg

def decMsg(enc_aut_msg,recPP):
    dec_msg = gpg.decrypt(enc_aut_msg,passphrase=recPP)
    return dec_msg