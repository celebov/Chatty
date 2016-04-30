from ctypes import *
from ctypes import *
from struct import *
import binascii

class message(Structure):
    _pack_ = 1
    _fields_ = [
        ("version", c_byte ),
        ("source", c_char * 8),
        ("destination", c_char * 8),
        ("type", c_byte ),
        ("flag", c_byte ),
        ("hop_count", c_byte ),
        ("length", c_byte),
        ("payload", c_char * 79)
    ]

def dump(obj):
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


# temp = U.message()
# temp.version = 1
# temp.source = "A1DB1329"
# temp.destination = "A1DB1329"
# temp.type = 4
# temp.flag = 255
# temp.hop_count = 15