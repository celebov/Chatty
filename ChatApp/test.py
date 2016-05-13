from ctypes import *
from struct import *
from socket import *
from enum import Enum
from os import urandom
from bitstring import *
import binascii,time,sys,scapy.all,gnupg,os

gpg = gnupg.GPG(gnupghome='/home/raziel/.gnupg') #TYPE YOUR OWN .GNUPG PATH
gpg.encoding = 'utf-8'


unencrypted_string = 'Who are you? How did you get in my house?'
fingerprint = gpg.list_keys(True)[0]['fingerprint']

encrypted_data = gpg.encrypt(unencrypted_string, fingerprint, passphrase = 'kaan1234', sign = fingerprint)
decrypted_data = gpg.decrypt(encrypted_data.data, passphrase='kaan1234')
verified = gpg.verify(decrypted_data.data)
print('ok: ', decrypted_data.ok)
print('status: ', decrypted_data.status)
print('stderr: ', decrypted_data.stderr)
print('decrypted string: ', decrypted_data.data)
if verified:
    print("Verified")
else:
    print("Unverified")


