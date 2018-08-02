#!/usr/bin/env python

from pyDes import des
import hashlib
import time
import socket
import sys
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import zlib
import base64

#rude_message = "Packet traces are rude"

PORT = int(sys.argv[1])

def decrypt_blob(encrypted_blob, private_key):

    #Import the Private Key and use for decryption using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    #Base 64 decode the data
    encrypted_blob = base64.b64decode(encrypted_blob)

    #In determining the chunk size, determine the private key length used in bytes.
    #The data will be in decrypted in chunks
    chunk_size = 512
    offset = 0
    decrypted = ""

    #keep loop going as long as we have chunks to decrypt
    while offset < len(encrypted_blob):
        #The chunk
        chunk = encrypted_blob[offset: offset + chunk_size]

        #Append the decrypted chunk to the overall decrypted file
        decrypted += rsakey.decrypt(chunk)

        #Increase the offset by chunk size
        offset += chunk_size

    #return the decompressed decrypted data
    return zlib.decompress(decrypted)


def encrypt_blob(blob, public_key):
    #Import the Public Key and use for encryption using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    #compress the data first
    blob = zlib.compress(blob)

    #In determining the chunk size, determine the private key length used in bytes
    #and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
    #in chunks
    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted =  ""

    while not end_loop:
        #The chunk
        chunk = blob[offset:offset + chunk_size]

        #If the data chunk is less then the chunk size, then we need to add
        #padding with " ". This indicates the we reached the end of the file
        #so we end loop here
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += " " * (chunk_size - len(chunk))

        #Append the encrypted chunk to the overall encrypted file
        encrypted += rsa_key.encrypt(chunk)

        #Increase the offset by chunk size
        offset += chunk_size

    #return encrypted # Return RAW

    #Base 64 encode the encrypted file
    return base64.b64encode(encrypted)


print "Importing keys..............."

fd = open("key.pem", "rb")
PRIVKEY = fd.read()
fd.close()

fd = open("pub_key.pem", "rb")
PUBKEY = fd.read()
fd.close()

print "COMPLETE"
#print "PRIVKEY: " + str(key.exportKey("PEM"))
#print "PUBKEY:  " + str(key.publickey().exportKey("PEM"))

#PRIVKEY = key.exportKey("PEM")
#PUBKEY = key.publickey().exportKey("PEM")

PASSWORD = ""

class _stdout():
    def __init__(self, sock_resp):
        self.sock_resp = sock_resp

    def write(self, data):
#        sys.stderr.write("SENDING:")
#        sys.stderr.write(repr(data))
#        sys.stderr.write("\n")
#        self.sock_resp.send(rude_message + data.encode('ascii'))
	self.sock_resp.send(data.encode('ascii'))

class _stdin():
    def __init__(self, sock_resp):
        self.sock_resp = sock_resp

    def readline(self):
        DATA = self.sock_resp.recv(1024).decode()
#        sys.stderr.write("RECIEVING:")
#        sys.stderr.write(repr(DATA))
#        sys.stderr.write("\n")
#        return DATA[len(rude_message):(len(DATA)-len(rude_message))]
	return DATA

    def read(self):
        DATA = self.sock_resp.recv(1024).decode()
#        sys.stderr.write("RECIEVING:")
#        sys.stderr.write(repr(DATA))
#        sys.stderr.write("\n")
#        return DATA[len(rude_message):(len(DATA)-len(rude_message))]
	return DATA


class _stdout_secure():
    def __init__(self, sock_resp):
        self.sock_resp = sock_resp

    def write(self, data):
        key = PASSWORD
        text = data
        d = des()
        data = d.encrypt(key,text)
        sys.stderr.write("[SECURE] SENDING:")
        sys.stderr.write(repr(data))
        sys.stderr.write("\n")
 #       self.sock_resp.send(rude_message + data)
        self.sock_resp.send(data)

class _stdin_secure():
    def __init__(self, sock_resp):
        self.sock_resp = sock_resp

    def readline(self):
        DATA = self.sock_resp.recv(1024).encode('ascii')

        key = PASSWORD
        text = DATA
        d = des()
        DATA = d.decrypt(key,text)

        return DATA

    def read(self):
        DATA = self.sock_resp.recv(1024).decode()

        key = PASSWORD
        text = DATA
        d = des()
        DATA = d.decrypt(key,text)

        return DATA


STDOUT_ORG = sys.stdout
STDIN_ORG = sys.stdin

HOST= raw_input("HOST: ")


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print "Connecting to "+ HOST+ ":"+ str(PORT)

try:
    s.connect((HOST, PORT))
except socket.error as msg:
    print('Bind failed. Error Code : ' , str(msg[0]) , ' Message ' , msg[1])
    sys.exit()


sys.stderr = sys.stdout
sys.stdout = _stdout(s)
#sys.stdin = _stdin(s)

s.recv(24)
sys.stderr.write("AUTH: ")
PASSWORD = raw_input()
s.sendall(hashlib.sha512(PASSWORD).hexdigest())

while 1:
   sys.stderr.write(s.recv(4096)+"\n==>")
   STR = raw_input()
   sys.stdout.write(str(encrypt_blob(STR,PUBKEY)))
#   sys.stderr.write(s.recv(4096))

#    s.shutdown(socket.SHUT_WR)
#    s.close()
#    sys.stdout = STDOUT_ORG

#s.close()


