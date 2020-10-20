#!/usr/bin/python


import base64
import io
import tink
from tink import aead
from tink import tink_config
from tink import mac
from tink.proto import tink_pb2
from tink.proto import common_pb2
from tink import core

from tink import cleartext_keyset_handle

tink_config.register()
aead.register()
mac.register()


class AESCipher(object):

    def __init__(self, encoded_key):
      tink_config.register()
      aead.register()

      if (encoded_key==None):
        self.keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)
      else:
        reader = tink.BinaryKeysetReader(base64.b64decode(encoded_key))
        self.keyset_handle = cleartext_keyset_handle.read(reader)
      self.key=self.keyset_handle.keyset_info()
      self.aead_primitive = self.keyset_handle.primitive(aead.Aead)

    def printKey(self):
      print(self.keyset_handle.keyset_info())

    def getKey(self):
      iostream = io.BytesIO()
      writer = tink.BinaryKeysetWriter(iostream)
      writer.write(self.keyset_handle._keyset)
      encoded_key = base64.b64encode(iostream.getvalue()).decode('utf-8')
      return base64.b64encode(iostream.getvalue()).decode('utf-8')
      

    def encrypt(self, plaintext, associated_data):
      ciphertext = self.aead_primitive.encrypt(plaintext, associated_data.encode('utf-8'))
      base64_bytes = base64.b64encode(ciphertext)
      return (base64_bytes.decode('utf-8'))  

    def decrypt(self, ciphertext, associated_data):
      plaintext = self.aead_primitive.decrypt(base64.b64decode(ciphertext), associated_data.encode('utf-8'))
      return(plaintext.decode('utf-8'))

class HMACFunctions(object):

    def __init__(self, encoded_key=None):
      if encoded_key == None:
        self.keyset_handle = tink.new_keyset_handle(mac.mac_key_templates.HMAC_SHA256_256BITTAG)
      else:
        reader = tink.BinaryKeysetReader(base64.b64decode(encoded_key.encode('utf_8')))
        self.keyset_handle = cleartext_keyset_handle.read(reader)
      self.mac = self.keyset_handle.primitive(mac.Mac)

    def printKey(self):
      print(self.keyset_handle.keyset_info())

    def getKey(self):
      iostream = io.BytesIO()
      writer = tink.BinaryKeysetWriter(iostream)
      writer.write(self.keyset_handle._keyset)
      encoded_key = base64.b64encode(iostream.getvalue()).decode('utf-8')
      return base64.b64encode(iostream.getvalue()).decode('utf-8')

    def hash(self, msg):
      tag = self.mac.compute_mac(msg)
      return base64.b64encode(tag)

    def verify(self,data, signature):
      try:
        self.mac.verify_mac(signature, data)
        return True
      except tink.TinkError as e:
        return False
 

c = AESCipher(encoded_key=None)
k = c.getKey()
c.printKey()
print(k)
k = 'CNSKwpcCEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIGLSL2lQeHvR5byaWT7geg8/utkX0NAvbE4b+dPx53hoGAEQARjUisKXAiAB'
cc = AESCipher(k)
enc=cc.encrypt("foo".encode('utf-8'),"none")
print(enc)
dec = cc.decrypt(enc,"none")
print(dec)

h = HMACFunctions(encoded_key=None)
k = h.getKey()
h.printKey()
print(k)

h = HMACFunctions(encoded_key=k)
dd = "dsfas"
hashed=h.hash(dd.encode('utf-8'))
print(base64.b64encode(hashed).decode('utf-8'))

print(h.verify(dd.encode('utf-8'),base64.b64decode(hashed)))

