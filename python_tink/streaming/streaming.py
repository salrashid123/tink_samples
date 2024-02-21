#!/usr/bin/python


import base64
import io
import tink
from tink import aead
from tink import tink_config
from tink import mac
from tink.proto import tink_pb2
from tink.proto import common_pb2
from tink.integration import gcpkms
from tink import core

from tink import secret_key_access
from tink import streaming_aead
from tink import cleartext_keyset_handle

from typing import BinaryIO
from absl import logging


# https://developers.google.com/tink/encrypt-large-files-or-data-streams

BLOCK_SIZE = 1024 * 1024  # The CLI tool will read/write at most 1 MB at once.

def read_as_blocks(file: BinaryIO):
  while True:
    data = file.read(BLOCK_SIZE)
    # If file was opened in rawIO, EOF is only reached when b'' is returned.
    # pylint: disable=g-explicit-bool-comparison
    if data == b'':
      break
    # pylint: enable=g-explicit-bool-comparison
    yield data
    

tink_config.register()
aead.register()
streaming_aead.register()

key_uri="gcp-kms://projects/core-eso/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1"

gcp_client = gcpkms.GcpKmsClient(key_uri=key_uri,credentials_path="")
gcp_aead = gcp_client.get_aead(key_uri)

## gcm
#keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)

## streaming
keyset_handle = tink.new_keyset_handle(streaming_aead.streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_4KB)
streaming_aead_primitive = keyset_handle.primitive(streaming_aead.StreamingAead)


env_aead = aead.KmsEnvelopeAead(aead.aead_key_templates.AES256_GCM, gcp_aead)

# echo -n "foosdfasfd" > plaintext.txt

with open('plaintext.txt', 'rb') as input_file:
  with open('ciphertext.enc', 'wb') as output_file:
     with streaming_aead_primitive.new_encrypting_stream(output_file, b'aad') as enc_stream:
       for data_block in read_as_blocks(input_file):
        enc_stream.write(data_block)



stream = io.StringIO()
writer = tink.JsonKeysetWriter(stream)    
keyset_handle.write(writer, env_aead)
print(stream.getvalue())


reader = tink.JsonKeysetReader(stream.getvalue())
new_keyset_handle = tink.read_keyset_handle(reader, env_aead)
new_streaming_aead_primitive = new_keyset_handle.primitive(streaming_aead.StreamingAead)


with open('ciphertext.enc', 'rb') as input_file:
  with open('decrypted.txt', 'wb') as output_file:
     with new_streaming_aead_primitive.new_decrypting_stream(input_file, b'aad') as dec_stream:
       for data_block in read_as_blocks(dec_stream):
        output_file.write(data_block)