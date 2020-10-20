
# Simple Examples of using Tink Encryption library in Golang

Just a scratchpad for [Tink](https://github.com/google/tink) examples i used (and will use again).

This is just for my reference...the official examples are [here](https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md)


- `client/`:  Encrypt/Decrypt string using the b64 encoded form of the keyset protobouf of `aead.AES256GCMKeyTemplate()` type.

- `client_kms`: Encrypt/Decrypt using Envelope encryption where the KEK is is KMS
   `keyURI = "gcp-kms://projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1"`

- `client_stream`: Encrypt/Decrypt using AEAD Stream


- `client_stream_gcs`: Encrypt/Decrypt using AEAD Stream.  Source->Destination are objects in GCS
   GCS(stream) -> Tink(stream encrypt) -> GCS(stream)


- `python_tink`: Simple AEAD for python



