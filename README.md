
# Simple Examples of using Tink Encryption library in Golang

Just a scratchpad for [Tink](https://github.com/google/tink) examples i used (and will use again).

This is just for my reference...the official examples are [here](https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md)

some more uses/references w/ Tink:

* [End-to-End Stream encryption with gsutil and TINK](https://github.com/salrashid123/gcs_stream_enc)
* [Message Payload Encryption in Google Cloud Pub/Sub](https://github.com/salrashid123/gcp_pubsub_message_encryption)
* [Message Encryption with Dataflow PubSub Stream Processing](https://github.com/salrashid123/dataflow_pubsub_message_encryption)

---

- `client/`:  Encrypt/Decrypt string using the b64 encoded form of the keyset protobouf of `aead.AES256GCMKeyTemplate()` type.

```json
{
  "primaryKeyId": 1791408185,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
        "value": "GiAO06HMApt+/970XhBkkbKEqfmtCgKvimBCqih+XVaguA==",
        "keyMaterialType": "SYMMETRIC"
      },
      "status": "ENABLED",
      "keyId": 1791408185,
      "outputPrefixType": "TINK"
    }
  ]
}
```


- `client_kms`: Encrypt/Decrypt using Envelope encryption where the KEK is is KMS
   `keyURI = "gcp-kms://projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1"`

```json
{
  "encryptedKeyset": "AAAAdAolAJk/lVXdo5y9ROHX5ufncWvwifZDiaDiwZ0zNH9YFhj6O++gqRJLANpmZRN7qXa7bBK3AibOIRUm6C2uZ7noefjYdcYgBQKg2AQ2lbrHxjSTb/v1VlcoEKNJ17XyhVQGz38wVJ5YDQKlPObE4EUEBxFg//BM+EofmuEOQzPrE1JMe48xgU+fbCa4SF0ErssQfo/hL+C3D9FNh3ev55dW8uStXtcgXB2yMSj4krEJw1F3HFD6l5lg8POpFV2STIJTqCLQ3l4Q0BhcQlYp3NQUbJHi3DGUqr6O34VCsjjJXIRfmiNY4sSfGwMz+UG6PGtATO4OjQNKZf9G93OmYRl9U8BnUi3d4RcbepMOPQFGG0bO61Vn+vRcBBoA/8v/cTuCXdhWkKRux7GB3qEOsxCIq64tp6OUe9+v7P/xEise6dzpfeBsMY2MxvOi5LSRBKOIaykZGWc22Rm+tPIvZmnGEOMMvkLIiSLphEZN+HBYHLX4TdRKgAOtD5gOzYN7VsbmY1Q=",
  "keysetInfo": {
    "primaryKeyId": 2300296717,
    "keyInfo": [
      {
        "typeUrl": "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey",
        "status": "ENABLED",
        "keyId": 2300296717,
        "outputPrefixType": "TINK"
      }
    ]
  }
}
```

- `client_stream`: Encrypt/Decrypt using AEAD Stream


- `client_stream_gcs`: Encrypt/Decrypt using AEAD Stream.  Source->Destination are objects in GCS
   GCS(stream) -> Tink(stream encrypt) -> GCS(stream)


- `python_tink`: Simple AEAD for python


- `external`: import and use an external AES GCM Key.
