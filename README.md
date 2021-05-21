
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


- `client_kms`: Encrypt/Decrypt using Envelope encryption where the KEK is in KMS.  THis encrypts the KeySet directly with  a KMS key


```json
 {
	"encryptedKeyset": "CiUAmT+VVR1i/HwmBQVSqROqM5gpO6wUmt+LKRqgY9VzbdG0WfHuEpUBACsKZVL5EieNkMUQTxjy2QhBAOpir5Z5o98sccXf1LlyTE5/dTzvunhdJym62HO0KF1OQi36UZxuxIm1XyknfEVJOKOksgyLfFUY7IWlJsFwGuzOhugsJEXPSYPMj0WOEYDUogH5WDJY7aP4KgubuaDUD7fRNwHZejR7L+Yz4r+9IyIRrY9YiPCF0tDfPAmtUI6ffFY=",
	"keysetInfo": {
		"primaryKeyId": 4015179016,
		"keyInfo": [
			{
				"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
				"status": "ENABLED",
				"keyId": 4015179016,
				"outputPrefixType": "TINK"
			}
		]
	}
}
```

- `client_kms_envelope`: Use `aead.NewKMSEnvelopeAEAD2`

"This primitive implements envelope encryption. In envelope encryption, user generates a data encryption key (DEK) locally, encrypts data with DEK, sends DEK to a KMS to be encrypted (with a key managed by KMS), and stores encrypted DEK with encrypted data; at a later point user can retrieve encrypted data and DEK, use Storky to decrypt DEK, and use decrypted DEK to decrypt the data. The ciphertext structure is as follows: - Length of encrypted DEK: 4 bytes. - Encrypted DEK: variable length that is equal to the value specified in the last 4 bytes. - AEAD payload: variable length."
- from [public final class KmsEnvelopeAead](https://google.github.io/tink/javadoc/tink/1.1.0/com/google/crypto/tink/aead/KmsEnvelopeAead.html)

```json
{
	"encryptedKeyset": "AAAAdAolAJk/lVW4wjkjHJRmJzd9Zg24b4FfSlVwPiB2GFHcqZX+iMkS5RJLACsKZVJXecg1qqeb/a83n+eHPVAqDbK3EgRYY6XL2mAovAeB3Gg1DIZJXQxR74hANxPLNcogFSB2GZ1Qf6QfA97JXo7YCMk691dkpCyOihsmNqEEU27b2ZNGrVVIFpUVI0dyIJcaydL5QMcIpw+Fnk4haEn9FqcbfEBfIia5xG6WuY0e0wucB3Kn5dfJkftDsPVy7zBqMCPPKYuTJ9OKeha1x5x48T2Q9+ERhS7nH1tUcMhiTwJWdg2kCsVY43yBk9xU2EZZN9RhTnM4LCKZf6nkwg==",
	"keysetInfo": {
		"primaryKeyId": 1018928826,
		"keyInfo": [
			{
				"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
				"status": "ENABLED",
				"keyId": 1018928826,
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

- `external_kms`: import and use an external AES GCM Key which is encrypted with KMS `EncryptedKeySet`.