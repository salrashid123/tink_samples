
# Simple Examples of using Tink Encryption library in Golang

Just a scratchpad for [Tink](https://github.com/google/tink) examples i used (and will use again).

This is just for my reference...the official examples are [here](https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md)

some more uses/references w/ Tink:

* [End-to-End Stream encryption with gsutil and TINK](https://github.com/salrashid123/gcs_stream_enc)
* [Message Payload Encryption in Google Cloud Pub/Sub](https://github.com/salrashid123/gcp_pubsub_message_encryption)
* [Message Encryption with Dataflow PubSub Stream Processing](https://github.com/salrashid123/dataflow_pubsub_message_encryption)

---

- `client/`:  Encrypt/Decrypt string using the b64 encoded form of the keyset protobuf of `aead.AES256GCMKeyTemplate()` type.

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

- `client_siv/`:  Encrypt/Decrypt using AES-SIV.

```json
 {
	"primaryKeyId": 2596996162,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/google.crypto.tink.AesSivKey",
				"value": "EkCghIBMZApqHfym2jqG7xPQ+b1T1TVY02Yc+fESzKSGeHJGqUqTgWIaTMBqogbrDv3uM8ho9C9aUHveT/1Wxl6x",
				"keyMaterialType": "SYMMETRIC"
			},
			"status": "ENABLED",
			"keyId": 2596996162,
			"outputPrefixType": "RAW"
		}
	]
}
```


- `client_kms`: Encrypt/Decrypt using Envelope encryption where the KEK is in KMS.  THis encrypts the KeySet directly with  a KMS key

Encrypted (`google.crypto.tink.AesGcmKey`).  Use this to encrypt multiple messages and save the encrypted key outside of the ciphertext storage

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

- `client_kms_envelope`: (`google.crypto.tink.KmsEnvelopeAeadKey`)

  Please see [https://github.com/google/tink/issues/509](https://github.com/google/tink/issues/509)


```json
 {
	"encryptedKeyset": "AWesY4MAAAB0CiUAmT+VVZjhoN5ImPXgebCOA5lut6L30orwoH6EU/27ze03L3urEksAKwplUpHAvT1TalZrFBmaDrsxmwU4pnUJfvQ1yunojPw/0vLQPvyEfvRMy99TKK4HRu4DVMSFiLR7GVMoPUD06/NPzU1o5e+D84E/30lDyYrScC5LgwgYm0q8YI/oy/SBCKju8SLaC8FY6HCOxIykF+YGcgZM5ohjtpYQe0AHWTkDQ5y0IoAbIacdM2iplhxZf8qUGfWF1M2s6WfKIukcn7CCWejxVUa8HrcaQ71N6Wo8B3TNFNA2fnyIld7Pz3KJFTz/jQqFcqhzzaoTCpQr00P0SCmecQRqYnXtMnvmBVWazWRH92FBlpuTvAgr+kREbKCb5lgfsvjhLFrHiHywY2ml2sEtkUGoFjkM5ppdoJxrtaTzhX7o1Okdqnq6yojHa6h7ezxaGjbIAP7Ls+WdaHLdRzOmG3EKLp1YXd/8nNKC/ahj75QaO8+dGXjYjmE4uo8LWF1ghLsC7w==",
	"keysetInfo": {
		"primaryKeyId": 1739350915,
		"keyInfo": [
			{
				"typeUrl": "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey",
				"status": "ENABLED",
				"keyId": 1739350915,
				"outputPrefixType": "TINK"
			}
		]
	}
}
```

- `client_stream`: Encrypt/Decrypt using AEAD Stream

- `client_stream_gcs`: Encrypt/Decrypt using AEAD Stream.  Source->Destination are objects in GCS
   GCS(stream) -> Tink(stream encrypt) -> GCS(stream)

- `client_hybrid`:  Hybrid encryption (eg. encrypt symmetric key with asymmetric key)

```json
 {
	"primaryKeyId": 569289530,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
				"value": "ElwKBAgCEAMSUhJQCjh0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNDdHJIbWFjQWVhZEtleRISCgYKAggQEBASCAoECAMQEBAgGAEYARogK1ZsW8pVVMIPwzhm4thj0ZjSk+lpWluMIsLwm32kF9MiIEpyowCqmanFl7GuppVZVvKflZwDV1yNHhgrCxlwQsoJ",
				"keyMaterialType": "ASYMMETRIC_PUBLIC"
			},
			"status": "ENABLED",
			"keyId": 569289530,
			"outputPrefixType": "TINK"
		}
	]
}
```

- `client_signature`: DigitalSignature using EC

```json
 {
	"primaryKeyId": 2190705367,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
				"value": "EgYIAxACGAIaIEG8Cfq3ZyZEgK/hIEqbzI1y2N5aDZewlFeDgV0Kun5mIiCp+AxtjQxscdvpx4nXoPwtQy5ue+EFATNY2GTF77BV7w==",
				"keyMaterialType": "ASYMMETRIC_PUBLIC"
			},
			"status": "ENABLED",
			"keyId": 2190705367,
			"outputPrefixType": "RAW"
		}
	]
}
```

- `python_tink`: Simple AEAD for python

- `external_aes_gcm`: import and use an external AES GCM Key.

- `external_kms`: import and use an external AES GCM Key which is encrypted with KMS `EncryptedKeySet`.

- `external_hmac`: import and use an external HMAC Key which is encrypted with KMS `EncryptedKeySet`.