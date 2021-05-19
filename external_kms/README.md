### Import and use an external AES GCM Key with KMS Backed EncryptedKeyset

1. Create an AES key
2. Test Encrypt/Decrypt some text using plain go AESGCM encryption
3. Embed that rawkey as a tink AesGcmKey and serialize it
4. Construct a KeySet and place the serialized key into that
5. Serialize the whole KeySet
6. Encrypt the serialized KeySet (from step 3) with KMS
7. Create  an EncryptedKeyset and embed the encrypted KeySet into that
8. Print the Encrypted Keyset
9. Read the json keyset bytes using the KMS backend
10. Construct AEAD
11. Encrypt and decrypt some that data using 
12. Add TINK output prefix to plain ciphertext generated in step 2  
13. Use Tink to decrypt cipherText created manually (from step 12)



---

#### References

* [Tink Issue#353](https://github.com/google/tink/issues/353)
* [tink aes_gcm.go](https://github.com/google/tink/blob/master/go/aead/subtle/aes_gcm.go)
* [Tink subtle constants](https://pkg.go.dev/github.com/mightyguava/tink/go/subtle/aead#pkg-constants)


---

```log
$ go run external_kms/main.go 
2021/05/19 09:05:39 Tink AESGCM Key: 6368616e676520746869732070617373776f726420746f206120736563726574
2021/05/19 09:05:39    Serialized Keyset: CMKIrNYJEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIGNoYW5nZSB0aGlzIHBhc3N3b3JkIHRvIGEgc2VjcmV0GAEQARjCiKzWCSAB
2021/05/19 09:05:39   KMS Encrypted keySet: Er8BCiUAmT+VVWWH9W64MaRop1/KS9Tot+MYFnSvjVg+qRriZ7tF8IH7EpUBACsKZVLRjJ7Wqq6X6OKJinHM4ajcbmEP7aNVmcw2bp4MWV0PrqX6EIYuV0aY5XpYYT/LPidX+/3vx+CY0hxB9m7I1qdHMZrGF5hHKsAgQulGo7PBaZiXh6qhsIEQ0PKwJUfYWk24W38c5fPGt3LrzKc1TlTT+ImW6svoiptfIkR254UIejPhZ/LcB5rjojJPhKSVSZ0aRAjCiKzWCRI8CjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNHY21LZXkQARjCiKzWCSAB
2021/05/19 09:05:39 Tink Keyset:
 {
	"encryptedKeyset": "CiUAmT+VVWWH9W64MaRop1/KS9Tot+MYFnSvjVg+qRriZ7tF8IH7EpUBACsKZVLRjJ7Wqq6X6OKJinHM4ajcbmEP7aNVmcw2bp4MWV0PrqX6EIYuV0aY5XpYYT/LPidX+/3vx+CY0hxB9m7I1qdHMZrGF5hHKsAgQulGo7PBaZiXh6qhsIEQ0PKwJUfYWk24W38c5fPGt3LrzKc1TlTT+ImW6svoiptfIkR254UIejPhZ/LcB5rjojJPhKSVSZ0=",
	"keysetInfo": {
		"primaryKeyId": 2596996162,
		"keyInfo": [
			{
				"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
				"status": "ENABLED",
				"keyId": 2596996162,
				"outputPrefixType": "TINK"
			}
		]
	}
}
2021/05/19 09:05:39 Encrypted AZrLBEIP8A/uWIi0yOxA2T9Iw4xS1QUIk3iTtyAT3dyErDGIigut82EcNPNJxnDGjEXSPkYDqlhnLouCbfmUaQ==
2021/05/19 09:05:39 Cipher text: AZrLBEIP8A/uWIi0yOxA2T9Iw4xS1QUIk3iTtyAT3dyErDGIigut82EcNPNJxnDGjEXSPkYDqlhnLouCbfmUaQ
Plain text: this data needs to be encrypted

```