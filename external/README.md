### Import and use an external AES GCM Key with Tink

1. Create AES GCM 128 key
2. Encrypt plainText using `crypto.aes`
3. Decrypt cipherText using `cyypto.aes`
4. Use generated key in `1` to create tink AESGCM instance ([subtle.AESGCM](https://pkg.go.dev/github.com/google/tink/go/subtle))
5. Decrypt cipherText using `subtle.AESGCM`
6. Construct and serialize `AesGcmKey` using `subtle.AESGCM` key
7. Construct tink [KeySet](https://pkg.go.dev/github.com/google/tink/go/keyset) using serialized `AesGcmKey`
8. Load the KeySet
9. Create [tink.AEAD](https://pkg.go.dev/github.com/google/tink/go/aead) using KeySet
10. Encrypt plainText using Tink
11. Decrypt cipherText from step `10` using Tink
12. Prepare cipherText from step `3` for Tink cipher prefix
13. Decrypt prefixed cipher in step `12` with tink.AEAD
14. Extract and print raw Encryption Key from keySet

---

#### References

* [Tink Issue#353](https://github.com/google/tink/issues/353)
* [tink aes_gcm.go](https://github.com/google/tink/blob/master/go/aead/subtle/aes_gcm.go)
* [Tink subtle constants](https://pkg.go.dev/github.com/mightyguava/tink/go/subtle/aead#pkg-constants)


---

```log
$ go run main.go 
2021/05/04 08:54:14 Raw Key: 6368616e676520746869732070617373776f726420746f206120736563726574
2021/05/04 08:54:14 crypto.cipher.AEAD.Seal() 5SlJgSaRHbtqsR1UrRBdbp98qhh5yZBj5067ZE1Y6IrQ6VU=
2021/05/04 08:54:14 crypto.cipher.AEAD.Unseal() fooobar
2021/05/04 08:54:14 Tink subtle decrypted fooobar
2021/05/04 08:54:14 Recreated Tink RawKey: 6368616e676520746869732070617373776f726420746f206120736563726574
2021/05/04 08:54:14 Tink Keyset:
 {
	"primaryKeyId": 2596996162,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
				"value": "GiBjaGFuZ2UgdGhpcyBwYXNzd29yZCB0byBhIHNlY3JldA==",
				"keyMaterialType": "SYMMETRIC"
			},
			"status": "ENABLED",
			"keyId": 2596996162,
			"outputPrefixType": "TINK"
		}
	]
}
2021/05/04 08:54:14 Tink Encrypted: AZrLBEKBrDgCeQJYH8OIVrJewz8qAptvFaqq6Uhgq4E43NWwxAj9sA==
2021/05/04 08:54:14 Tink Decrypted: fooobar
2021/05/04 08:54:14 Plain text: fooobar
2021/05/04 08:54:14 Recrated Raw Key: 6368616e676520746869732070617373776f726420746f206120736563726574
```