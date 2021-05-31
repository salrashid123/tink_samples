### Import and use an external HMAC Key as KMS EncryptedKeySet




```log
$ go run external_hmac/main.go 
2021/05/31 09:39:26 1.  Test HMAC/Verify secret using crypto/hmac
2021/05/31 09:39:26     HMAC: fFBQbZk7ShDlrmszypUb8rjIrDmeCjQCa7CsRpvqPeI=
2021/05/31 09:39:26     MAC Verified
2021/05/31 09:39:26 2.  Create tink suble.HMAC using secret
2021/05/31 09:39:26     Tink HmacKey Key: Y2hhbmdlIHRoaXMgcGFzc3dvcmQgdG8gYSBzZWNyZXQ=
2021/05/31 09:39:26     Serialized Tink Keyset: CMKIrNYJEmgKXAoudHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuSG1hY0tleRIoEgQIAxAgGiBjaGFuZ2UgdGhpcyBwYXNzd29yZCB0byBhIHNlY3JldBgBEAEYwois1gkgAw==
2021/05/31 09:39:27     Serialized EncryptedKeyset: EsMBCiUAmT+VVbtrbaE1D0w9tCeEtPKtB8D0cckUqzzHlnUx974KDIQHEpkBACsKZVK1AN1NRDVI5gSWIRtrAR9345KvCcTr7KJTNxOsjLARdgGC3qrSVXTz1n5+WlhTYD1JOey2Pleu6S0s7rnsCJ8b9DYSEzHcJwccUqBYVvn2SkKFESvCFOJRb4+alqDbqlmRG85a3XoRAbxHkHYeFcSD72D7++r/F+nguEFABQuFqWnqytrZqDe8QiBpkpT7X1Pecv4PGkIIwois1gkSOgoudHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuSG1hY0tleRABGMKIrNYJIAM=
2021/05/31 09:39:27     Tink Keyset:
 {
	"encryptedKeyset": "CiUAmT+VVbtrbaE1D0w9tCeEtPKtB8D0cckUqzzHlnUx974KDIQHEpkBACsKZVK1AN1NRDVI5gSWIRtrAR9345KvCcTr7KJTNxOsjLARdgGC3qrSVXTz1n5+WlhTYD1JOey2Pleu6S0s7rnsCJ8b9DYSEzHcJwccUqBYVvn2SkKFESvCFOJRb4+alqDbqlmRG85a3XoRAbxHkHYeFcSD72D7++r/F+nguEFABQuFqWnqytrZqDe8QiBpkpT7X1Pecv4P",
	"keysetInfo": {
		"primaryKeyId": 2596996162,
		"keyInfo": [
			{
				"typeUrl": "type.googleapis.com/google.crypto.tink.HmacKey",
				"status": "ENABLED",
				"keyId": 2596996162,
				"outputPrefixType": "RAW"
			}
		]
	}
}
2021/05/31 09:39:27 3. Constructing MAC with TINK
2021/05/31 09:39:27     MAC fFBQbZk7ShDlrmszypUb8rjIrDmeCjQCa7CsRpvqPeI
2021/05/31 09:39:27     MAC Verified
2021/05/31 09:39:27 4. Verify TINK MAC with crypto/hmac
2021/05/31 09:39:27     MAC Verified
```