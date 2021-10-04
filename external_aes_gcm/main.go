package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/rand"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/random"
)

const (
	// AESGCMIVSize is the only IV size that TINK supports.
	// https://pkg.go.dev/github.com/mightyguava/tink/go/subtle/aead#pkg-constants
	AESGCMIVSize = 12

	// https://github.com/google/tink/blob/master/go/core/cryptofmt/cryptofmt.go#L68
	// NonRawPrefixSize is the prefix size of Tink and Legacy key types.
	NonRawPrefixSize = 5

	// TinkPrefixSize is the prefix size of Tink key types.
	// The prefix starts with \x01 and followed by a 4-byte key id.
	TinkPrefixSize = NonRawPrefixSize
	// TinkStartByte is the first byte of the prefix of Tink key types.
	TinkStartByte = byte(1)

	// RawPrefixSize is the prefix size of Raw key types.
	// Raw prefix is empty.
	RawPrefixSize = 0
	// RawPrefix is the empty prefix of Raw key types.
	RawPrefix = ""
)

func main() {

	// 1. AES GCM Key
	secret := "change this password to a secret"
	plainText := "Greed"

	rawKey := []byte(secret)
	pt := []byte(plainText)

	log.Printf("Raw Key: %s", hex.EncodeToString(rawKey))

	// 2,3 Test encryption/decryption with crypto.cipher
	aesCipher, err := aes.NewCipher(rawKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	rawAES, err := cipher.NewGCM(aesCipher)
	if err != nil {
		log.Fatal(err.Error())
	}
	iv := random.GetRandomBytes(AESGCMIVSize)
	ciphertext := rawAES.Seal(nil, iv, pt, []byte(""))
	ciphertext = append(iv, ciphertext...)

	log.Printf("crypto.cipher.AEAD.Seal() %s\n", base64.StdEncoding.EncodeToString(ciphertext))

	plaintext, err := rawAES.Open(nil, iv, ciphertext[AESGCMIVSize:], nil)
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Printf("crypto.cipher.AEAD.Unseal() %s\n", plaintext)

	// 4. use the rawKey to generate a tink subtle.AESGCM
	tk, err := subtle.NewAESGCM(rawKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	// 5. decrypt the same ciphertext with `subtle.AESGCM`
	d, err := tk.Decrypt(ciphertext, []byte(""))
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Printf("Tink subtle decrypted %s\n", d)

	// 6. create a tink AesGcmKey and serialize it
	k := &gcmpb.AesGcmKey{
		Version:  0,
		KeyValue: tk.Key,
	}
	log.Printf("Recreated Tink RawKey: %v", hex.EncodeToString(k.GetKeyValue()))

	serialized, err := proto.Marshal(k)
	if err != nil {
		log.Fatal(err)
	}

	// 7.seed the serialized key into a KeySet
	id := rand.Uint32()
	ks := &tinkpb.Keyset{
		PrimaryKeyId: id,
		Key: []*tinkpb.Keyset_Key{{
			KeyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmKey",
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				Value:           serialized,
			},
			KeyId:            id,
			Status:           tinkpb.KeyStatusType_ENABLED,
			OutputPrefixType: tinkpb.OutputPrefixType_TINK,
		},
		},
	}

	// 8. Load the keyset
	nkh, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		log.Fatal(err)
	}

	ksw := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(nkh, ksw); err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	if err := w.Write(ksw.Keyset); err != nil {
		log.Fatalf("Could not write encrypted keyhandle %v", err)

	}

	bbw := new(bytes.Buffer)
	bw := keyset.NewBinaryWriter(bbw)
	if err := bw.Write(ksw.Keyset); err != nil {
		log.Fatalf("Could not write encrypted keyhandle %v", err)

	}

	log.Println("Tink Keyset Encoded: ", base64.StdEncoding.EncodeToString(bbw.Bytes()))

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)

	}

	log.Println("Tink Keyset:\n", prettyJSON.String())

	// 9. create a tink AEAD to encrypt/decrypt
	a, err := aead.New(nkh)
	if err != nil {
		log.Fatal(err)
	}

	// 10. encrypt using Tink.AEAD
	ec, err := a.Encrypt(pt, []byte(""))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Tink Encrypted: %s", base64.StdEncoding.EncodeToString(ec))

	// 11. Decrypt cipher form step10 using Tink.AEAD
	dec, err := a.Decrypt(ec, []byte(""))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Tink Decrypted: %s", string(dec))

	// 12. Prepare CipherText with Tink cipher prefix
	pf := createOutputPrefix(TinkPrefixSize, TinkStartByte, id)
	ciphertext = append([]byte(pf), ciphertext...)

	// 13. Decrypt prefixed cipher in step 12 with tink.AEAD
	dc, err := a.Decrypt(ciphertext, []byte(""))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Plain text: %s\n", string(dc))

	// 14. Extract and print raw Encryption Key from keySet
	for _, kk := range ks.Key {
		kserialized := kk.KeyData.Value
		rk := &gcmpb.AesGcmKey{}

		err := proto.Unmarshal(kserialized, rk)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Recrated Raw Key: %s", hex.EncodeToString(rk.KeyValue))
	}

	// optionally write the keyset to a file
	// later you can list and rotate
	// ./tinkey list-keyset --in-format=json --in keyset.json
	// ./tinkey rotate-keyset --in-format=json --in keyset.json  --key-template AES256_GCM --out-format=json --out keyset2.json

	// buf = new(bytes.Buffer)
	// w = keyset.NewJSONWriter(buf)
	// if err := w.Write(ks); err != nil {
	// 	log.Fatalf("cannot write encrypted keyset: %v", err)
	// }
	// err = ioutil.WriteFile("keyset.json", buf.Bytes(), 0644)
	// if err != nil {
	// 	log.Fatal("cannot write encrypted keyset: %v", err)
	// }

}

// https://github.com/google/tink/blob/master/go/core/cryptofmt/cryptofmt.go#L68
func createOutputPrefix(size int, startByte byte, keyID uint32) string {
	prefix := make([]byte, size)
	prefix[0] = startByte
	binary.BigEndian.PutUint32(prefix[1:], keyID)
	return string(prefix)
}
