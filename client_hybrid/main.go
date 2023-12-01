package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

const ()

func main() {

	khPriv, err := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	khPub, err := khPriv.Public()
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	err = insecurecleartextkeyset.Write(khPub, w)
	if err != nil {
		log.Fatal(err)
	}

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)

	}
	log.Println("Tink Keyset:\n", string(prettyJSON.Bytes()))

	// TODO: share the public keyset with the sender.

	enc, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("this data needs to be encrypted")
	encryptionContext := []byte("encryption context")
	ct, err := enc.Encrypt(msg, encryptionContext)
	if err != nil {
		log.Fatal(err)
	}

	dec, err := hybrid.NewHybridDecrypt(khPriv)
	if err != nil {
		log.Fatal(err)
	}

	pt, err := dec.Decrypt(ct, encryptionContext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Ciphertext: %s\n", base64.StdEncoding.EncodeToString(ct))
	fmt.Printf("Original  plaintext: %s\n", msg)
	fmt.Printf("Decrypted Plaintext: %s\n", pt)
}
