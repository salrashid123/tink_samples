// for creating keys https://cloud.google.com/bigquery/docs/reference/standard-sql/aead-encryption-concepts#keysets
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/google/tink/go/aead"

	"github.com/google/tink/go/keyset"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"
)

const (
	keyURI = "gcp-kms://projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1"
)

func main() {
	// https://github.com/google/tink/issues/509

	gcpClient, err := gcpkms.NewClient("gcp-kms://")
	if err != nil {
		panic(err)
	}
	registry.RegisterKMSClient(gcpClient)

	dek := aead.AES256GCMKeyTemplate()
	kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))
	if err != nil {
		log.Fatal(err)
	}

	a, err := aead.New(kh)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("this message needs to be encrypted")
	aad := []byte("this data needs to be authenticated, but not encrypted")
	ct, err := a.Encrypt(msg, aad)
	if err != nil {
		log.Fatal(err)
	}

	pt, err := a.Decrypt(ct, aad)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Ciphertext: %s\n", base64.StdEncoding.EncodeToString(ct))
	log.Printf("Original  plaintext: %s\n", msg)
	log.Printf("Decrypted Plaintext: %s\n", pt)

	// ******************

	// in the following we're just re-wrapping the keyset with KMS again
	//  Note, the ciphertext pt already contains the key encoded in it

	memKeyset := &keyset.MemReaderWriter{}
	if err := kh.Write(memKeyset, a); err != nil {
		log.Printf("Could not serialize KeyHandle  %v", err)
		return
	}
	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	if err := w.WriteEncrypted(memKeyset.EncryptedKeyset); err != nil {
		log.Printf("Could not write encrypted keyhandle %v", err)
		return
	}

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)

	}
	log.Println("Tink Keyset:\n", string(prettyJSON.Bytes()))

	//  reread

	buf2 := bytes.NewBuffer(prettyJSON.Bytes())
	r := keyset.NewJSONReader(buf2)

	kh2, err := keyset.Read(r, a)
	if err != nil {
		log.Printf("Could not create TINK keyHandle %v", err)
		return
	}

	b, err := aead.New(kh2)
	if err != nil {
		log.Fatal(err)
	}

	pt2, err := b.Decrypt(ct, aad)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Decrypted Plaintext: %s\n", pt2)
}
