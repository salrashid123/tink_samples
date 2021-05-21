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

	gcpClient, err := gcpkms.NewClient("gcp-kms://")
	if err != nil {
		panic(err)
	}
	registry.RegisterKMSClient(gcpClient)

	kmsAead, err := gcpClient.GetAEAD(keyURI)
	if err != nil {
		log.Printf("Could not acquire KMS AEAD %v", err)
		return
	}
	a := aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), kmsAead)

	// An io.Reader and io.Writer implementation which simply writes to memory.
	memKeyset := &keyset.MemReaderWriter{}

	kh1, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		log.Printf("Could not create TINK keyHandle %v", err)
		return
	}
	// Write encrypts the keyset handle with the master key and writes to the
	// io.Writer implementation (memKeyset).  We recommend you encrypt the keyset
	// handle before persisting it.
	if err := kh1.Write(memKeyset, a); err != nil {
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

	// Create an AEAD off of the keyhandle
	ekh, err := aead.New(kh1)
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)
	}
	ct, err := ekh.Encrypt([]byte("this data needs to be encrypted"), []byte("associated data"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Cipher text: %s", base64.RawStdEncoding.EncodeToString(ct))

	// now reread from scratch

	//  reread the keyset
	buf2 := bytes.NewBuffer(prettyJSON.Bytes())
	r := keyset.NewJSONReader(buf2)

	// decrypt it with the KMS handle
	kh2, err := keyset.Read(r, a)
	if err != nil {
		log.Printf("Could not create TINK keyHandle %v", err)
		return
	}

	// generate the aead

	dkh, err := aead.New(kh2)
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)
	}

	pt, err := dkh.Decrypt(ct, []byte("associated data"))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Plain text: %s\n", pt)

}
