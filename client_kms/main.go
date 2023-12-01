// for creating keys https://cloud.google.com/bigquery/docs/reference/standard-sql/aead-encryption-concepts#keysets
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/tink-crypto/tink-go/v2/aead"

	"github.com/tink-crypto/tink-go/v2/keyset"

	gcpkms "github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"github.com/tink-crypto/tink-go/v2/core/registry"
)

const (
	keyURI = "gcp-kms://projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1"
)

func main() {

	ctx := context.Background()
	gcpClient, err := gcpkms.NewClientWithOptions(ctx, "gcp-kms://")
	if err != nil {
		panic(err)
	}
	registry.RegisterKMSClient(gcpClient)

	// generate wrapping AEAD w/ KMS
	a, err := gcpClient.GetAEAD(keyURI)
	if err != nil {
		log.Printf("Could not acquire KMS AEAD %v", err)
		return
	}

	memKeyset := &keyset.MemReaderWriter{}

	kh1, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		log.Printf("Could not create TINK keyHandle %v", err)
		return
	}

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
	// decrypt
	pt, err := dkh.Decrypt(ct, []byte("associated data"))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Plain text: %s", pt)

}
