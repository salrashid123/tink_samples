// for creating keys https://cloud.google.com/bigquery/docs/reference/standard-sql/aead-encryption-concepts#keysets
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/google/tink/go/aead"

	"github.com/google/tink/go/keyset"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"
)

func main() {

	keyURI := "gcp-kms://projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1"
	kekkeyURI := "gcp-kms://projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key11"

	gcpClient, err := gcpkms.NewClient("gcp-kms://")
	if err != nil {
		panic(err)
	}
	registry.RegisterKMSClient(gcpClient)

	backend, err := gcpClient.GetAEAD(keyURI)
	if err != nil {
		log.Printf("Could not acquire KMS AEAD %v", err)
		return
	}
	masterKey := aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), backend)
	memKeyset := &keyset.MemReaderWriter{}
	dek := aead.AES256GCMKeyTemplate()

	kh1, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(kekkeyURI, dek))
	if err != nil {
		log.Printf("Could not create TINK keyHandle %v", err)
		return
	}

	if err := kh1.Write(memKeyset, masterKey); err != nil {
		log.Printf("Could not serialize KeyHandle  %v", err)
		return
	}

	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	if err := w.WriteEncrypted(memKeyset.EncryptedKeyset); err != nil {
		log.Printf("Could not write encrypted keyhandle %v", err)
		return
	}

	a, err := aead.New(kh1)
	if err != nil {
		log.Fatal(err)
	}

	m := jsonpb.Marshaler{}
	result, err := m.MarshalToString(memKeyset.EncryptedKeyset)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%s\n", result)
	ct, err := a.Encrypt([]byte("this data needs to be encrypted"), []byte("associated data"))
	if err != nil {
		log.Fatal(err)
	}

	pt, err := a.Decrypt(ct, []byte("associated data"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Cipher text: %s\nPlain text: %s\n", base64.RawStdEncoding.EncodeToString(ct), pt)

}
