// for creating keys https://cloud.google.com/bigquery/docs/reference/standard-sql/aead-encryption-concepts#keysets
package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/google/tink/go/aead"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"

	"github.com/golang/protobuf/jsonpb"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"
)

func main() {

	keyURI := "gcp-kms://projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1"

	g, err := gcpkms.NewClient(keyURI)
	if err != nil {
		panic(err)
	}
	registry.RegisterKMSClient(g)

	dek := aead.AES128CTRHMACSHA256KeyTemplate()

	khPriv, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))

	//khPriv, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		panic(err)
	}

	ksw := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(khPriv, ksw); err != nil {
		panic(err)
	}

	ks, err := proto.Marshal(ksw.Keyset)
	if err != nil {
		panic(err)
	}

	log.Printf("%s", base64.RawStdEncoding.EncodeToString(ks))

	m := jsonpb.Marshaler{}
	result, err := m.MarshalToString(ksw.Keyset)
	if err != nil {
		panic(err)
	}

	log.Printf("%s\n", result)

	a, err := aead.New(khPriv)
	if err != nil {
		log.Fatal(err)
	}

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
