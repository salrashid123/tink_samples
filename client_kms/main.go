package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"
)

const (
	keyURI = "gcp-kms://projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1"
)

func main() {

	// Fetch the master key from a KMS.
	gcpClient, err := gcpkms.NewClient("gcp-kms://")
	if err != nil {
		log.Fatal(err)
	}

	registry.RegisterKMSClient(gcpClient)

	dek := aead.AES128CTRHMACSHA256KeyTemplate()
	kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))
	if err != nil {
		log.Fatal(err)
	}

	a, err := aead.New(kh)
	if err != nil {
		log.Fatal(err)
	}

	ct, err := a.Encrypt([]byte("secret message"), []byte("associated data"))
	if err != nil {
		log.Fatal(err)
	}

	pt, err := a.Decrypt(ct, []byte("associated data"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Cipher text: %s\nPlain text: %s\n", base64.StdEncoding.EncodeToString(ct), pt)

}
