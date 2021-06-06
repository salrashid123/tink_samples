package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
)

func main() {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyWithoutPrefixTemplate()) // Other key templates can also be used.
	if err != nil {
		log.Fatal(err)
	}

	// TODO: save the private keyset to a safe location. DO NOT hardcode it in source code.
	// Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
	// See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

	s, err := signature.NewSigner(kh)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("this data needs to be signed")
	sig, err := s.Sign(msg)
	if err != nil {
		log.Fatal(err)
	}

	pubkh, err := kh.Public()
	if err != nil {
		log.Fatal(err)
	}

	// TODO: share the public with the verifier.
	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	err = insecurecleartextkeyset.Write(pubkh, w)
	if err != nil {
		log.Fatal(err)
	}

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)

	}
	log.Println("Tink Keyset:\n", string(prettyJSON.Bytes()))

	v, err := signature.NewVerifier(pubkh)
	if err != nil {
		log.Fatal(err)
	}

	if err := v.Verify(sig, msg); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Message: %s\n", msg)
	fmt.Printf("Signature: %s\n", base64.StdEncoding.EncodeToString(sig))
}
