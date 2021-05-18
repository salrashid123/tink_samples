package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

const (
	keySetString = "CLnwmtYGEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIA7TocwCm37/3vReEGSRsoSp+a0KAq+KYEKqKH5dVqC4GAEQARi58JrWBiAB"
)

func main() {

	decoded, err := base64.StdEncoding.DecodeString(keySetString)
	if err != nil {
		log.Fatal(err)
	}

	ksr := keyset.NewBinaryReader(bytes.NewBuffer(decoded))
	ks, err := ksr.Read()
	if err != nil {
		log.Fatal(err)
	}

	handle, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		log.Fatal(err)
	}

	a, err := aead.New(handle)
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	if err := w.Write(ks); err != nil {
		log.Printf("Could not write encrypted keyhandle %v", err)
		return
	}
	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)

	}
	log.Println("Tink Keyset:\n", string(prettyJSON.Bytes()))

	ec, err := a.Encrypt([]byte("foo"), []byte(""))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Encrypted Data: %s", base64.StdEncoding.EncodeToString(ec))

	dc, err := a.Decrypt(ec, []byte(""))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Plain text: %s\n", string(dc))

}
