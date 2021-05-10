package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/streamingaead"
)

const (
	plainText = "Some text to encrypt"
)

var ()

func main() {

	// Generate Key

	nkh, err := keyset.NewHandle(streamingaead.AES256GCMHKDF4KBKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	ksw := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(nkh, ksw); err != nil {
		log.Fatal(err)
	}

	//"github.com/golang/protobuf/proto"
	nks, err := proto.Marshal(ksw.Keyset)
	if err != nil {
		log.Fatal(err)
	}

	keySetString := base64.RawStdEncoding.EncodeToString(nks)
	log.Printf("KeySet: %s", keySetString)

	m := jsonpb.Marshaler{}
	result, err := m.MarshalToString(ksw.Keyset)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Unmarshalled Keyset: %s\n", result)

	decoded, err := base64.RawStdEncoding.DecodeString(keySetString)
	if err != nil {
		log.Fatal(err)
	}

	ksr := keyset.NewBinaryReader(bytes.NewBuffer(decoded))
	ks, err := ksr.Read()
	if err != nil {
		log.Fatal(err)
	}

	kh, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		log.Fatal(err)
	}

	a, err := streamingaead.New(kh)
	if err != nil {
		log.Fatalf("Failed to create primitive: %v\n", err)
	}

	bufin := bytes.NewBufferString(plainText)
	bufout := new(bytes.Buffer)
	ad := []byte("")

	// encrypt

	w, err := a.NewEncryptingWriter(bufout, ad)
	if err != nil {
		log.Fatalf("Failed to create encrypt writer: %v", err)
	}
	if _, err := io.Copy(w, bufin); err != nil {
		log.Fatalf("Failed to encrypt data: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("Failed to close encrypt writer: %v", err)
	}

	log.Printf("%s", base64.RawStdEncoding.EncodeToString(bufout.Bytes()))

	// Decrypt

	r, err := a.NewDecryptingReader(bufout, ad)
	if err != nil {
		log.Fatalf("Failed to create decrypt reader: %v", err)
	}
	if _, err := io.Copy(bufin, r); err != nil {
		log.Fatalf("Failed to encrypt data: %v", err)
	}

	log.Printf("%s", bufin.String())

}
