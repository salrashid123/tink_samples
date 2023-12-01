package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"google.golang.org/protobuf/proto"
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

	buf := new(bytes.Buffer)
	wr := keyset.NewJSONWriter(buf)
	if err := wr.Write(ksw.Keyset); err != nil {
		log.Printf("Could not write encrypted keyhandle %v", err)
		return
	}
	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)

	}
	log.Println("Tink Keyset:\n", string(prettyJSON.Bytes()))

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
