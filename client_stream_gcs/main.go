package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"os"

	"context"

	"cloud.google.com/go/storage"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/streamingaead"
	//"github.com/golang/protobuf/proto"
)

const (
	keySetString = "CLDt99MHEnoKbgo9dHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtSGtkZlN0cmVhbWluZ0tleRIrEgcIgCAQIBgDGiAKuLgp8pUCNGdrjdRVair5IwVB3aapACGbzVdbt7NCDxgBEAEYsO330wcgAw"
	plainText    = "lorem ipsum"
	targetBucket = "mineral-minutia-820-encrypted"
)

var ()

func main() {

	// kh, err := keyset.NewHandle(streamingaead.AES256GCMHKDF4KBKeyTemplate())
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// ksw := &keyset.MemReaderWriter{}
	// if err := insecurecleartextkeyset.Write(kh, ksw); err != nil {
	// 	log.Fatal(err)
	// }

	// use "github.com/golang/protobuf/proto"
	// ks, err := proto.Marshal(ksw.Keyset)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// log.Printf("%s", base64.RawStdEncoding.EncodeToString(ks))

	// m := jsonpb.Marshaler{}
	// result, err := m.MarshalToString(ksw.Keyset)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// log.Printf("%s\n", result)

	srcObjectFile := "in.txt"
	ctx := context.Background()
	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer gcsClient.Close()
	encBucket := gcsClient.Bucket(targetBucket)
	gcsDstObject := encBucket.Object(srcObjectFile + ".enc")

	gcsDstWriter := gcsDstObject.NewWriter(ctx)

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

	file, err := os.Open("in.txt")
	if err != nil {
		log.Fatalf("Failed to open file %v\n", err)
	}

	fReader := bufio.NewReader(file)

	ad := []byte("")

	// encrypt
	log.Println("Encrypting")

	pt, err := a.NewEncryptingWriter(gcsDstWriter, ad)
	if err != nil {
		log.Fatalf("Failed to create encrypt writer: %v", err)
	}

	if _, err := io.Copy(pt, fReader); err != nil {
		log.Fatalf("[Encrypter] Error io.Copy(pt, r.Body): (%s) ", err)
	}
	err = pt.Close()
	if err != nil {
		log.Fatalf("[Encrypter] Error gcsDstWriter.Close: (%s) ", err)
	}
	err = gcsDstWriter.Close()
	if err != nil {
		log.Fatalf("[Encrypter] Error gcsDstWriter.Close: (%s) ", err)
	}

	// *******************************   decrypt
	log.Println("Decrypting")
	gcsSrcObject := encBucket.Object(srcObjectFile + ".enc")
	gcsSrcReader, err := gcsSrcObject.NewReader(ctx)
	if err != nil {
		log.Fatalf("[Decrypter] Error: (%s) ", err)
	}
	defer gcsSrcReader.Close()

	bufout := new(bytes.Buffer)
	r, err := a.NewDecryptingReader(gcsSrcReader, ad)
	if err != nil {
		log.Fatalf("Failed to create decrypt reader: %v", err)
	}
	if _, err := io.Copy(bufout, r); err != nil {
		log.Fatalf("Failed to encrypt data: %v", err)
	}

	log.Printf("%s", bufout.String())

}
