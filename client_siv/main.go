package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	gcmpb "github.com/google/tink/go/proto/aes_siv_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	hk "github.com/google/tink/go/subtle"

	"log"
	"math/rand"
)

const (

	// https://github.com/google/tink/blob/master/go/core/cryptofmt/cryptofmt.go#L68
	NonRawPrefixSize = 5

	TinkPrefixSize = NonRawPrefixSize
	// TinkStartByte is the first byte of the prefix of Tink key types.
	TinkStartByte = byte(1)

	secret    = "change this password to a secret"
	plainText = "foo"
)

func main() {

	rawKey := []byte(secret)
	pt := []byte(plainText)

	// run key derivation on the original key to 64 (required by tink SIV)
	info := []byte("")
	rawKeyHkdf, err := hk.ComputeHKDF("SHA256", []byte(rawKey), []byte(""), info, 64)
	if err != nil {
		fmt.Print(err)
		return
	}

	k := &gcmpb.AesSivKey{
		Version:  0,
		KeyValue: rawKeyHkdf,
	}

	serialized, err := proto.Marshal(k)
	if err != nil {
		panic(err)
	}

	id := rand.Uint32()
	ks := &tinkpb.Keyset{
		PrimaryKeyId: id,
		Key: []*tinkpb.Keyset_Key{{
			KeyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				Value:           serialized,
			},
			KeyId:            id,
			Status:           tinkpb.KeyStatusType_ENABLED,
			OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		},
		},
	}

	nkh, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		panic(err)
	}

	ksw := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(nkh, ksw); err != nil {
		panic(err)
	}

	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	if err := w.Write(ksw.Keyset); err != nil {
		panic(err)
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
	if err != nil {
		panic(err)
	}

	log.Println("Tink Keyset:\n", string(prettyJSON.Bytes()))

	a, err := daead.New(nkh)
	if err != nil {
		panic(err)
	}

	ec, err := a.EncryptDeterministically(pt, []byte(""))
	if err != nil {
		panic(err)
	}

	log.Printf("Tink Encrypted: %s", base64.StdEncoding.EncodeToString(ec))

	dec, err := a.DecryptDeterministically(ec, []byte(""))
	if err != nil {
		panic(err)
	}
	log.Printf("Tink Decrypted: %s", string(dec))

}
