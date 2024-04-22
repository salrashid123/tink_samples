package main

/*
gcloud kms keyrings create kr1 --location=global
gcloud kms keys create --keyring=kr1 --location=global --purpose=encryption  k1
*/

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"

	gcpkms "github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"google.golang.org/protobuf/proto"

	gcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	// commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	// ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	// rsppb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	// rspsspb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pss_go_proto"
)

var (
	keysetFile     = flag.String("keyset-file", "", "Tink PublicKey")
	keyID          = flag.Uint("key-id", 0, "Tink PrivateKey")
	kmsURI         = flag.String("master-key-uri", "", "MasterKeyURI for encrypted keyset")
	insecureKeySet = flag.Bool("insecure-key-set", true, "Parse a cleartext keyset")
)

const (
	// AESGCMIVSize is the only IV size that TINK supports.
	// https://pkg.go.dev/github.com/mightyguava/tink/go/subtle/aead#pkg-constants
	AESGCMIVSize = 12

	// https://github.com/google/tink/blob/master/go/core/cryptofmt/cryptofmt.go#L68
	// NonRawPrefixSize is the prefix size of Tink and Legacy key types.
	NonRawPrefixSize = 5

	// TinkPrefixSize is the prefix size of Tink key types.
	// The prefix starts with \x01 and followed by a 4-byte key id.
	TinkPrefixSize = NonRawPrefixSize
	// TinkStartByte is the first byte of the prefix of Tink key types.
	TinkStartByte = byte(1)

	// RawPrefixSize is the prefix size of Raw key types.
	// Raw prefix is empty.
	RawPrefixSize = 0
	// RawPrefix is the empty prefix of Raw key types.
	RawPrefix = ""

	aesGCMKeyTypeURL = "type.googleapis.com/google.crypto.tink.AesGcmKey"
)

func main() {

	flag.Parse()

	keysetBytes, err := os.ReadFile(*keysetFile)
	if err != nil {
		log.Fatalf("Error error reading private key %v", err)
	}

	var keysetHandle *keyset.Handle

	if *insecureKeySet {
		keysetReader := keyset.NewBinaryReader(bytes.NewReader(keysetBytes))
		keysetHandle, err = insecurecleartextkeyset.Read(keysetReader)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		ctx := context.Background()
		gcpClient, err := gcpkms.NewClientWithOptions(ctx, "gcp-kms://")
		if err != nil {
			log.Fatal(err)
		}

		kmsaead, err := gcpClient.GetAEAD(*kmsURI)
		if err != nil {
			log.Fatal(err)
		}
		keysetReader := keyset.NewBinaryReader(bytes.NewReader(keysetBytes))
		keysetHandle, err = keyset.Read(keysetReader, kmsaead)
		if err != nil {
			log.Fatal(err)
		}
	}

	// list all the keyID in this keyset

	log.Printf("keyset default primary keyID: %d\n", keysetHandle.KeysetInfo().PrimaryKeyId)
	for _, k := range keysetHandle.KeysetInfo().KeyInfo {
		log.Printf("  keyset contains keyID: %d with status %s\n", k.KeyId, k.Status)
	}

	a, err := aead.New(keysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	ec, err := a.Encrypt([]byte("foo"), []byte("some additional data"))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Encrypted Data: %s", base64.StdEncoding.EncodeToString(ec))

	if *insecureKeySet {
		tpb := &tinkpb.Keyset{}

		err = proto.Unmarshal(keysetBytes, tpb)
		if err != nil {
			log.Fatal(err)
		}
		for _, kk := range tpb.Key {
			kserialized := kk.KeyData.Value
			if kk.KeyId == tpb.PrimaryKeyId {
				switch kk.KeyData.TypeUrl {
				case aesGCMKeyTypeURL:

					plaintext, err := decryptAES(ec, []byte("some additional data"), kserialized, kk.KeyId, uint32(kk.OutputPrefixType))
					if err != nil {
						log.Fatal(err)
					}
					log.Printf("crypto.cipher.AEAD.Unseal() %s\n", plaintext)

				default:
					log.Fatal(fmt.Errorf(" unsupported keyset %s", kk.KeyData.TypeUrl))
				}
			}
		}
	} else {

		etpb := &tinkpb.EncryptedKeyset{}

		err = proto.Unmarshal(keysetBytes, etpb)
		if err != nil {
			log.Fatal(err)
		}
		ctx := context.Background()
		gcpClient, err := gcpkms.NewClientWithOptions(ctx, "gcp-kms://")
		if err != nil {
			log.Fatal(err)
		}

		kmsaead, err := gcpClient.GetAEAD(*kmsURI)
		if err != nil {
			log.Fatal(err)
		}
		// https://github.com/tink-crypto/tink-go/issues/4
		ekeysetBytes, err := kmsaead.Decrypt(etpb.EncryptedKeyset, []byte{})
		if err != nil {
			log.Fatal(err)
		}

		tpb := &tinkpb.Keyset{}
		err = proto.Unmarshal(ekeysetBytes, tpb)
		if err != nil {
			log.Fatal(err)
		}
		for _, kk := range tpb.Key {
			if kk.KeyId == tpb.PrimaryKeyId {
				kserialized := kk.KeyData.Value

				switch kk.KeyData.TypeUrl {
				case aesGCMKeyTypeURL:
					plaintext, err := decryptAES(ec, []byte("some additional data"), kserialized, kk.KeyId, uint32(kk.OutputPrefixType))
					if err != nil {
						log.Fatal(err)
					}
					log.Printf("crypto.cipher.AEAD.Unseal() %s\n", plaintext)

				default:
					log.Fatal(fmt.Errorf(" unsupported keyset %s", kk.KeyData.TypeUrl))
				}
			}

		}
	}
}

// https://github.com/google/tink/blob/master/go/core/cryptofmt/cryptofmt.go#L68
func createOutputPrefix(size int, startByte byte, keyID uint32) string {
	prefix := make([]byte, size)
	prefix[0] = startByte
	binary.BigEndian.PutUint32(prefix[1:], keyID)
	return string(prefix)
}

func decryptAES(ciphertext, aad, serializedKey []byte, keyID, outputPrefixType uint32) ([]byte, error) {
	aeskey := &gcmpb.AesGcmKey{}
	if err := proto.Unmarshal(serializedKey, aeskey); err != nil {
		return nil, err
	}

	log.Printf("KeyValue %s\n", base64.RawStdEncoding.EncodeToString(aeskey.KeyValue))

	aesCipher, err := aes.NewCipher(aeskey.KeyValue)
	if err != nil {
		return nil, err
	}
	rawAES, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	var ecca []byte
	if outputPrefixType == uint32(tinkpb.OutputPrefixType_TINK) {
		pf := createOutputPrefix(TinkPrefixSize, TinkStartByte, keyID)
		log.Printf("Ciphertext with TINK Prefix %s\n", base64.RawStdEncoding.EncodeToString(ciphertext))
		ecca = ciphertext[len([]byte(pf)):]
		log.Printf("Ciphertext without TINK Prefix %s\n", base64.RawStdEncoding.EncodeToString(ecca))
	} else {
		ecca = ciphertext
	}
	plaintext, err := rawAES.Open(nil, ecca[:AESGCMIVSize], ecca[AESGCMIVSize:], aad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
