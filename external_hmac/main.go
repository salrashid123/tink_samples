package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log"
	"math/rand"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/mac/subtle"
	common_go_proto "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"
)

const (
	NonRawPrefixSize = 5
	RawPrefixSize    = 0
	TinkPrefixSize   = NonRawPrefixSize
	TinkStartByte    = byte(1)
	RawPrefix        = ""

	tagSize = 32
	keyURI  = "projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1"
)

var (
	secret    = "change this password to a secret"
	plainText = "foo"
)

func main() {

	id := rand.Uint32()

	log.Println("1.  Test HMAC/Verify secret using crypto/hmac")
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(plainText))

	// Get result and encode as hexadecimal string
	m := h.Sum(nil)
	sha := base64.StdEncoding.EncodeToString(m)

	log.Printf("    HMAC: %s", sha)

	vmac := hmac.New(sha256.New, []byte(secret))
	vmac.Write([]byte(plainText))
	if !hmac.Equal(m, vmac.Sum(nil)) {
		log.Fatal("Couldnot verify MAC")
	}
	log.Printf("    MAC Verified")

	//****************

	log.Println("2.  Create tink suble.HMAC using secret")
	tk, err := subtle.NewHMAC(common_go_proto.HashType_name[int32(common_go_proto.HashType_SHA256)], []byte(secret), tagSize)
	if err != nil {
		log.Fatal(err.Error())
	}

	k := &hmacpb.HmacKey{
		Version: 0,
		Params: &hmacpb.HmacParams{
			Hash:    common_go_proto.HashType_SHA256,
			TagSize: tagSize,
		},
		KeyValue: tk.Key,
	}
	log.Printf("    Tink HmacKey Key: %v", base64.StdEncoding.EncodeToString(k.GetKeyValue()))

	keyserialized, err := proto.Marshal(k)
	if err != nil {
		log.Fatal(err)
	}

	// construct a keyset and place the serialized key into that
	keysetKey := &tinkpb.Keyset_Key{
		KeyData: &tinkpb.KeyData{
			TypeUrl:         "type.googleapis.com/google.crypto.tink.HmacKey",
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			Value:           keyserialized,
		},
		KeyId:            id,
		Status:           tinkpb.KeyStatusType_ENABLED,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}

	ks := &tinkpb.Keyset{
		PrimaryKeyId: id,
		Key:          []*tinkpb.Keyset_Key{keysetKey},
	}

	// Serialize the whole keyset
	rawSerialized, err := proto.Marshal(ks)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt the serialized keyset with kms
	gcpClient, err := gcpkms.NewClient("gcp-kms://")
	if err != nil {
		log.Fatal(err)
	}
	registry.RegisterKMSClient(gcpClient)

	backend, err := gcpClient.GetAEAD("gcp-kms://" + keyURI)
	if err != nil {
		log.Printf("Could not acquire KMS Hmac %v", err)
		return
	}

	log.Printf("    Serialized Tink Keyset: %s\n", base64.StdEncoding.EncodeToString(rawSerialized))
	ciphertext, err := backend.Encrypt(rawSerialized, []byte(""))
	if err != nil {
		log.Fatal(err)
	}

	// Create  an EncryptedKeyset and embed the encrypted key into that
	ksi := &tinkpb.KeysetInfo{
		PrimaryKeyId: keysetKey.KeyId,
		KeyInfo: []*tinkpb.KeysetInfo_KeyInfo{
			{
				TypeUrl:          keysetKey.KeyData.TypeUrl,
				Status:           keysetKey.Status,
				KeyId:            keysetKey.KeyId,
				OutputPrefixType: keysetKey.OutputPrefixType,
			},
		},
	}

	eks := &tinkpb.EncryptedKeyset{
		EncryptedKeyset: ciphertext,
		KeysetInfo:      ksi,
	}

	eksSerialized, err := proto.Marshal(eks)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("    Serialized EncryptedKeyset: %s\n", base64.StdEncoding.EncodeToString(eksSerialized))

	// Print the Encrypted Keyset

	eks2 := &tinkpb.EncryptedKeyset{}
	err = proto.Unmarshal(eksSerialized, eks2)
	if err != nil {
		panic(err)
	}

	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	if err := w.WriteEncrypted(eks2); err != nil {
		log.Printf("Could not write encrypted keyhandle %v", err)
		return
	}

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)

	}
	log.Println("    Tink Keyset:\n", string(prettyJSON.Bytes()))

	// Read the json keyset bytes using the KMS backend
	r := keyset.NewJSONReader(&prettyJSON)
	kh1, err := keyset.Read(r, backend)
	if err != nil {
		log.Printf("Could not create TINK keyHandle %v", err)
		return
	}

	log.Println("3. Constructing MAC with TINK")

	// Construct MAC
	a, err := mac.New(kh1)
	if err != nil {
		log.Fatal(err)
	}

	tag, err := a.ComputeMAC([]byte(plainText))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("    MAC %s\n", base64.RawStdEncoding.EncodeToString(tag))

	err = a.VerifyMAC(tag, []byte(plainText))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("    MAC Verified")

	log.Println("4. Verify TINK MAC with crypto/hmac")
	// Add TINK output prefix to plain MAC
	//   use if OutputPrefixType: tinkpb.OutputPrefixType_TINK
	//   pf := createOutputPrefix(TinkPrefixSize, TinkStartByte, id)
	decoded, err := base64.StdEncoding.DecodeString(sha)
	if err != nil {
		log.Fatal(err)
	}
	//  pciphertext := append([]byte(pf), decoded...)

	// 13. Use Tink to decrypt cipherText created manually (from step 12)
	err = a.VerifyMAC(decoded, []byte(plainText))
	if err != nil {
		log.Fatal(err)
	}
	// 14. Use Tink to decrypt cipherText created manually (from step 12)
	smac := hmac.New(sha256.New, []byte(secret))
	smac.Write([]byte(plainText))
	if !hmac.Equal(decoded, smac.Sum(nil)) {
		log.Fatal("Couldnot verify MAC")
	}
	log.Printf("    MAC Verified")

	// buf = new(bytes.Buffer)
	// w = keyset.NewJSONWriter(buf)
	// if err := w.Write(ks); err != nil {
	// 	log.Fatalf("cannot write encrypted keyset: %v", err)
	// }
	// err = ioutil.WriteFile("keyset.json", buf.Bytes(), 0644)
	// if err != nil {
	// 	log.Fatal("cannot write encrypted keyset: %v", err)
	// }

}

// https://github.com/google/tink/blob/master/go/core/cryptofmt/cryptofmt.go#L68
func createOutputPrefix(size int, startByte byte, keyID uint32) string {
	prefix := make([]byte, size)
	prefix[0] = startByte
	binary.BigEndian.PutUint32(prefix[1:], keyID)
	return string(prefix)
}
