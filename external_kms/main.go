package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/rand"

	//"github.com/gogo/protobuf/jsonpb"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"
)

const (
	keyURI = "projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1"
)

func main() {

	// 1 Create an AES key
	secret := "change this password to a secret"
	rawKey := []byte(secret)
	id := rand.Uint32()

	tk, err := subtle.NewAESGCM(rawKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	// 2 Embed that key as a tink AesGcmKey and serialize it
	k := &gcmpb.AesGcmKey{
		Version:  0,
		KeyValue: tk.Key,
	}
	log.Printf("Tink AESGCM Key: %v", hex.EncodeToString(k.GetKeyValue()))

	keyserialized, err := proto.Marshal(k)
	if err != nil {
		log.Fatal(err)
	}

	// 3 construct a keyset and place the serialized key into that
	keysetKey := &tinkpb.Keyset_Key{
		KeyData: &tinkpb.KeyData{
			TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmKey",
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			Value:           keyserialized,
		},
		KeyId:            id,
		Status:           tinkpb.KeyStatusType_ENABLED,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}

	ks := &tinkpb.Keyset{
		PrimaryKeyId: id,
		Key:          []*tinkpb.Keyset_Key{keysetKey},
	}

	// 4. Serialize the whole keyset
	rawSerialized, err := proto.Marshal(ks)
	if err != nil {
		log.Fatal(err)
	}

	// 5. Encrypt the serialized keyset with kms
	gcpClient, err := gcpkms.NewClient("gcp-kms://")
	if err != nil {
		log.Fatal(err)
	}
	registry.RegisterKMSClient(gcpClient)

	backend, err := gcpClient.GetAEAD("gcp-kms://" + keyURI)
	if err != nil {
		log.Printf("Could not acquire KMS AEAD %v", err)
		return
	}

	log.Printf("   Serialized Keyset: %s\n", base64.StdEncoding.EncodeToString(rawSerialized))
	ciphertext, err := backend.Encrypt(rawSerialized, []byte(""))
	if err != nil {
		log.Fatal(err)
	}

	// 6. Create  an EncryptedKeyset and embed the encrypted key into that
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

	log.Printf("   Serialized EncryptedKeyset: %s\n", base64.StdEncoding.EncodeToString(eksSerialized))

	// 7. Print the Encrypted Keyset

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
	log.Println("Tink Keyset:\n", string(prettyJSON.Bytes()))

	// 8. Read the json keyset bytes using the KMS backend
	r := keyset.NewJSONReader(&prettyJSON)
	kh1, err := keyset.Read(r, backend)
	if err != nil {
		log.Printf("Could not create TINK keyHandle %v", err)
		return
	}

	// 9. Construct AEAD
	a, err := aead.New(kh1)
	if err != nil {
		log.Fatal(err)
	}

	// 10. Encrypt and decrypt with that data

	ct, err := a.Encrypt([]byte("this data needs to be encrypted"), []byte("associated data"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Encrypted %s\n", base64.StdEncoding.EncodeToString(ct))

	pt, err := a.Decrypt(ct, []byte("associated data"))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Cipher text: %s\nPlain text: %s\n", base64.RawStdEncoding.EncodeToString(ct), pt)

}
