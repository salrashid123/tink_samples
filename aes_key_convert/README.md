## Tink Keyset Key Extractor


Encrypt with `TINK-AES` key and decrypt with `crypto.aes`

```bash
$ tinkey list-key-templates
```

```bash
## AES
$ tinkey create-keyset --key-template=AES256_GCM --out-format=binary --out=/tmp/1.bin

$ tinkey rotate-keyset --key-template=AES256_GCM \
   --in-format=binary \
   --in=/tmp/1.bin \
   --out-format=binary --out=/tmp/2.bin

$ tinkey rotate-keyset --key-template=AES256_GCM \
   --in-format=binary \
   --in=/tmp/2.bin \
   --out-format=binary --out=example/keysets/aes_gcm_1.bin


$ go run main.go --insecure-key-set=true --keyset-file=example/keysets/aes_gcm_1.bin
2024/04/22 14:48:56 keyset default primary keyID: 4112199248
2024/04/22 14:48:56   keyset contains keyID: 536538909 with status ENABLED
2024/04/22 14:48:56   keyset contains keyID: 86374772 with status ENABLED
2024/04/22 14:48:56   keyset contains keyID: 4112199248 with status ENABLED
2024/04/22 14:48:56 Encrypted Data: AfUbLlDge2BHGcfBTzdxT7kZCIEhghYv/3mod2N6ut+z2Btp
2024/04/22 14:48:56 KeyValue 9d17bL1kuWVfEfn9skFI7Caost/X/Qf1/Wafl14gyGQ
2024/04/22 14:48:56 Ciphertext with TINK Prefix AfUbLlDge2BHGcfBTzdxT7kZCIEhghYv/3mod2N6ut+z2Btp
2024/04/22 14:48:56 Ciphertext without TINK Prefix 4HtgRxnHwU83cU+5GQiBIYIWL/95qHdjerrfs9gbaQ
```


---

```bash

export PROJECT_ID=`gcloud config get-value core/project`
gcloud kms keyrings create kr1 --location=global
gcloud kms keys create --keyring=kr1 --location=global --purpose=encryption  k1

export MASTERKEY="gcp-kms://projects/$PROJECT_ID/locations/global/keyRings/kr1/cryptoKeys/k1"

$ tinkey create-keyset --master-key-uri=$MASTERKEY --key-template=AES256_GCM --out-format=binary --out=/tmp/1.bin

$ tinkey rotate-keyset --master-key-uri=$MASTERKEY --key-template=AES256_GCM \
   --in-format=binary \
   --in=/tmp/1.bin \
   --out-format=binary --out=/tmp/2.bin

$ tinkey rotate-keyset --master-key-uri=$MASTERKEY --key-template=AES256_GCM \
   --in-format=binary \
   --in=/tmp/2.bin \
   --out-format=binary --out=example/keysets/aes_gcm_1_kms.bin

$ go run main.go  --master-key-uri=$MASTERKEY --insecure-key-set=false --keyset-file=example/keysets/aes_gcm_1_kms.bin
2024/04/22 14:49:05 keyset default primary keyID: 3519649456
2024/04/22 14:49:05   keyset contains keyID: 790842175 with status ENABLED
2024/04/22 14:49:05   keyset contains keyID: 494503561 with status ENABLED
2024/04/22 14:49:05   keyset contains keyID: 3519649456 with status ENABLED
2024/04/22 14:49:05 Encrypted Data: AdHJlrCo7cMR77rJtLBAWiZTsWoDLZX6L1clsR13W+uPrNye
2024/04/22 14:49:06 KeyValue PO4c7FtswxTdhnjyCd3SyyyhV3jJhqu/+VeuPRbu/hg
2024/04/22 14:49:06 Ciphertext with TINK Prefix AdHJlrCo7cMR77rJtLBAWiZTsWoDLZX6L1clsR13W+uPrNye
2024/04/22 14:49:06 Ciphertext without TINK Prefix qO3DEe+6ybSwQFomU7FqAy2V+i9XJbEdd1vrj6zcng
2024/04/22 14:49:06 crypto.cipher.AEAD.Unseal() foo


```
