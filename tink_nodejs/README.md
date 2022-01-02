## Tink Javascript

Sample that calculates HMAC given a key and data in a browser using [Tink](https://www.npmjs.com/package/tink-crypto).

TBH, i have NO idea why you'd use Tink this in a browser (its certainly something that should be done server-side)

This node sample just generates a MAC so there maybe a small academic usecase for this...but why you'd use the other modes are beyond me.

Anyway, the [npm tink library](https://github.com/npm/tink) has been "in development" for maybe 4 years now and is close to abandonware, IMO...i'm only documenting it since i spent time...you're better off elsewhere..



### Usage
```bash
$ node --version
v16.13.1

$ npm --version
8.1.2
```

then

```bash
npm i
npm start
```

a browser should pop up so type in some text and see the mac


---

Reference for AES-GCM: [https://stackblitz.com/edit/react-rmxhhb](https://stackblitz.com/edit/react-rmxhhb)

(again, that makes even less sense on the browser)

### Control

```bash
echo -n "change this password to a secret" | xxd -p -c 100
  6368616e676520746869732070617373776f726420746f206120736563726574

echo -n foo > data.in

openssl dgst -sha256 -mac hmac -macopt hexkey:6368616e676520746869732070617373776f726420746f206120736563726574 data.in
       HMAC-SHA256(data.in)= 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2
```

note `hex(7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2)` is `fFBQbZk7ShDlrmszypUb8rjIrDmeCjQCa7CsRpvqPeI`
```