## crypto.Signer for PKCS11


where private keys as embedded inside `PKCS-11` device

Basically, you will get a [crypto.Signer](https://pkg.go.dev/crypto#Signer) interface for the private key. 
Use the signer to create a TLS session, sign CA/CSRs, or just sign anything.

Note, pkcs11 crypto.signers are a dime a dozen (eg. at [ThalesGroup/crypto11](https://github.com/ThalesGroup/crypto11?tab=readme-ov-file#crypto11), and many more)

the difference with this library is that it also surfaces a way to directly establish TLS using PKCS11 based keys

```golang
  func (t PKCS) TLSCertificate() (tls.Certificate, error) {
```

* [mTLS with PKCS11](https://github.com/salrashid123/mtls_pkcs11)

>> NOTE: this repo is NOT supported by Google

---

For pure TPM signer, review

[crypto.Signer, implementations for Trusted Platform Modules](https://github.com/salrashid123/tpmsigner)

---

### Usage Signer

Initialize a signer and directly use `.sign()` as shown in this below and in the samples

```golang
require (
	github.com/salrashid123/tpmsigner v0.0.1
)
```

then

```golang
import (
	"github.com/salrashid123/pkcsigner"
	"github.com/ThalesGroup/crypto11"  
)

	config := &crypto11.Config{
		Path:       "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		TokenLabel: "token1",
		Pin:        "mynewpin",
	}

	stringToSign := []byte("foo")

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	ctx, err := crypto11.Configure(config)
	if err != nil {
		log.Fatal(err)
	}

	defer ctx.Close()

	r, err := pkcssigner.NewPKCSCrypto(&pkcssigner.PKCS{
		Context:   ctx,
		PkcsId:    nil, 
		PkcsLabel: []byte("keylabel1"),
	})

	s, err := r.Sign(rand.Reader, digest, crypto.SHA256)

	fmt.Printf("RSA Signed String: %s\n", base64.StdEncoding.EncodeToString(s))
```

### Install PKCS11 support and Verify with OpenSSL

The following will install and test softHSM using openssl.  Once this is done, we will use the golang mTLS clients to establish client-server communication.

First install openssl with its [PKCS11 engine](https://github.com/OpenSC/libp11#openssl-engines).

On debian

```bash
apt-get update && apt-get install libtpm2-pkcs11-1 \
     tpm2-tools pkcs11-provider opensc softhsm2 libsofthsm2 libengine-pkcs11-openssl -y


$ openssl engine -t -c pkcs11
(pkcs11) pkcs11 engine
     [ available ]

$ openssl engine dynamic \
 -pre SO_PATH:/usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so \
 -pre ID:pkcs11 -pre LIST_ADD:1 \
 -pre LOAD \
 -pre MODULE_PATH:/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
 -t -c

  (dynamic) Dynamic engine loading support
  [Success]: SO_PATH:/usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so
  [Success]: ID:pkcs11
  [Success]: LIST_ADD:1
  [Success]: LOAD
  [Success]: MODULE_PATH:/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
  Loaded: (pkcs11) pkcs11 engine
  [RSA, rsaEncryption, id-ecPublicKey]
      [ available ]

## TODO: use providers
# $ openssl list  -provider pkcs11  -provider default  --providers
# Providers:
#   default
#     name: OpenSSL Default Provider
#     version: 3.5.0
#     status: active
#   pkcs11
#     name: PKCS#11 Provider
#     version: 3.5.0
#     status: active
```


#### SOFTHSM

SoftHSM is as the name suggests, a sofware "HSM" module used for testing.   It is ofcourse not hardware backed but the module does allow for a PKCS11 interface which we will also use for testing.

First make sure the softhsm library is installed

- [SoftHSM Install](https://www.opendnssec.org/softhsm/)

Setup a config file where the `directories.tokendir` points to a existing folder where softHSM will save all its data (in this case its `misc/tokens/`)

>> This repo already contains a sample configuration/certs to use with the softhsm token directory...just delete the folder and start from scratch if you want..


Use [pkcs11-too](https://manpages.debian.org/testing/opensc/pkcs11-tool.1.en.html) which comes with the installation of opensc

```bash
# export OPENSSL_CONF=`pwd`/example/openssl.cnf
export PKCS11_PROVIDER_MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
export SOFTHSM2_CONF=`pwd`/example/softhsm.conf
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/ 

rm -rf /tmp/tokens
mkdir /tmp/tokens

pkcs11-tool --module $PKCS11_PROVIDER_MODULE  --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module $PKCS11_PROVIDER_MODULE  --label="token1" --init-pin --so-pin "123456" --pin mynewpin

pkcs11-tool --module $PKCS11_PROVIDER_MODULE --list-token-slots
pkcs11-tool --module $PKCS11_PROVIDER_MODULE -l -k --key-type rsa:2048 --id=1 --label keylabel1 --pin mynewpin 
pkcs11-tool --module $PKCS11_PROVIDER_MODULE -l -k --key-type ec:prime256v1 --id 2 --label keylabel2 --pin mynewpin

pkcs11-tool --module $PKCS11_PROVIDER_MODULE  --list-objects

## important: set the serial_num you get after you ran --list-token-slots above
export serial_number="3cb32116793a2272"

export PKCS11_RSA_PRIVATE_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;id=%01;serial=$serial_number;token=token1;type=private;object=keylabel1?pin-value=mynewpin"
export PKCS11_RSA_PUBLIC_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;id=%01;serial=$serial_number;token=token1;type=public;object=keylabel1?pin-value=mynewpin"

### TODO: using provider https://github.com/latchset/pkcs11-provider/issues/634
# export PKCS11_PROVIDER_DEBUG=file:/tmp/p11prov-debug.log,level=5
# openssl pkey -provider pkcs11 -provider default -in "$PKCS11_RSA_PUBLIC_KEY" -pubout
# openssl pkey -provider pkcs11 -provider default  -in "$PKCS11_RSA_PRIVATE_KEY" -pubout

### using engine, create a key 
openssl pkey -engine pkcs11  -inform engine -in "$PKCS11_RSA_PUBLIC_KEY" -pubout  -out /tmp/pub.pem

## optionally create a csr and load it to the device
openssl req  -engine pkcs11 --keyform engine -new -key "$PKCS11_RSA_PRIVATE_KEY" -subj "/CN=my_key" -out /tmp/server.csr
openssl x509  -engine pkcs11 --keyform engine -req -days 365 -in /tmp/server.csr -signkey "$PKCS11_RSA_PRIVATE_KEY" -out /tmp/server.crt
openssl x509 -outform DER -in  /tmp/server.crt -out  /tmp/server.der
pkcs11-tool  --module $PKCS11_PROVIDER_MODULE --pin mynewpin --write-object /tmp/server.der --type cert --id 1 --label keylabel1 

## you can now see the public items:
pkcs11-tool --module $PKCS11_PROVIDER_MODULE  --list-objects

## now sign some data
echo "sig data" > /tmp/data.txt
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_RSA_PUBLIC_KEY" -pubout -out /tmp/pub.pem
openssl pkeyutl -engine pkcs11 -keyform engine  -inkey $PKCS11_RSA_PRIVATE_KEY -sign -in /tmp/data.txt -out /tmp/data.sig
openssl pkeyutl -pubin -inkey /tmp/pub.pem -verify -in /tmp/data.txt -sigfile /tmp/data.sig
```

then run the `examples`:

```bash
cd example/

go run rsa/main.go

## for ecc
go run ecc/main.go
```

---

### References

* OpenSSL Provider
  - `/usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so`:  OpenSSL Engine that allows dynamic PKCS11 providers

* PKCS11 Modules
  - `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`: [SoftHSM PKCS Driver](https://packages.ubuntu.com/xenial/libsofthsm2)
  - `/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1`: [TPM PKCS11 Driver](https://github.com/tpm2-software/tpm2-pkcs11)
  - `/usr/lib/x86_64-linux-gnu/libykcs11.so`:  [Yubikey PKCS Driver](https://developers.yubico.com/yubico-piv-tool/YKCS11/)
  - `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`:  Older PKCS11 provider for SmartCards.  [No longer required](https://developers.yubico.com/PIV/Guides/SSH_with_PIV_and_PKCS11.html) for Yubikey 
