package pkcssigner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/ThalesGroup/crypto11"
	"github.com/stretchr/testify/require"
)

const (
	pin      = "mynewpin"
	confPath = "./test_data/softhsm.conf"
)

/*
$ export SOFTHSM2_CONF=test_data/softhsm.conf
// $ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
// $ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots

    Available slots:
    Slot 0 (0x5a08e6cf): SoftHSM slot ID 0x5a08e6cf
      token label        : token1
      token manufacturer : SoftHSM project
      token model        : SoftHSM v2
      token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
      hardware version   : 2.6
      firmware version   : 2.6
      serial num         : c7ce2755da08e6cf
      pin min/max        : 4/255
    Slot 1 (0x1): SoftHSM slot ID 0x1
      token state:   uninitialized

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l -k --key-type rsa:2048 --id 4142 --label keylabel1 --pin mynewpin
	Using slot 0 with a present token (0x5a08e6cf)
	Key pair generated:
	Private Key Object; RSA
	label:      keylabel1
	ID:         4142
	Usage:      decrypt, sign, signRecover, unwrap
	Access:     sensitive, always sensitive, never extractable, local

	Public Key Object; RSA 2048 bits
	label:      keylabel1
	ID:         4142
	Usage:      encrypt, verify, verifyRecover, wrap
	Access:     local

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l -k --key-type ec:prime256v1 --id 4143 --label keylabel2 --pin mynewpin

Using slot 0 with a present token (0x5a08e6cf)
	Key pair generated:
	Private Key Object; EC
	label:      keylabel2
	ID:         4143
	Usage:      decrypt, sign, signRecover, unwrap, derive
	Access:     sensitive, always sensitive, never extractable, local

	Public Key Object; EC  EC_POINT 256 bits
	EC_POINT:   0441041c83a886c449b9a0ee75d39d6e68f46b6fde30b29c029194073b7089d795eac7b2c76c536f108e99931c5e8abf64ba21da3dd123406805b077e7bab942129cce
	EC_PARAMS:  06082a8648ce3d030107 (OID 1.2.840.10045.3.1.7)
	label:      keylabel2
	ID:         4143
	Usage:      encrypt, verify, verifyRecover, wrap, derive
	Access:     local


pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-objects

## get the serial number from the previous --list-token-slots command
export serial_number="c7ce2755da08e6cf"

### Use openssl module to sign and print the public key (not, your serial number will be different)

export PKCS11_RSA_PRIVATE_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=$serial_number;token=token1;type=private;object=keylabel1?pin-value=mynewpin"
export PKCS11_RSA_PUBLIC_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=$serial_number;token=token1;type=public;object=keylabel1?pin-value=mynewpin"


#### issue x509
openssl pkey -engine pkcs11  -inform engine -in "$PKCS11_RSA_PUBLIC_KEY" -pubout  -out /tmp/pub.pem
openssl req  -engine pkcs11 --keyform engine -new -key "$PKCS11_RSA_PRIVATE_KEY" -subj "/CN=my_key" -out /tmp/server.csr
openssl x509  -engine pkcs11 --keyform engine -req -days 365 -in /tmp/server.csr -signkey "$PKCS11_RSA_PRIVATE_KEY" -out /tmp/server.crt

openssl x509 -outform DER -in  /tmp/server.crt -out  /tmp/server.der

pkcs11-tool  --module $PKCS11_PROVIDER_MODULE --pin mynewpin --write-object /tmp/server.der --type cert --id 1 --label keylabel1
pkcs11-tool --module $PKCS11_PROVIDER_MODULE  --list-objects


*/

const (
	newpin       = "mynewpin"
	defaultpin   = "1234"
	defaultLabel = "token1"
)

var (
	//lib = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
	lib = "/usr/lib/softhsm/libsofthsm2.so"
)

const ()

func TestSignRSA(t *testing.T) {
	t.Setenv("SOFTHSM2_CONF", confPath)

	config := &crypto11.Config{
		Path:       lib,
		TokenLabel: defaultLabel,
		Pin:        newpin,
	}

	ctx, err := crypto11.Configure(config)
	require.NoError(t, err)

	defer ctx.Close()

	r, err := NewPKCSCrypto(&PKCS{
		Context:   ctx,
		PkcsId:    nil,                 //softhsm
		PkcsLabel: []byte("keylabel1"), //softhsm
	})
	require.NoError(t, err)

	// Sign 'msg'

	stringToSign := "sig data"

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	sig, err := r.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)

	rsaPubKey, ok := r.Public().(*rsa.PublicKey)
	require.True(t, ok)

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest[:], sig)
	require.NoError(t, err)
}

func TestSignRSAPSS(t *testing.T) {
	t.Setenv("SOFTHSM2_CONF", confPath)

	config := &crypto11.Config{
		Path:       lib,
		TokenLabel: defaultLabel,
		Pin:        newpin,
	}

	ctx, err := crypto11.Configure(config)
	require.NoError(t, err)

	defer ctx.Close()

	r, err := NewPKCSCrypto(&PKCS{
		Context:   ctx,
		PkcsId:    nil,                 //softhsm
		PkcsLabel: []byte("keylabel1"), //softhsm
	})
	require.NoError(t, err)

	// Sign 'msg'

	stringToSign := "sig data"

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash, // Use maximum salt length
		Hash:       crypto.SHA256,               // Use SHA256 for hashing
	}

	sig, err := r.Sign(rand.Reader, digest, pssOpts)
	require.NoError(t, err)

	rsaPubKey, ok := r.Public().(*rsa.PublicKey)
	require.True(t, ok)

	err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, digest, sig, pssOpts)
	require.NoError(t, err)
}

func TestSignECCASN1(t *testing.T) {
	t.Setenv("SOFTHSM2_CONF", confPath)

	config := &crypto11.Config{
		Path:       lib,
		TokenLabel: defaultLabel,
		Pin:        newpin,
	}

	ctx, err := crypto11.Configure(config)
	require.NoError(t, err)

	defer ctx.Close()

	er, err := NewPKCSCrypto(&PKCS{
		Context:   ctx,
		PkcsId:    nil,                 //softhsm
		PkcsLabel: []byte("keylabel2"), //softhsm
	})
	require.NoError(t, err)

	// Sign 'msg'

	stringToSign := "sig data"

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	es, err := er.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)

	ecPubKey, ok := er.Public().(*ecdsa.PublicKey)
	require.True(t, ok)

	curveBits := ecPubKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	ok = ecdsa.VerifyASN1(ecPubKey, digest[:], es)
	require.True(t, ok)

}

func TestCertificate(t *testing.T) {
	t.Setenv("SOFTHSM2_CONF", confPath)

	config := &crypto11.Config{
		Path:       lib,
		TokenLabel: defaultLabel,
		Pin:        newpin,
	}

	ctx, err := crypto11.Configure(config)
	require.NoError(t, err)

	defer ctx.Close()

	pubPEMData, err := os.ReadFile("./test_data/server.crt")
	require.NoError(t, err)

	block, _ := pem.Decode(pubPEMData)
	require.NoError(t, err)

	filex509, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	r, err := NewPKCSCrypto(&PKCS{
		Context:         ctx,
		PkcsId:          nil,                 //softhsm
		PkcsLabel:       []byte("keylabel1"), //softhsm
		X509Certificate: filex509,
	})
	require.NoError(t, err)

	tcert, err := r.TLSCertificate()
	require.NoError(t, err)

	require.Equal(t, tcert.Leaf, filex509)
}
