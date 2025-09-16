package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/ThalesGroup/crypto11"
	pkcssigner "github.com/salrashid123/pkcssigner"
)

const ()

var ()

func main() {

	// var slotNum *int
	// slotNum = new(int)
	// *slotNum = 0

	// softhsm
	// export SOFTHSM2_CONF=/path/to/softhsm.conf
	config := &crypto11.Config{
		Path:       "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		TokenLabel: "token1",
		Pin:        "mynewpin",
	}

	ctx, err := crypto11.Configure(config)
	if err != nil {
		log.Fatal(err)
	}

	defer ctx.Close()

	er, err := pkcssigner.NewPKCSCrypto(&pkcssigner.PKCS{
		Context:   ctx,
		PkcsId:    nil,                 //softhsm
		PkcsLabel: []byte("keylabel2"), //softhsm
	})
	if err != nil {
		log.Fatal(err)
	}
	// Sign 'msg'

	stringToSign := "sig data"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	es, err := er.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Printf("ECC Signed String: %s\n", base64.StdEncoding.EncodeToString(es))

	ecPubKey, ok := er.Public().(*ecdsa.PublicKey)
	if !ok {
		log.Println("EKPublic key not found")
		return
	}

	curveBits := ecPubKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	ok = ecdsa.VerifyASN1(ecPubKey, digest[:], es)
	if !ok {
		fmt.Printf("ECDSA Signed String failed\n")
		os.Exit(1)
	}

	fmt.Printf("ECDSA Signed String verified ASN1\n")

	type ECDSASignature struct {
		R *big.Int
		S *big.Int
	}

	var sig ECDSASignature
	// Unmarshal DER-encoded ASN.1 data into the struct
	_, err = asn1.Unmarshal(es, &sig)
	if err != nil {
		fmt.Printf("ECDSA Signed String failed\n")
		os.Exit(1)
	}

	ok = ecdsa.Verify(ecPubKey, digest[:], sig.R, sig.S)
	if !ok {
		fmt.Printf("ECDSA verify failed\n")
		os.Exit(1)
	}
	fmt.Printf("ECDSA Signed String verified RAW\n")

}
