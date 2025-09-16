package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
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

	r, err := pkcssigner.NewPKCSCrypto(&pkcssigner.PKCS{
		Context:   ctx,
		PkcsId:    nil,                 //softhsm
		PkcsLabel: []byte("keylabel1"), //softhsm

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

	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash, // Use maximum salt length
		Hash:       crypto.SHA256,               // Use SHA256 for hashing
	}

	sig, err := r.Sign(rand.Reader, digest, pssOpts)
	if err != nil {
		log.Fatalf("signing failed (%s)", err.Error())
	}

	log.Printf("Signature %s", base64.RawStdEncoding.EncodeToString(sig))

	rsaPubKey, ok := r.Public().(*rsa.PublicKey)
	if !ok {
		fmt.Println(err)
		os.Exit(1)
	}

	err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, digest, sig, pssOpts)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("RSA Signed String verified\n")

	log.Printf(">>>>>> Signature Verified")

}
