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

	// yubikey
	// config := &crypto11.Config{
	// 	Path:       "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
	// 	TokenLabel: "user1_esodemoapp2_com",
	// 	Pin:        "123456",
	// }

	// tpm
	// config := &crypto11.Config{
	// 	Path:       "/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1",
	// 	TokenLabel: "token1",
	// 	Pin:        "mynewpin",
	// }

	ctx, err := crypto11.Configure(config)
	if err != nil {
		log.Fatal(err)
	}

	defer ctx.Close()

	r, err := pkcssigner.NewPKCSCrypto(&pkcssigner.PKCS{
		Context:   ctx,
		PkcsId:    nil,                 //softhsm
		PkcsLabel: []byte("keylabel1"), //softhsm

		// PkcsId:    []byte{1}, //yubikey
		// PkcsLabel: nil,       //yubikey

		// PkcsId:         nil,                  //tpm
		// PkcsId: []byte{0}, //tpm
		// // PkcsLabel:      []byte("keylabel1"),  //tpm https://github.com/ThalesIgnite/crypto11/issues/82
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

	sig, err := r.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Fatalf("signing failed (%s)", err.Error())
	}

	log.Printf("Signature %s", base64.RawStdEncoding.EncodeToString(sig))

	rsaPubKey, ok := r.Public().(*rsa.PublicKey)
	if !ok {
		fmt.Println(err)
		os.Exit(1)
	}

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest[:], sig)
	if err != nil {
		log.Printf("Failed verification. Retrying: %s", err)
		return
	}

	log.Printf(">>>>>> Signature Verified")

}
