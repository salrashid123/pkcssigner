package pkcssigner

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"sync"

	"github.com/ThalesGroup/crypto11"
)

const ()

var ()

type PKCS struct {
	priv crypto.Signer
	//_ crypto.MessageSigner // introduced in https://tip.golang.org/doc/go1.25#cryptopkgcrypto

	X509Certificate *x509.Certificate // public x509 certificate for the signer

	pcert     *x509.Certificate
	PkcsId    []byte
	PkcsLabel []byte
	Context   *crypto11.Context

	ECCRawOutput bool // for ECC keys, output raw signatures. If false, signature is ans1 formatted

	refreshMutex *sync.Mutex
}

func NewPKCSCrypto(conf *PKCS) (PKCS, error) {

	var err error
	conf.priv, err = conf.Context.FindKeyPair(conf.PkcsId, conf.PkcsLabel)
	if err != nil {
		return PKCS{}, fmt.Errorf("could not find keypair %v", err)
	}

	if conf.priv == nil {
		return PKCS{}, fmt.Errorf("could not find KeyPair")
	}

	if conf.X509Certificate == nil {
		crt, err := conf.Context.FindCertificate(conf.PkcsId, conf.PkcsLabel, nil)
		if err != nil {
			return PKCS{}, fmt.Errorf("could not retrieve x509 Certificate from PKCS config;  please specify X509Certificate %v", err)
		}
		// if crt == nil {
		// 	return PKCS{}, fmt.Errorf("Could not retrieve x509 Certificate from PKCS config;  please specify X509Certificate")
		// }
		conf.pcert = crt
	} else {
		conf.pcert = conf.X509Certificate
	}

	return PKCS{
		refreshMutex: &sync.Mutex{}, // guards impersonatedToken; held while fetching or updating it.
		priv:         conf.priv,
		pcert:        conf.pcert,
		PkcsId:       conf.PkcsId,
		PkcsLabel:    conf.PkcsLabel,
		Context:      conf.Context,
	}, nil

}

func (t PKCS) Public() crypto.PublicKey {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()
	return t.priv.Public()
}

func (t PKCS) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()
	return t.priv.Sign(rand, digest, opts)
}

func (t PKCS) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	sigHash := opts.HashFunc()
	if !sigHash.Available() {
		return nil, fmt.Errorf("messagesignerwrapper: hash function [%s] not available", sigHash.String())
	}
	hsh := sigHash.New()
	hsh.Write(msg)
	digest := hsh.Sum(nil)
	return t.priv.Sign(rand, digest, opts)
}

func (t PKCS) TLSCertificate() (tls.Certificate, error) {

	if t.pcert == nil {
		return tls.Certificate{}, fmt.Errorf("please specify X509Certificate for TLSCertificate")
	}

	var privKey crypto.PrivateKey = t
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        t.pcert,
		Certificate: [][]byte{t.pcert.Raw},
	}, nil
}
