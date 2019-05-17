package lib

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"golang.org/x/crypto/hkdf"
)

var sharedKeyLength = 32

// DhExchange computes the shared key from a private key and a public key
func DhExchange(ownPrivate kyber.Scalar, remotePublic kyber.Point) kyber.Point {
	sk := cothority.Suite.Point()
	sk.Mul(ownPrivate, remotePublic)
	return sk
}

// NewAEAD returns the AEAD cipher to be use to encrypt a share
func NewAEAD(fn func() hash.Hash, preSharedKey kyber.Point, context []byte) (cipher.AEAD, error) {
	preBuff, _ := preSharedKey.MarshalBinary()
	reader := hkdf.New(fn, preBuff, nil, context)

	sharedKey := make([]byte, sharedKeyLength)
	if _, err := reader.Read(sharedKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}

// Context returns the context slice to be used when encrypting a share
func Context(client, server kyber.Point) []byte {
	h := cothority.Suite.Hash()
	_, _ = h.Write([]byte("client"))
	_, _ = client.MarshalTo(h)
	_, _ = h.Write([]byte("server"))
	_, _ = server.MarshalTo(h)
	return h.Sum(nil)
}
