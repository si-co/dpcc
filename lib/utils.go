package lib

import (
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
)

// GenEphemeralKeys generate an ephemeral key pair for every conode in the
// roster. Note: the security of this function should be verified, because we
// return also the private keys
func GenEphemeralKeys(r *onet.Roster) (map[string]kyber.Scalar, map[string]kyber.Point) {
	ephemeralPrivateKeys := make(map[string]kyber.Scalar)
	ephemeralPublicKeys := make(map[string]kyber.Point)
	for _, v := range r.List {
		k := cothority.Suite.Scalar().Pick(random.New())
		ephemeralPrivateKeys[v.Public.String()] = k
		ephemeralPublicKeys[v.Public.String()] = cothority.Suite.Point().Mul(k, nil)
	}

	return ephemeralPrivateKeys, ephemeralPublicKeys
}

// GenNonce generates a 32 bytes nonce
func GenNonce() []byte {
	nonce := make([]byte, 32)
	random.Bytes(nonce, random.New())
	return nonce
}

// SignWithNonce signs the message concatenated with the nonce using a Schnorr
// signature.
func SignWithNonce(privateKey kyber.Scalar, msg []byte, nonce []byte) ([]byte, error) {
	// concatenate message and nonce
	msgWithNonce := append(msg, nonce...)

	// sign using Schnorr
	sig, err := schnorr.Sign(cothority.Suite, privateKey, msgWithNonce)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// VerifyWithNonce verifies a signature of the message concatenated with the
// nonce.
func VerifyWithNonce(publicKey kyber.Point, msg []byte, nonce []byte, sig []byte) error {
	msgWithNonce := append(msg, nonce...)
	return schnorr.Verify(cothority.Suite, publicKey, msgWithNonce, sig)
}
