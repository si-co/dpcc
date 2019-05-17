package protocol

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

// HashPrivateAnnouncement is sent down the tree by the leader to start a new
// HashPrivate protocol
type HashPrivateAnnouncement struct {
	URL              string
	ClientPublicKeys map[string]kyber.Point
}

type chanHashPrivateAnnouncement struct {
	*onet.TreeNode
	HashPrivateAnnouncement
}

// HashPrivateResponse contains the encrypted hash and its signature and is
// sent by every conode to the root
type HashPrivateResponse struct {
	PublicKey     kyber.Point
	EncryptedHash []byte
	Nonce         []byte
}

type chanHashPrivateResponse struct {
	*onet.TreeNode
	HashPrivateResponse
}

// ConodeResponse is a data structure used by the leader of the protocol to
// send the encrypted hashes and the nonces of all conodes to the client
type ConodeResponse struct {
	PublicKey     kyber.Point
	EncryptedHash []byte
	Nonce         []byte
}
