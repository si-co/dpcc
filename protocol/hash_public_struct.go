package protocol

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

// HashPublicAnnouncement is sent down the tree by the root to propagate the hash
// received by the client to other conodes
type HashPublicAnnouncement struct {
	URL               string
	ClientContentHash []byte
	Nonce             []byte
}

type chanHashPublicAnnouncement struct {
	*onet.TreeNode
	HashPublicAnnouncement
}

// WorkerResponseHashPublic is used to store the responses of the workers by
// the leader and send them back to the service
type WorkerResponseHashPublic struct {
	PublicKey kyber.Point
	Hash      []byte
	Signature []byte
}

// HashPublicResponse send by every conode to the root
type HashPublicResponse struct {
	WorkerResponseHashPublic
}

type chanHashPublicResponse struct {
	*onet.TreeNode
	HashPublicResponse
}
