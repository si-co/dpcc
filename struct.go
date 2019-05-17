package dpcc

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

// We need to register all messages so the network knows how to handle them.
func init() {
	network.RegisterMessages(HashPublicRequest{}, HashPublicResponse{})
	network.RegisterMessages(HashPrivateRequest{}, HashPrivateResponse{})
}

// HashPublicRequest is used by the client to send a request of a hash public
// protocol to the leader of the roster
type HashPublicRequest struct {
	Roster *onet.Roster
	URL    string
	Nonce  []byte
}

// HashPublicSingleResponse is a helper for HashPublicResponse and stores the
// response of a single worker in the roster for the hash public protocol
type HashPublicSingleResponse struct {
	PubliKey  kyber.Point
	Hash      []byte
	Signature []byte
}

// HashPublicResponse is used by the leader of the protocol to send the results
// of the hash public protocol to the client
type HashPublicResponse struct {
	Responses map[string]*HashPublicSingleResponse
}

// HashPrivateRequest is used by the client to send a request of a hash private
// protocol to the leader of the roster
type HashPrivateRequest struct {
	Roster           *onet.Roster
	URL              string
	ClientPublicKeys map[string]kyber.Point
}

// HashPrivateSingleResponse is a helper for HashPrivateResponse and stores the
// response of a single worker in the roster of the hash private protocol
type HashPrivateSingleResponse struct {
	PublicKey     kyber.Point
	EncryptedHash []byte
	Nonce         []byte
}

// HashPrivateResponse is used by the leader of the protocol to send the
// results of the hash private protocol back to the client
type HashPrivateResponse struct {
	Hashes    map[string][]byte
	Responses map[string]*HashPrivateSingleResponse
}
