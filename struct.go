package dpcc

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

// We need to register all messages so the network knows how to handle them.
func init() {
	network.RegisterMessages(ClientRequest{}, ResponseToClient{})
}

// ConsensusType is used to set the security level of the protocol
type ConsensusType int

const (
	// Public consensus is used when the messages exchanged during the
	// protocol can be public
	Public ConsensusType = iota
	// Private consensus is used when we have to handle honest-but-curious
	// conodes
	Private
	// PrivateVerifiable consensus is used when the conodes can be
	// malicious
	PrivateVerifiable
)

// RequestType indicates the type of the request
type RequestType int

const (
	// Hash indicates the simplest functionality of the protocol, i.e.
	// returning the hash values of the servers' views
	Hash RequestType = iota
	// MainContent indicates to run the consensus protocol only on the main
	// content referenced by the URL received from the client
	MainContent
	// AllContent indicates to run the consensus protocol on the main
	// content and on (part of) the files referenced by the main content
	AllContent
)

// ClientRequest is used by the client to send a request to the lader of the
// protocol, also controlled by the client
type ClientRequest struct {
	Roster        *onet.Roster // indicates the roster the client wants to use
	ConsensusType ConsensusType
	RequestType   RequestType
	URL           string // indicates the URL, or URI, of the object
	Nonce         []byte
}

// ResponseToClient contains
type ResponseToClient struct {
	Hashes     map[string][]byte
	Signatures map[string][]byte
}
