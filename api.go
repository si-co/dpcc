package dpcc

import (
	"errors"

	"github.com/si-co/dpcc/lib"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

// ServiceName is used for registration on the onet.
const ServiceName = "DPPC"

// Client is a structure to communicate with the DWC
// service
type Client struct {
	*onet.Client
}

// NewClient instantiates a new decenarch.Client
func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}

// PublicHashRequest sends a request for a public hash protocol to the roster
func (c *Client) PublicHashRequest(r *onet.Roster, URL string) (*HashPublicResponse, error) {
	// verify the roster
	if len(r.List) == 0 {
		return nil, errors.New("got an empty roster list")
	}

	// prepare request for the leader
	req := &HashPublicRequest{
		Roster: r,
		URL:    URL,
		Nonce:  lib.GenNonce(),
	}

	// send request to a random conode in the roster, acting as the leader
	// of the protocol
	dst := r.RandomServerIdentity()
	log.Lvl4("sending message to leader", dst)
	resp := &HashPublicResponse{}
	err := c.SendProtobuf(dst, req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// PrivateHashRequest sends a request for a private hash protocol to the roster
func (c *Client) PrivateHashRequest(r *onet.Roster, URL string) (*HashPrivateResponse, error) {
	// verify the roster
	if len(r.List) == 0 {
		return nil, errors.New("got an empty roster list")
	}

	// generate ephemeral keys. Note: this has to be done here on the
	// client, because in this setting the leader is considered to be HBC
	// and therefore we don't want him to be able to decrypt the hashes
	privateKeys, publicKeys := lib.GenEphemeralKeys(r)

	// prepare request for the leader
	req := &HashPrivateRequest{
		Roster:           r,
		URL:              URL,
		ClientPublicKeys: publicKeys,
	}

	// send request to a random conode in the roster, acting as the leader
	// of the protocol
	dst := r.RandomServerIdentity()
	log.Lvl4("sending message to leader", dst)
	resp := &HashPrivateResponse{}
	err := c.SendProtobuf(dst, req, resp)
	if err != nil {
		return nil, err
	}

	// decrypt the received hashes
	hashes := make(map[string][]byte)
	for pk, v := range resp.Responses {
		// compute previsously shared key
		pre := lib.DhExchange(privateKeys[pk], v.PublicKey)
		// determine context for this AEAD scheme
		ctx := lib.Context(publicKeys[pk], v.PublicKey)
		// instantiate AEAD scheme (AES128-GCM)
		gcm, err := lib.NewAEAD(cothority.Suite.Hash, pre, ctx)
		if err != nil {
			return nil, err
		}
		// encrypt hash with AES128-GCM
		decrypted, err := gcm.Open(nil, v.Nonce, v.EncryptedHash, nil)
		if err != nil {
			return nil, err
		}

		// store decrypted hash
		hashes[pk] = decrypted
	}

	// send decrypted hashes back to the app
	resp.Hashes = hashes
	return resp, nil
}
