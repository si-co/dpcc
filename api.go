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
func (c *Client) PublicHashRequest(r *onet.Roster, URL string) (*ResponseToClient, error) {
	// verify the roster
	if len(r.List) == 0 {
		return nil, errors.New("got an empty roster list")
	}

	// prepare request for the leader
	req := &ClientRequest{
		Roster:        r,
		ConsensusType: Public,
		RequestType:   Hash,
		URL:           URL,
		Nonce:         lib.GenNonce(),
	}

	// send request to a random conode in the roster, acting as the leader
	// of the protocol
	dst := r.RandomServerIdentity()
	log.Lvl4("sending message to leader", dst)
	resp := &ResponseToClient{}
	err := c.SendProtobuf(dst, req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
