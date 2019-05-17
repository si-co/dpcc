package protocol

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"sync"

	"github.com/si-co/dpcc/lib"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// NameHashPublic is the protocol identifier string
const NameHashPublic = "HashPublic"

func init() {
	network.RegisterMessages(HashPublicAnnouncement{}, HashPublicResponse{})
	onet.GlobalProtocolRegister(NameHashPublic, NewHashPublicProtocol)
}

// WorkerResponseHashPublic is used to store the responses of the workers by
// the leader and send them back to the service
type WorkerResponseHashPublic struct {
	PublicKey kyber.Point
	Hash      []byte
	Signature []byte
}

// HashPublic is the core structure of the protocol, holding all the
// necessary information
type HashPublic struct {
	*onet.TreeNodeInstance
	// resource's URL
	URL string
	// nonce received from the client
	Nonce []byte
	// map of conode responses indexed by the public key of the worker
	Responses map[string]*WorkerResponseHashPublic
	// associated lock
	responsesLock *sync.Mutex

	// protocol channels
	// the channel waiting for Announcement messages
	announce chan chanHashPublicAnnouncement
	// the channel waiting for Response messages
	response chan []chanHashPublicResponse
	// the channel that indicates if we are finished or not
	Finished chan bool
}

// NewHashPublicProtocol returns a HashPublicProtocol with the right
// channels initialized
func NewHashPublicProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl2("creating new hash comparaison protocol")
	h := &HashPublic{
		TreeNodeInstance: n,
		Responses:        make(map[string]*WorkerResponseHashPublic),
		responsesLock:    new(sync.Mutex),
		Finished:         make(chan bool, 1),
	}

	// register the channels we want listen on
	if err := n.RegisterChannels(&h.announce, &h.response); err != nil {
		return nil, err
	}

	return h, nil
}

// Start is executed by the root to start the protocol, by checking that all
// the needed parameters have been initialized and by handling the announcement
// for the root itself
func (h *HashPublic) Start() error {
	log.Lvl2("starting hash public protocol")
	// check parameters of the protocol
	if h.URL == "" {
		return errors.New("initialize URL first")
	}
	if h.Nonce == nil {
		return errors.New("initialize nonce first")
	}

	// start announcement phase
	a := &HashPublicAnnouncement{
		URL:   h.URL,
		Nonce: h.Nonce,
	}

	return h.handleAnnouncement(a)
}

// Dispatch will listen on the two channels we use
func (h *HashPublic) Dispatch() error {
	defer h.Done()
	nbrChild := len(h.Children())

	// if we are a leaf, we should handle the announcement
	if !h.IsRoot() {
		log.Lvl3(h.Name(), "waiting for announcement")
		a := (<-h.announce).HashPublicAnnouncement
		if err := h.handleAnnouncement(&a); err != nil {
			return err

		}
	}

	// if we are the root, we should handle the responses
	if !h.IsLeaf() {
		for n, r := range <-h.response {
			log.Lvlf3("%s handling response of child %d/%d",
				h.Name(), n+1, nbrChild)
			err := h.handleResponse(&r.HashPublicResponse)
			if err != nil {
				return err
			}
		}

		// once all responses have been aggregated, communicate end of
		// the protocol to service
		log.Lvl2("hash public protocol terminated")
		h.Finished <- true
	}

	return nil
}

// handleAnnouncement wait for the announcement coming from the root, compute
// the hash of the resource and send it back to the root
func (h *HashPublic) handleAnnouncement(in *HashPublicAnnouncement) error {
	// store parameters of the protocol
	h.URL = in.URL
	log.Lvlf4("%s received %s as URL in announcement", h.Name(), h.URL)
	h.Nonce = in.Nonce
	log.Lvlf4("%s received %s ad nonce in announcement", h.Name(), h.Nonce)

	// if we are a leaf, we should go to response
	if h.IsLeaf() {
		return h.handleResponse(nil)
	}

	// root should send announcement to children
	return h.SendToChildren(in)
}

func (h *HashPublic) handleResponse(in *HashPublicResponse) error {
	if h.IsLeaf() {
		// fetch resource specified by the URL
		// in this case we do not parse nor normalize the resource, we
		// take the hash of the data as they are seen by the host
		resource, err := lib.FetchMainResource(h.URL)
		if err != nil {
			return err
		}

		// compute hash
		hasher := cothority.Suite.Hash()
		io.Copy(hasher, bytes.NewReader(resource.Data))
		hash := hasher.Sum(nil)
		log.Lvlf4("%s computed hash %s", h.Name(), base64.StdEncoding.EncodeToString(hash))

		// compute signature with nonce
		sig, err := lib.SignWithNonce(h.Private(), hash, h.Nonce)
		if err != nil {
			return err
		}
		log.Lvlf4("%s produced sig %s", h.Name(), base64.StdEncoding.EncodeToString(sig))

		// since we are a leaf, send response to parent
		r := &HashPublicResponse{
			PublicKey: h.Public(),
			Hash:      hash,
			Signature: sig,
		}

		log.Lvlf3("%s sending response to parent", h.Name())
		return h.SendToParent(r)
	}

	// if we are the root, we store the child contribution
	pkString := in.PublicKey.String()
	log.Lvlf3("%s aggregating response for node %s", h.Name(), pkString)
	wr := &WorkerResponseHashPublic{
		PublicKey: in.PublicKey,
		Hash:      in.Hash,
		Signature: in.Signature,
	}
	h.responsesLock.Lock()
	h.Responses[pkString] = wr
	h.responsesLock.Unlock()
	return nil

}
