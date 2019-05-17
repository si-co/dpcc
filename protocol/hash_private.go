package protocol

import (
	"bytes"
	"errors"
	"io"
	"sync"

	"github.com/si-co/dpcc/lib"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// NameHashPrivate is the protocol identifier string
const NameHashPrivate = "HashPrivate"

func init() {
	network.RegisterMessages(HashPrivateAnnouncement{}, HashPrivateResponse{})
	onet.GlobalProtocolRegister(NameHashPrivate, NewHashPrivateProtocol)
}

// HashPrivate is the core structure of the protocol, holding all the
// necessary information
type HashPrivate struct {
	*onet.TreeNodeInstance
	// resource's URL
	URL string
	// public keys provided by the server
	ClientPublicKeys map[string]kyber.Point
	// map of encrypted hashes received from every server
	Responses map[string]*ConodeResponse
	// associated lock
	responsesLock *sync.Mutex

	// protocol channels
	// the channel waiting for Announcement message
	announce chan chanHashPrivateAnnouncement
	// the channel waiting for the Response message
	response chan []chanHashPrivateResponse
	// the channel that indicates if we are finished or not
	Finished chan bool
}

// NewHashPrivateProtocol returns a HashPrivateProtocol with the necessary
// information and the right channels initialized
func NewHashPrivateProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl2("creating new hash private protocol")
	h := &HashPrivate{
		TreeNodeInstance: n,
		Responses:        make(map[string]*ConodeResponse),
		responsesLock:    new(sync.Mutex),
		Finished:         make(chan bool, 1),
	}

	// register the channels we want to register and listen on
	if err := n.RegisterChannels(&h.announce, &h.response); err != nil {
		return nil, err
	}

	return h, nil
}

// Start is executed by the root to start the protocol, by checking that all
// the needed parameters have been initialized and by handling the announcement
// for the root itself
func (h *HashPrivate) Start() error {
	log.Lvl3("starting hash private protocol")
	// check parameters of the protocol
	if h.URL == "" {
		return errors.New("please initialize URL first")
	}
	if h.ClientPublicKeys == nil {
		return errors.New("please provide a list of ephemeral public keys")
	}

	a := &HashPrivateAnnouncement{
		URL:              h.URL,
		ClientPublicKeys: h.ClientPublicKeys,
	}

	return h.handleAnnouncement(a)
}

// Dispatch will listen on the two channels we user
func (h *HashPrivate) Dispatch() error {
	defer h.Done()
	nbrChild := len(h.Children())

	// if we are a leaf, we should handle the announcement
	if !h.IsRoot() {
		log.Lvl3(h.Name(), "waiting for announcement")
		a := (<-h.announce).HashPrivateAnnouncement
		if err := h.handleAnnouncement(&a); err != nil {
			return err

		}
	}

	// if we are the root, then we handle the responses
	if !h.IsLeaf() {
		for n, r := range <-h.response {
			log.Lvlf3("%s handling response of child %d/%d",
				h.Name(), n+1, nbrChild)
			err := h.handleResponse(&r.HashPrivateResponse)
			if err != nil {
				return err
			}
		}

		// once all responses have been aggregated, communicate end of
		// the protocol to service
		log.Lvl2("hash private protocol terminated")
		h.Finished <- true
	}
	return nil

}

// handleAnnouncement wait for the announcement coming from the root, compute
// the hash of the resource and send it back to the root
func (h *HashPrivate) handleAnnouncement(in *HashPrivateAnnouncement) error {
	// store parameters of the protocol
	h.URL = in.URL
	log.Lvlf3("%s received %s as URL in announcement", h.Name(), h.URL)
	h.ClientPublicKeys = in.ClientPublicKeys
	log.Lvlf3("%s received %#v as ClientPublicKeys in announcement",
		h.Name(), h.ClientPublicKeys)

	// if we are a leaf, we should go to response
	if h.IsLeaf() {
		return h.handleResponse(nil)
	}

	// root should send announcement to children
	return h.SendToChildren(in)
}

func (h *HashPrivate) handleResponse(in *HashPrivateResponse) error {
	if h.IsLeaf() {
		// fetch resource specified by the URL
		// in this case we do not parse nor normalize the resource, we
		// take the hash of the data as they are seen by the host
		resource, err := lib.FetchMainResource(h.URL)
		if err != nil {
			return err
		}

		clientPublicKey := h.ClientPublicKeys[h.Public().String()]

		// compute hash
		hasher := cothority.Suite.Hash()
		io.Copy(hasher, bytes.NewReader(resource.Data))
		hash := hasher.Sum(nil)

		// compute previsously shared key
		pre := lib.DhExchange(h.Private(), clientPublicKey)

		// determine context for HKDF
		ctx := lib.Context(clientPublicKey, h.Public())

		// instantiate AEAD scheme (AES128-GCM)
		gcm, err := lib.NewAEAD(cothority.Suite.Hash, pre, ctx)
		if err != nil {
			return err
		}

		// even if the ephemeral key used by the client is randomly
		// generated and should therefore be always different from
		// previous keys, we use a random nonce for every encryption
		nonce := make([]byte, gcm.NonceSize())
		random.Bytes(nonce, random.New())

		// encrypt hash with AES128-GCM
		encrypted := gcm.Seal(nil, nonce, hash, nil)

		// send response to parent
		r := &HashPrivateResponse{
			PublicKey:     h.Public(),
			EncryptedHash: encrypted,
			Nonce:         nonce,
		}

		return h.SendToParent(r)

	}

	// if we are the root, we store the child contribution
	pk := in.PublicKey
	cr := &ConodeResponse{
		PublicKey:     in.PublicKey,
		EncryptedHash: in.EncryptedHash,
		Nonce:         in.Nonce,
	}
	h.responsesLock.Lock()
	h.Responses[pk.String()] = cr
	h.responsesLock.Unlock()
	return nil
}
