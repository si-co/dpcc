package service

import (
	"errors"
	"sync"
	"time"

	"github.com/si-co/dpcc"
	"github.com/si-co/dpcc/protocol"

	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// used for tests
var templateID onet.ServiceID

func init() {
	var err error
	templateID, err = onet.RegisterNewService(dpcc.ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessages(&storage{})
}

// Service is our template-service
type Service struct {
	*onet.ServiceProcessor

	// storage of the service
	storage *storage
}

// storageID reflects the data we're storing
var storageID = []byte("main")

// storage is used to save our data
type storage struct {
	sync.Mutex
}

// HandleClientRequest is responsible for handling the client request, i.e.
// start the corresponding protocols and send the response back to the client
func (s *Service) HandleClientRequest(req *dpcc.ClientRequest) (*dpcc.ResponseToClient, error) {
	// generate the tree
	root := req.Roster.NewRosterWithRoot(s.ServerIdentity())
	tree := root.GenerateNaryTree(len(req.Roster.List))
	if tree == nil {
		return nil, errors.New("error while creating the tree for the requested protocol")

	}

	// the different protocols are consensus type and request type dependent
	switch req.ConsensusType {
	case dpcc.Public:
		switch req.RequestType {
		case dpcc.Hash:
			// create protocol
			instance, err := s.CreateProtocol(protocol.NameHashPublic, tree)
			if err != nil {
				return nil, err
			}
			protocol := instance.(*protocol.HashPublic)

			// configure protocol
			protocol.URL = req.URL
			protocol.Nonce = req.Nonce

			// run protocol
			if err = protocol.Start(); err != nil {
				return nil, err
			}

			// wait protocol to finish or trigger timeout error
			select {
			case <-protocol.Finished:
				// get data from protocol
				hashes := protocol.Hashes
				signatures := protocol.Signatures

				// send hashes and signatures to client
				resp := &dpcc.ResponseToClient{
					Hashes:     hashes,
					Signatures: signatures,
				}

				return resp, nil
			case <-time.After(time.Second * 5):
				return nil, errors.New("timeout in hash public protocol")
			}
		default:
			return nil, errors.New("unknow request type")

		}
	default:
		return nil, errors.New("unknow consensus type")
	}
}

// NewProtocol is called on all nodes of a Tree (except the root, since it is
// the one starting the protocol) so it's the Service that will be called to
// generate the PI on all others node.
// If you use CreateProtocolOnet, this will not be called, as the Onet will
// instantiate the protocol on its own. If you need more control at the
// instantiation of the protocol, use CreateProtocolService, and you can
// give some extra-configuration to your protocol in here.
func (s *Service) NewProtocol(node *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	return nil, nil
}

// save saves all the data.
func (s *Service) save() {
	s.storage.Lock()
	defer s.storage.Unlock()
	err := s.Save(storageID, s.storage)
	if err != nil {
		log.Error("Couldn't save data:", err)
	}
}

// tryLoad tries to load the configuration and updates the data in the service
// if it finds a valid config-file.
func (s *Service) tryLoad() error {
	s.storage = &storage{}
	msg, err := s.Load(storageID)
	if err != nil {
		return err
	}
	if msg == nil {
		return nil
	}
	var ok bool
	s.storage, ok = msg.(*storage)
	if !ok {
		return errors.New("data of wrong type")
	}
	return nil
}

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real deployments.
func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	if err := s.RegisterHandlers(s.HandleClientRequest); err != nil {
		log.Error(err, "Couldn't register messages")
		return nil, err
	}
	if err := s.tryLoad(); err != nil {
		log.Error(err)
		return nil, err
	}
	return s, nil
}
