package protocol

import (
	"testing"
	"time"

	"github.com/si-co/dpcc/lib"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func TestHashPrivateProtocol(t *testing.T) {
	// define log visibility level
	//log.SetDebugVisible(4)

	// define URL for test
	tURL := "https://dedis.epfl.ch/"

	// test the protocol
	for _, nbrHosts := range []int{4, 6, 16} {
		log.Lvl2("testing hash private protocol with", nbrHosts, "hosts")
		local := onet.NewLocalTest(tSuite)
		_, roster, tree := local.GenBigTree(nbrHosts, nbrHosts, nbrHosts, true)

		// start the protocol
		instance, err := local.CreateProtocol(NameHashPrivate, tree)
		if err != nil {
			t.Fatal("couldn't create a new hash private protocol:", err)
		}

		// generate ephemeral public keys for all the workers
		ephemeralPrivateKeys, ephemeralPublicKeys := lib.GenEphemeralKeys(roster)

		// set parameters of the protocol
		p := instance.(*HashPrivate)
		p.URL = tURL
		p.ClientPublicKeys = ephemeralPublicKeys

		// start the protocol
		err = p.Start()
		if err != nil {
			t.Fatal("couldn't start hash private protocol:", err)
		}

		// wait the protocol to finish or trigger timeout
		select {
		case <-p.Finished:
			// results not nil
			require.NotNil(t, p.Responses)

			// store responses
			responses := p.Responses

			// check number of responses from workers
			require.Equal(t, len(roster.List)-1, len(responses))

			// decrypted the responses
			for pk, v := range responses {
				// compute previsously shared key
				pre := lib.DhExchange(ephemeralPrivateKeys[pk], v.PublicKey)
				// determine context for this AEAD scheme
				ctx := lib.Context(ephemeralPublicKeys[pk], v.PublicKey)
				// instantiate AEAD scheme (AES128-GCM)
				gcm, err := lib.NewAEAD(cothority.Suite.Hash, pre, ctx)
				require.Nil(t, err)
				// encrypt hash with AES128-GCM
				decrypted, err := gcm.Open(nil, v.Nonce, v.EncryptedHash, nil)
				require.Nil(t, err)
				require.NotNil(t, decrypted)
			}

		case <-time.After(time.Second * 5):
			t.Fatal("couldn't get private hash protocol done in time")
		}

		local.CloseAll()
	}
}
