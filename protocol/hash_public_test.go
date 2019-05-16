package protocol

import (
	"testing"
	"time"

	"github.com/si-co/dpcc/lib"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func TestHashPublicProtocol(t *testing.T) {
	// define log visibility level
	//log.SetDebugVisible(3)

	// define URL for test
	tURL := "https://dedis.epfl.ch/"

	// test the protocol
	for _, nbrHosts := range []int{4, 6, 16} {
		log.Lvl2("testing hash public protocol with", nbrHosts, "hosts")
		local := onet.NewLocalTest(tSuite)
		_, _, tree := local.GenBigTree(nbrHosts, nbrHosts, nbrHosts, true)

		nonce := lib.GenNonce()

		// start the protocol
		instance, err := local.CreateProtocol(NameHashPublic, tree)
		if err != nil {
			t.Fatal("couldn't create a new hash public protocol:", err)
		}

		// set parameters of the protocol
		p := instance.(*HashPublic)
		p.URL = tURL
		p.Nonce = nonce

		// start the protocol
		err = p.Start()
		if err != nil {
			t.Fatal("couldn's start a new hash public protocol:", err)
		}

		// wait the protocol to finish or trigger timeout
		select {
		case <-p.Finished:
			// results not nil
			require.NotNil(t, p.Hashes)
			require.NotNil(t, p.Signatures)
			require.NotNil(t, p.PublicKeys)

			// enough responses from workers
			require.Equal(t, len(p.Hashes), nbrHosts-1)
			require.Equal(t, len(p.Signatures), nbrHosts-1)
			require.Equal(t, len(p.PublicKeys), nbrHosts-1)

			// verify all the signatures, which should be correct
			for pkString, s := range p.Signatures {
				err := lib.VerifyWithNonce(p.PublicKeys[pkString], p.Hashes[pkString], nonce, s)
				require.Nil(t, err)
			}

			// print the map containing the hashes
			//			for pkString, v := range p.Hashes {
			//				hashEncoded := base64.StdEncoding.EncodeToString(v)
			//				fmt.Printf("Server with pk %s sended %s\n", pkString, hashEncoded)
			//			}

		case <-time.After(time.Second * 10):
			t.Fatal("couldn't get hash public protocol done in time")
		}

		local.CloseAll()
	}
}
