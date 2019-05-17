package service

import (
	"testing"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"

	"github.com/si-co/dpcc"
	"github.com/si-co/dpcc/lib"
	"github.com/stretchr/testify/require"
)

var tSuite = cothority.Suite

func TestHashPublicService(t *testing.T) {
	//log.SetDebugVisible(3)

	tURL := "https://dedis.epfl.ch"

	local := onet.NewLocalTest(tSuite)

	nodes, roster, _ := local.GenBigTree(6, 6, 1, true)
	s0 := local.GetServices(nodes, templateID)[0].(*Service)
	s1 := local.GetServices(nodes, templateID)[1].(*Service)
	s2 := local.GetServices(nodes, templateID)[2].(*Service)
	s3 := local.GetServices(nodes, templateID)[3].(*Service)
	s4 := local.GetServices(nodes, templateID)[4].(*Service)
	s5 := local.GetServices(nodes, templateID)[5].(*Service)
	services := []*Service{s0, s1, s2, s3, s4, s5}

	resp, err := s0.HashPublic(&dpcc.HashPublicRequest{
		Roster: roster,
		URL:    tURL,
		Nonce:  lib.GenNonce(),
	})

	// test if everything wents good
	require.Nil(t, err)
	require.NotNil(t, resp)
	require.Equal(t, len(services)-1, len(resp.Responses))

	local.CloseAll()
}

func TestHashPrivateService(t *testing.T) {
	//log.SetDebugVisible(3)

	tURL := "https://dedis.epfl.ch"

	local := onet.NewLocalTest(tSuite)

	nodes, roster, _ := local.GenBigTree(6, 6, 1, true)
	s0 := local.GetServices(nodes, templateID)[0].(*Service)
	s1 := local.GetServices(nodes, templateID)[1].(*Service)
	s2 := local.GetServices(nodes, templateID)[2].(*Service)
	s3 := local.GetServices(nodes, templateID)[3].(*Service)
	s4 := local.GetServices(nodes, templateID)[4].(*Service)
	s5 := local.GetServices(nodes, templateID)[5].(*Service)
	services := []*Service{s0, s1, s2, s3, s4, s5}

	// generate client's ephemeral keys
	privateKeys, publicKeys := lib.GenEphemeralKeys(roster)

	resp, err := s0.HashPrivate(&dpcc.HashPrivateRequest{
		Roster:           roster,
		URL:              tURL,
		ClientPublicKeys: publicKeys,
	})

	// test if everything wents good
	require.Nil(t, err)
	require.NotNil(t, resp)
	require.Equal(t, len(services)-1, len(resp.Responses))

	// try to decrypt the hashes
	for pk, v := range resp.Responses {
		// compute previsously shared key
		pre := lib.DhExchange(privateKeys[pk], v.PublicKey)
		// determine context for this AEAD scheme
		ctx := lib.Context(publicKeys[pk], v.PublicKey)
		// instantiate AEAD scheme (AES128-GCM)
		gcm, err := lib.NewAEAD(cothority.Suite.Hash, pre, ctx)
		require.Nil(t, err)
		// encrypt hash with AES128-GCM
		decrypted, err := gcm.Open(nil, v.Nonce, v.EncryptedHash, nil)
		require.Nil(t, err)
		require.NotNil(t, decrypted)
	}

	local.CloseAll()
}
