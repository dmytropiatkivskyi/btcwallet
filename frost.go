// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stroomnetwork/frost"
	"github.com/stroomnetwork/frost/approver"
	frostConfig "github.com/stroomnetwork/frost/config"
	"github.com/stroomnetwork/frost/crypto"
	"github.com/stroomnetwork/frost/networking"
	"github.com/stroomnetwork/frost/storage"
	_ "net/http/pprof" // nolint:gosec
	"time"
)

type ApprovalRequests struct {
	ChApprovalRequests chan *approver.ApprovalRequest
}

func NewApprovalRequests() *ApprovalRequests {
	return &ApprovalRequests{
		ChApprovalRequests: make(chan *approver.ApprovalRequest),
	}
}

func getValidators(n int, k int) []*frost.Signer {
	createStorageFunc := func() (storage.Storage, error) {
		return storage.NewInMemoryStorage(), nil
	}

	validators := SetupInMemoryNetworkWithGeneratedKeys(n, k, createStorageFunc)
	//frost.alwaysApproveStrategy(apRequestsArr)

	return validators
}

func SetupInMemoryNetworkWithGeneratedKeys(n int, k int, createStorage func() (storage.Storage, error)) []*frost.Signer {

	pubKeys := make([]*btcec.PublicKey, n)
	privKeys := make([]*btcec.PrivateKey, n)
	for i := 0; i < n; i++ {
		// generate pubKeys and privKeys of validators
		privKeys[i], pubKeys[i] = crypto.GetDeterministicKeysBip340(fmt.Sprintf("Test-key-%d", i))
	}

	nodes, bindingInfos := SetupInMemoryNetwork(k, pubKeys, privKeys)

	return createSigners(createStorage, nodes, bindingInfos)
}

func createSigners(createStorage func() (storage.Storage, error), nodes []networking.Node, bindingInfos []frostConfig.BindingInfo) []*frost.Signer {
	n := len(nodes)
	signers := make([]*frost.Signer, n)
	for i := 0; i < n; i++ {
		st, _ := createStorage()

		apRequests := NewApprovalRequests()
		signerParams := &frost.SignerParameters{
			SignerConfig:          frost.DefaultConfig(),
			Node:                  nodes[i],
			BindingInfo:           &bindingInfos[i],
			Storage:               st,
			ChKeyApprovalRequests: apRequests.ChApprovalRequests,
		}

		approver.AlwaysApprove(apRequests.ChApprovalRequests)

		// signers[i] is the validator(or frost signer).
		signers[i], _ = frost.CreateSigner(signerParams)
		_ = signers[i].Start()
	}
	time.Sleep(10 * time.Millisecond)

	return signers
}

func SetupInMemoryNetworkWithProvidedKeys(k int) ([]networking.Node, []frostConfig.BindingInfo) {

	privKeys := crypto.GetTestPrivateKeys()
	n := len(privKeys)

	pubKeys := make([]*btcec.PublicKey, n)
	for i := 0; i < n; i++ {
		pubKeys[i] = privKeys[i].PubKey()
	}

	return SetupInMemoryNetwork(k, pubKeys, privKeys)
}

func SetupInMemoryNetwork(k int, pubKeys []*btcec.PublicKey, privKeys []*btcec.PrivateKey) ([]networking.Node, []frostConfig.BindingInfo) {
	n := len(pubKeys)
	network := networking.NewInMemoryNetwork()
	nodes := make([]networking.Node, n)

	for i := 0; i < n; i++ {
		nodes[i], _ = network.NewNode(pubKeys[i])
	}

	bindingInfos := make([]frostConfig.BindingInfo, n)
	for i := 0; i < n; i++ {
		// bindingConfig contains information about the binding of this validator to the validators network.
		bindingConfig := frostConfig.NewBindingConfig(privKeys[i], pubKeys, k)

		// bi is the binding information of this validator.
		// it is used for the generation of the bound keys which are the original keys modified with this specific network information)
		bi, _ := bindingConfig.GetBindingInfo()
		bindingInfos[i] = *bi
	}
	return nodes, bindingInfos
}
