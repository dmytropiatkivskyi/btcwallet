package main

/*
import (
	"bytes"
	"fmt"
	"log"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	//"github.com/ethereum/go-ethereum/accounts/abi"
	//"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stroomnetwork/frost"
	"github.com/stroomnetwork/frost/crypto"
	"github.com/stroomnetwork/frost/storage"
)

func CreateTaprootAddressFromPubKey(pubKey *btcec.PublicKey) (*btcutil.AddressTaproot, error) {
	return btcutil.NewAddressTaproot(crypto.GetPubkeyBytes(pubKey), &chaincfg.RegressionNetParams)
}

func main() {
	connCfg := &rpcclient.ConnConfig{
		Host:         "localhost:19702",
		Endpoint:     "",
		DisableTLS:   true,
		HTTPPostMode: true,
		Params:       chaincfg.RegressionNetParams.Name,
		CookiePath:   "/tmp/bitcoin_func_test_omnujcz1/node0/regtest/.cookie",
	}
	finalAddr, err := btcutil.DecodeAddress("bcrt1quy5lrvcx6u62lv004dy4gsymp96rg3cdf2hh56", &chaincfg.RegressionNetParams)
	if err != nil {
		log.Println("Error decoding final address:", err)
		return
	}
	fmt.Println("finalAddr:", finalAddr)

	t := new(testing.T)
	N := 3
	K := 2
	validators, apRequestsArr := frost.SetupInMemoryNetworkWithGeneratedKeys(t, N, K, func() (storage.Storage, error) {
		return storage.NewInMemoryStorage(), nil
	})
	frost.AlwaysApproveStrategy(apRequestsArr)
	fmt.Println("FROST STARTED")
	fmt.Println("N:", N)
	fmt.Println("K:", K)

	groupPk1, err := validators[0].MakePubKey("seed-addr-1")
	assert.NoError(t, err)
	addr1, err := CreateTaprootAddressFromPubKey(groupPk1)
	assert.NoError(t, err)
	fmt.Printf("seed-addr-1: %v\n", addr1.String())

	fmt.Println("")

	groupPk2, err := validators[0].MakePubKey("seed-addr-2")
	assert.NoError(t, err)
	addr2, err := CreateTaprootAddressFromPubKey(groupPk2)
	assert.NoError(t, err)
	fmt.Printf("seed-addr-2: %v\n", addr2.String())

	fmt.Println("")

	ethAddrStr := "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
	// reader := bufio.NewReader(os.Stdin)
	// fmt.Print("Enter ethAddr: ")
	// ethAddrStr, _ := reader.ReadString('\n')
	// fmt.Println("ethAddrStr", ethAddrStr)

	ethAddr := common.HexToAddress(ethAddrStr)
	fmt.Printf("ethAddr: %v\n", ethAddrStr)

	uint256Ty, _ := abi.NewType("uint256", "uint256", nil)
	addressTy, _ := abi.NewType("address", "address", nil)

	arguments := abi.Arguments{
		{
			Type: uint256Ty,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: addressTy,
		},
	}

	b1, _ := arguments.Pack(
		groupPk1.X(),
		groupPk1.Y(),
		ethAddr,
	)
	h1 := crypto.Sha256(b1)
	c1FromAddr, _ := crypto.PrivkeyFromBytes(h1[:])
	fmt.Printf("c1FromAddr: 0x%X\n", c1FromAddr.ToECDSA().D)

	b2, _ := arguments.Pack(
		groupPk2.X(),
		groupPk2.Y(),
		ethAddr,
	)
	h2 := crypto.Sha256(b2)
	c2FromAddr, _ := crypto.PrivkeyFromBytes(h2[:])
	fmt.Printf("c2FromAddr: 0x%X\n", c2FromAddr.ToECDSA().D)
	fmt.Println("")

	pkFromAddr := crypto.AddPubkey(
		crypto.MulPubkey(groupPk1, c1FromAddr),
		crypto.MulPubkey(groupPk2, c2FromAddr),
	)

	fmt.Println("pkFromAddr = c1FromAddr*pk1 + c2FromAddr*pk2")
	fmt.Printf("pkFromAddr.X: 0x%X\n", pkFromAddr.X())
	fmt.Printf("pkFromAddr.Y: 0x%X\n", pkFromAddr.Y())

	addr, err := btcutil.NewAddressTaproot(crypto.GetPubkeyBytes(pkFromAddr), &chaincfg.RegressionNetParams)
	assert.NoError(t, err)

	fmt.Printf("addr: %v\n", addr.String())

	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		log.Println("Error connecting to bitcoind:", err)
		return
	}
	defer client.Shutdown()

	// Get the current block count
	blockCount, err := client.GetBlockCount()
	if err != nil {
		log.Println("Error getting block count:", err)
		return
	}

	log.Println("Current block count:", blockCount)
	blockHash, err := client.GetBlockHash(blockCount)
	if err != nil {
		log.Println("Error getting block hash:", err)
		return
	}
	log.Println("Current block hash:", blockHash)

	expectedLockScript := append([]byte{0x50 + 1, 32}, crypto.GetPubkeyBytes(pkFromAddr)...)

	block, err := client.GetBlock(blockHash)
	if err != nil {
		log.Println("Error getting block:", err)
		return
	}

	foundTx := (*wire.MsgTx)(nil)
	foundTxOutIndex := -1
	for itx, tx := range block.Transactions {
		fmt.Println(itx, tx.TxHash())
		for iTxOut, txOut := range tx.TxOut {
			fmt.Println()
			fmt.Println("    ", txOut.Value)
			fmt.Println("    ", len(txOut.PkScript), txOut.PkScript)
			if bytes.Equal(txOut.PkScript, expectedLockScript) {
				fmt.Println("    ", "Found the expected lock script")
				foundTx = tx
				foundTxOutIndex = iTxOut
			}
			fmt.Println()
		}
	}
	if foundTx == nil {
		log.Println("Error: expected lock script not found")
		return
	}

	fmt.Println("foundTx:", foundTx.TxHash())
	fmt.Println("foundTxOutIndex:", foundTxOutIndex)
	foundTxOut := foundTx.TxOut[foundTxOutIndex]
	fee := btcutil.Amount(10_000)

	finalAddrScript, err := txscript.PayToAddrScript(finalAddr)
	if err != nil {
		log.Println("Error getting final address script:", err)
		return
	}
	fmt.Println("finalAddrScript:", finalAddrScript)

	prevOutPoint := wire.OutPoint{
		Hash:  foundTx.TxHash(),
		Index: uint32(foundTxOutIndex),
	}
	tx := wire.NewMsgTx(2)
	tx.TxIn = []*wire.TxIn{{
		PreviousOutPoint: prevOutPoint,
	}}
	value := int64(btcutil.Amount(foundTx.TxOut[foundTxOutIndex].Value) - fee)
	tx.TxOut = []*wire.TxOut{{
		PkScript: finalAddrScript,
		Value:    value,
	}}

	hashType := txscript.SigHashDefault
	prevFetcher := txscript.NewCannedPrevOutputFetcher(foundTxOut.PkScript, foundTxOut.Value)
	sigHashes := txscript.NewTxSigHashes(tx, prevFetcher)

	// Next code is slightly modified from txscript.RawTxInTaprootSignature
	// We assume that transaction has only one input.
	sigHash, err := txscript.CalcTaprootSignatureHash(
		sigHashes, hashType, tx, 0,
		prevFetcher,
	)
	if err != nil {
		log.Println("Error calculating signature hash:", err)
		return
	}
	fmt.Println("sigHash:", sigHash)

	lc, err := crypto.NewLinearCombination(
		[]*btcec.PublicKey{groupPk1, groupPk2},
		[]*btcec.PrivateKey{c1FromAddr, c2FromAddr},
		crypto.PrivKeyFromInt(0),
	)
	if err != nil {
		log.Println("Error creating linear combination:", err)
		return
	}
	msd := &crypto.MultiSignatureDescriptor{
		SignDescriptors: []*crypto.LinearSignDescriptor{
			{
				MsgHash: sigHash,
				LC:      lc,
			},
		},
	}
	sigs, err := validators[0].SignAdvanced(msd)
	if err != nil {
		log.Println("Error signing:", err)
		return
	}
	fmt.Println("sigs[0]:", sigs[0].Serialize())

	tx.TxIn[0].Witness = wire.TxWitness{
		sigs[0].Serialize(),
	}

	newTxHash, err := client.SendRawTransaction(tx, true)
	if err != nil {
		log.Println("Error sending transaction:", err)
		return
	}
	fmt.Println("newTxHash:", newTxHash)

	for i := 0; i < N; i++ {
		assert.NoError(t, validators[i].Stop())
	}
}
*/
