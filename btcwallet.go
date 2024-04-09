// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/frost"
	"github.com/btcsuite/btcwallet/rpc/legacyrpc"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightninglabs/neutrino"
	"net"
	"net/http"
	_ "net/http/pprof" // nolint:gosec
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

var (
	cfg *config
)

func main() {
	// Use all processor cores.
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Work around defer not working after os.Exit.
	if err := walletMain(); err != nil {
		os.Exit(1)
	}
}

// walletMain is a work-around main function that is required since deferred
// functions (such as log flushing) are not called with calls to os.Exit.
// Instead, main runs this function and checks for a non-nil error, at which
// point any defers have already run, and if the error is non-nil, the program
// can be exited with an error exit status.
func walletMain() error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	tcfg, _, err := loadConfig()
	if err != nil {
		return err
	}
	cfg = tcfg
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	// Show version at startup.
	log.Infof("Version %s", version())

	if cfg.Profile != "" {
		go func() {
			listenAddr := net.JoinHostPort("", cfg.Profile)
			log.Infof("Profile server listening on %s", listenAddr)
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			log.Errorf("%v", http.ListenAndServe(listenAddr, nil))
		}()
	}

	dbDir := networkDir(cfg.AppDataDir.Value, activeNet.Params)
	loader := wallet.NewLoader(
		activeNet.Params, dbDir, true, cfg.DBTimeout, 250,
	)

	// Create and start HTTP server to serve wallet client connections.
	// This will be updated with the wallet and chain server RPC client
	// created below after each is created.
	rpcs, legacyRPCServer, listeners, err := startRPCServers(loader)
	if err != nil {
		log.Errorf("Unable to create RPC servers: %v", err)
		return err
	}

	// Create and start chain RPC client so it's ready to connect to
	// the wallet when loaded later.
	if !cfg.NoInitialLoad {
		go rpcClientConnectLoop(legacyRPCServer, loader)
	}

	loader.RunAfterLoad(func(w *wallet.Wallet) {
		startWalletRPCServices(w, rpcs, legacyRPCServer)
	})

	var w *wallet.Wallet
	if !cfg.NoInitialLoad {
		// Load the wallet database.  It must have been created already
		// or this will return an appropriate error.
		w, err = loader.OpenExistingWallet([]byte(cfg.WalletPass), true)
		if err != nil {
			log.Error(err)
			return err
		}
	}

	if listeners != nil && rpcs != nil {
		for _, lis := range listeners {
			lis := lis
			go func() {
				log.Infof("Experimental RPC server listening on %s",
					lis.Addr())
				err := rpcs.Serve(lis)
				log.Tracef("Finished serving expimental RPC: %v",
					err)
			}()
		}
	}
	// Add interrupt handlers to shutdown the various process components
	// before exiting.  Interrupt handlers run in LIFO order, so the wallet
	// (which should be closed last) is added first.
	addInterruptHandler(func() {
		err := loader.UnloadWallet()
		if err != nil && err != wallet.ErrNotLoaded {
			log.Errorf("Failed to close wallet: %v", err)
		}
	})
	if rpcs != nil {
		addInterruptHandler(func() {
			// TODO: Does this need to wait for the grpc server to
			// finish up any requests?
			log.Warn("Stopping RPC server...")
			rpcs.Stop()
			log.Info("RPC server shutdown")
		})
	}
	if legacyRPCServer != nil {
		addInterruptHandler(func() {
			log.Warn("Stopping legacy RPC server...")
			legacyRPCServer.Stop()
			log.Info("Legacy RPC server shutdown")
		})
		go func() {
			<-legacyRPCServer.RequestProcessShutdown()
			simulateInterrupt()
		}()
	}

	if w != nil {
		go stroom(w)
	}

	<-interruptHandlersDone
	log.Info("Shutdown complete")
	return nil
}

// rpcClientConnectLoop continuously attempts a connection to the consensus RPC
// server.  When a connection is established, the client is used to sync the
// loaded wallet, either immediately or when loaded at a later time.
//
// The legacy RPC is optional.  If set, the connected RPC client will be
// associated with the server for RPC passthrough and to enable additional
// methods.
func rpcClientConnectLoop(legacyRPCServer *legacyrpc.Server, loader *wallet.Loader) {
	var certs []byte
	if !cfg.UseSPV {
		certs = readCAFile()
	}

	for {
		var (
			chainClient chain.Interface
			err         error
		)

		if cfg.UseSPV {
			var (
				chainService *neutrino.ChainService
				spvdb        walletdb.DB
			)
			netDir := networkDir(cfg.AppDataDir.Value, activeNet.Params)
			spvdb, err = walletdb.Create(
				"bdb", filepath.Join(netDir, "neutrino.db"),
				true, cfg.DBTimeout,
			)
			if err != nil {
				log.Errorf("Unable to create Neutrino DB: %s", err)
				continue
			}
			defer spvdb.Close()
			chainService, err = neutrino.NewChainService(
				neutrino.Config{
					DataDir:      netDir,
					Database:     spvdb,
					ChainParams:  *activeNet.Params,
					ConnectPeers: cfg.ConnectPeers,
					AddPeers:     cfg.AddPeers,
				})
			if err != nil {
				log.Errorf("Couldn't create Neutrino ChainService: %s", err)
				continue
			}
			chainClient = chain.NewNeutrinoClient(activeNet.Params, chainService)
			err = chainClient.Start()
			if err != nil {
				log.Errorf("Couldn't start Neutrino client: %s", err)
			}
		} else {
			chainClient, err = startChainRPC(certs)
			if err != nil {
				log.Errorf("Unable to open connection to consensus RPC server: %v", err)
				continue
			}
		}

		// Rather than inlining this logic directly into the loader
		// callback, a function variable is used to avoid running any of
		// this after the client disconnects by setting it to nil.  This
		// prevents the callback from associating a wallet loaded at a
		// later time with a client that has already disconnected.  A
		// mutex is used to make this concurrent safe.
		associateRPCClient := func(w *wallet.Wallet) {
			w.SynchronizeRPC(chainClient)
			if legacyRPCServer != nil {
				legacyRPCServer.SetChainServer(chainClient)
			}
		}
		mu := new(sync.Mutex)
		loader.RunAfterLoad(func(w *wallet.Wallet) {
			mu.Lock()
			associate := associateRPCClient
			mu.Unlock()
			if associate != nil {
				associate(w)
			}
		})

		chainClient.WaitForShutdown()

		mu.Lock()
		associateRPCClient = nil
		mu.Unlock()

		loadedWallet, ok := loader.LoadedWallet()
		if ok {
			// Do not attempt a reconnect when the wallet was
			// explicitly stopped.
			if loadedWallet.ShuttingDown() {
				return
			}

			loadedWallet.SetChainSynced(false)

			// TODO: Rework the wallet so changing the RPC client
			// does not require stopping and restarting everything.
			loadedWallet.Stop()
			loadedWallet.WaitForShutdown()
			loadedWallet.Start()
		}
	}
}

func readCAFile() []byte {
	// Read certificate file if TLS is not disabled.
	var certs []byte
	if !cfg.DisableClientTLS {
		var err error
		certs, err = os.ReadFile(cfg.CAFile.Value)
		if err != nil {
			log.Warnf("Cannot open CA file: %v", err)
			// If there's an error reading the CA file, continue
			// with nil certs and without the client connection.
			certs = nil
		}
	} else {
		log.Info("Chain server RPC TLS is disabled")
	}

	return certs
}

// startChainRPC opens a RPC client connection to a btcd server for blockchain
// services.  This function uses the RPC options from the global config and
// there is no recovery in case the server is not available or if there is an
// authentication error.  Instead, all requests to the client will simply error.
func startChainRPC(certs []byte) (*chain.RPCClient, error) {
	log.Infof("Attempting RPC client connection to %v", cfg.RPCConnect)
	rpcc, err := chain.NewRPCClient(activeNet.Params, cfg.RPCConnect,
		cfg.BtcdUsername, cfg.BtcdPassword, certs, cfg.DisableClientTLS, 0)
	if err != nil {
		return nil, err
	}
	err = rpcc.Start()
	return rpcc, err
}

func stroom(w *wallet.Wallet) {

	time.Sleep(1 * time.Second)
	_ = w.Unlock([]byte("passphrase"), time.After(10*time.Minute))

	// -------------- Account ----------------
	accounts, err := w.Accounts(waddrmgr.KeyScopeBIP0086)
	if err != nil {
		fmt.Println(err)
		return
	}
	log.Info("account: ", accounts)

	// -------------- Import frost pk ----------------
	validators := frost.GetValidators(5, 3)
	pubKey, err := validators[0].MakePubKey("test")
	keyHex := hex.EncodeToString(pubKey.SerializeCompressed())
	log.Info("FROST key: ", keyHex)

	/*p2shAddr, _ := txscript.PayToTaprootScript(pubKey)
	_, address, _, err := txscript.ExtractPkScriptAddrs(p2shAddr, &chaincfg.SimNetParams)*/

	//manager, err := w.Manager.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0086) //.toImportedPublicManagedAddress
	//address, err := manager.toImportedPublicManagedAddress(pubKey, false)
	//manager.ImportTaprootScript(p2shAddr, pubKey)
	//log.Info("FROST address: ", address.Address())
	a, _ := btcutil.DecodeAddress("sb1pa2kpsgstqhxk3qfn6s8smt6k4sr984vn2aw4lcqzusgvkwxkpvnsu7u840", &chaincfg.SimNetParams)
	pk, err := w.PubKeyForAddress(a)
	log.Info("PubKeyForAddress: ", pk)
	acc, err := w.AccountOfAddress(a)
	log.Info("acc: ", acc)
	/*err = w.ImportPublicKey(pubKey, waddrmgr.TaprootPubKey)
	if err != nil {
		fmt.Println(err)
		return
	}*/

	//accountOfAddress, err := w.AccountOfAddress(addr)
	/*balances, err := w.CalculateAccountBalances(0, 0)
	if err != nil {
		fmt.Println(err)
		return
	}
	log.Info("balances: ", balances)*/

	//txHash, err := chainhash.NewHashFromStr("bfe95a6a953808aa05637947434b6f3ef1c97957d31302b33a37726a64a02717")
	/*txHash, err := chainhash.NewHashFromStr("1bfaed0aca3f902b5cc0e3a20e5a9f799328b6bf1a1d650c3b688b061561bc65")
	log.Info("hash: ", txHash)

	txDetails, err := wallet.UnstableAPI(w).TxDetails(txHash)
	log.Info("txDetails: ", txDetails)*/

	/*	log.Info("Frost key: ", hex.EncodeToString(pubKey.SerializeCompressed()))
		p2shAddr, err := txscript.PayToTaprootScript(pubKey)*/
	//accountOfAddress, err := w.AccountOfAddress(addr)

	/*p2shAddr, err := txscript.PayToTaprootScript(pubKey)
	txOut := wire.NewTxOut(10000000000, p2shAddr)*/

	/**/

	action := 2

	if action < 3 {

		var simpleTx *txauthor.AuthoredTx

		if action == 1 {
			/*addr, _ := btcutil.DecodeAddress("sb1pa2kpsgstqhxk3qfn6s8smt6k4sr984vn2aw4lcqzusgvkwxkpvnsu7u840", &chaincfg.SimNetParams)
			p2shAddr, _ := txscript.PayToAddrScript(addr)
			txOut := wire.NewTxOut(1000000000, p2shAddr)*/
			p2shAddr, _ := txscript.PayToTaprootScript(pubKey)
			txOut := wire.NewTxOut(10000000000, p2shAddr)
			simpleTx, err = w.CreateSimpleTx(&waddrmgr.KeyScopeBIP0044, 0, []*wire.TxOut{txOut}, 1, 1000, wallet.CoinSelectionLargest, false)
		} else {
			addr, _ := btcutil.DecodeAddress("SYrNq34ykQAdECpbfST4t9FfY61ANP4Mfb", &chaincfg.SimNetParams)
			p2shAddr, _ := txscript.PayToAddrScript(addr)
			txOut := wire.NewTxOut(1000000, p2shAddr)
			simpleTx, err = w.CreateSimpleTx(&waddrmgr.KeyScopeBIP0086, accounts.Accounts[1].AccountNumber, []*wire.TxOut{txOut}, 1, 1000, wallet.CoinSelectionLargest, false)
		}

		if err != nil {
			fmt.Println(err)
			return
		}
		log.Info("simpleTx: ", simpleTx)
		err = w.PublishTransaction(simpleTx.Tx, "")
	}
	if action == 3 {
		addr, _ := btcutil.DecodeAddress("SR9zEMt5qG7o1Q7nGcLPCMqv5BrNHcw2zi", &chaincfg.SimNetParams)
		finalAddrScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			log.Info("Error getting final pk script:", err)
			return
		}
		fmt.Println("finalAddrScript:", finalAddrScript)

		txHash, err := chainhash.NewHashFromStr("1356cb3e2eaddb56429327d41b6ff5aed2dcc1c5580f2bdc37e05069c0d4f8eb")
		log.Info("hash: ", txHash)

		txDetails, err := wallet.UnstableAPI(w).TxDetails(txHash)
		log.Info("txDetails: ", txDetails)

		index := 1
		prevOutPoint := wire.OutPoint{
			Hash:  txDetails.Hash,
			Index: uint32(index),
		}
		tx := wire.NewMsgTx(2)
		tx.TxIn = []*wire.TxIn{{
			PreviousOutPoint: prevOutPoint,
		}}
		tx.TxOut = []*wire.TxOut{{
			PkScript: finalAddrScript,
			Value:    txDetails.MsgTx.TxOut[index].Value - 10_000,
		}}

		hashType := txscript.SigHashDefault
		prevFetcher := txscript.NewCannedPrevOutputFetcher(txDetails.MsgTx.TxOut[index].PkScript, txDetails.MsgTx.TxOut[index].Value)
		sigHashes := txscript.NewTxSigHashes(tx, prevFetcher)

		sigHash, err := txscript.CalcTaprootSignatureHash(
			sigHashes, hashType, tx, 0,
			prevFetcher,
		)
		if err != nil {
			log.Info("Error calculating signature hash:", err)
			return
		}
		log.Info("sigHash:", sigHash)

		sig, err := validators[0].Sign(sigHash, pubKey)
		log.Info("sig:", sig.Serialize())
		if err != nil {
			log.Info("Error signing:", err)
			return
		}
		log.Info("sigs[0]:", sig.Serialize())

		tx.TxIn[0].Witness = wire.TxWitness{
			sig.Serialize(),
		}

		err = w.PublishTransaction(tx, "")
		if err != nil {
			log.Info("Error publishing tx:", err)
			return
		}
	}
}
