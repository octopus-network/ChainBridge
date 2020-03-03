// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package ethereum

import (
	"testing"

	emitter "github.com/ChainSafe/ChainBridgeV2/contracts/Emitter"
	"github.com/ChainSafe/ChainBridgeV2/keystore"

	ethcmn "github.com/ethereum/go-ethereum/common"
)

func newLocalConnection(t *testing.T, emitter ethcmn.Address) *Connection {

	cfg := &Config{
		endpoint: TestEndpoint,
		receiver: TestCentrifugeContractAddress,
		keystore: keystore.TestKeyStoreMap[keystore.AliceKey],
		from:     keystore.AliceKey,
	}

	conn := NewConnection(cfg)
	err := conn.Connect()
	if err != nil {
		t.Fatal(err)
	}

	return conn
}

// TODO: See TestListenerAndWriter
// test handler function for events
// func testTransferHandler(logi interface{}) msg.Message {
// 	log := logi.(ethtypes.Log)
// 	hash := [32]byte(log.Topics[1])
// 	return msg.Message{
// 		Destination: msg.EthereumId,
// 		Type:        msg.AssetTransferType,
// 		Data:        hash[:],
// 	}
// }

func createTestEmitterContract(t *testing.T, conn *Connection) *emitter.EmitterFilterer {
	addressBytes := TestEmitterContractAddress.Bytes()

	address := [20]byte{}
	copy(address[:], addressBytes)

	contract, err := emitter.NewEmitter(address, conn.conn)
	if err != nil {
		t.Fatal(err)
	}

	return &contract.EmitterFilterer
}

func TestEvent(t *testing.T) {
	conn := newLocalConnection(t, TestCentrifugeContractAddress)
	defer conn.Close()

	emitterContract := createTestEmitterContract(t, conn)
	listener := NewListener(conn, testConfig)
	listener.SetEmitterContract(emitterContract)

}

func TestListener(t *testing.T) {

	conn := NewConnection(testConfig)
	err := conn.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	emitterContract := createTestEmitterContract(t, conn)
	listener := NewListener(conn, testConfig)
	listener.SetEmitterContract(emitterContract)

	err = listener.Start()

	if err != nil {
		t.Fatalf("Listener unable to start.")
	}

	TestWriter_createDepositProposal(t)

}

// func TestListenerAndWriter(t *testing.T) {
// 	// TODO: Unclear what this is supposed to test
// 	conn := newLocalConnection(t, TestEmitterContractAddress)
// 	defer conn.Close()

// 	// setup writer and router
// 	writer := NewWriter(conn, testConfig)
// 	r := router.NewRouter()
// 	r.Listen(msg.EthereumId, writer)

// 	currBlock, err := conn.LatestBlock()
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	nonce, err := conn.NonceAt(TestAddress, currBlock.Number())
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	event := EventSig("Transfer(address,bytes32)")

// 	listener := NewListener(conn, testConfig)
// 	listener.SetRouter(r)
// 	err = listener.RegisterEventHandler(string(event), testTransferHandler)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer listener.Unsubscribe(event)

// 	// calling fallback in Emitter to trigger Transfer event
// 	tx := ethtypes.NewTransaction(
// 		nonce,
// 		TestEmitterContractAddress,
// 		big.NewInt(0),
// 		1000000,        // gasLimit
// 		big.NewInt(10), // gasPrice
// 		[]byte{},
// 	)

// 	data, err := tx.MarshalJSON()
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	// subscribe to event in Centrifuge receiver contract
// 	query := listener.buildQuery(TestEmitterContractAddress, EventSig("AssetStored(bytes32)"))
// 	subscription, err := conn.subscribeToEvent(query)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	// send tx to trigger event
// 	err = conn.SubmitTx(data)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	select {
// 	case evt := <-subscription.ch:
// 		t.Log("got event", evt)
// 	case <-time.After(TestTimeout):
// 		t.Fatal("Timed out")
// 	}
// }
