// Copyright (C) 2019-2025 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package node

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

var testAddr = basics.Address{0x6, 0xda, 0xcc, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x21, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}

func followNodeDefaultGenesis() bookkeeping.Genesis {
	return bookkeeping.Genesis{
		SchemaID:    "go-test-follower-node-genesis",
		Proto:       protocol.ConsensusCurrentVersion,
		Network:     config.Devtestnet,
		FeeSink:     sinkAddr.String(),
		RewardsPool: poolAddr.String(),
		Allocation: []bookkeeping.GenesisAllocation{
			{
				Address: poolAddr.String(),
				State: bookkeeping.GenesisAccountData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000000000},
				},
			},
			{
				Address: sinkAddr.String(),
				State: bookkeeping.GenesisAccountData{
					MicroAlgos: basics.MicroAlgos{Raw: 500000},
				},
			},
			{
				Address: testAddr.String(),
				State: bookkeeping.GenesisAccountData{
					MicroAlgos: basics.MicroAlgos{Raw: 500000},
				},
			},
		},
	}
}

func setupFollowNode(t *testing.T) *AlgorandFollowerNode {
	cfg := config.GetDefaultLocal()
	cfg.EnableFollowMode = true
	genesis := followNodeDefaultGenesis()
	root := t.TempDir()
	node, err := MakeFollower(logging.Base(), root, cfg, []string{}, genesis)
	require.NoError(t, err)
	return node
}

func TestSyncRound(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	node := setupFollowNode(t)
	b := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round: 1,
		},
	}
	b.CurrentProtocol = protocol.ConsensusCurrentVersion
	err := node.Ledger().AddBlock(b, agreement.Certificate{})
	require.NoError(t, err)
	dbRound := node.Ledger().LatestTrackerCommitted()
	// Sync Round should be initialized to the ledger's dbRound + 1
	require.Equal(t, dbRound+1, node.GetSyncRound())
	// Set a new sync round
	require.NoError(t, node.SetSyncRound(dbRound+11))
	// Ensure it is persisted
	require.Equal(t, dbRound+11, node.GetSyncRound())
	// Unset the sync round and make sure get returns 0
	node.UnsetSyncRound()
	require.Zero(t, node.GetSyncRound())
}

func TestSyncRoundPerformance(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// set up the main node using the node_test code
	// const numAccounts = 1
	// acctStake := make([]basics.MicroAlgos, numAccounts)
	// acctStake[0] = basics.MicroAlgos{Raw: uint64(100000000)}

	// configHook := func(ni nodeInfo, cfg config.Local) (nodeInfo, config.Local) {
	// 	cfg = config.GetDefaultLocal()
	// 	cfg.BaseLoggerDebugLevel = uint32(logging.Debug)
	// 	if ni.idx == 0 {
	// 		// node 0 is main node
	// 		cfg.GossipFanout = 1
	// 		cfg.DNSBootstrapID = ""
	// 		cfg.IncomingConnectionsLimit = 0
	// 		cfg.Archival = true
	// 		//cfg.isIndexerActive = false
	// 		cfg.EnableDeveloperAPI = true
	// 	}

	// 	if ni.idx == 1 {
	// 		// node 1 is follower node
	// 		cfg.EnableFollowMode = true
	// 		cfg.MaxAcctLookback = 64
	// 		cfg.CatchupParallelBlocks = 64
	// 		cfg.CatchupBlockValidateMode = 3
	// 	}

	// 	return ni, cfg
	// }

	// phonebookHook := func(nodes []nodeInfo, nodeIdx int) []string {
	// 	phonebook := make([]string, 0, len(nodes)-1)
	// 	for i := range nodes {
	// 		if i != nodeIdx {
	// 			phonebook = append(phonebook, nodes[i].wsNetAddr())
	// 		}
	// 	}
	// 	return phonebook
	// }
	// nodes, wallets := setupFullNodesEx(t, protocol.ConsensusCurrentVersion, nil, acctStake, configHook, phonebookHook)
	// require.Len(t, nodes, numAccounts)
	// require.Len(t, wallets, numAccounts)

	// for i := 0; i < len(nodes); i++ {
	// 	defer os.Remove(wallets[i])
	// 	defer nodes[i].Stop()
	// }

	// startAndConnectNodes(nodes, nodelayFirstNodeStartDelay)

	// setup the main node directly
	f, _ := os.Create(t.Name() + "-main.log")
	log1 := logging.NewLogger()
	log1.SetOutput(f)
	log1.SetLevel(logging.Debug)
	log1.SetJSONFormatter()
	cfg := config.GetDefaultLocal()
	cfg.GossipFanout = 1
	cfg.DNSBootstrapID = ""
	cfg.IncomingConnectionsLimit = 0
	cfg.Archival = true
	//cfg.isIndexerActive = false
	cfg.EnableDeveloperAPI = true
	cfg.BaseLoggerDebugLevel = 5
	genesis := bookkeeping.Genesis{
		SchemaID:    "go-test-node-genesis",
		Proto:       protocol.ConsensusCurrentVersion,
		Network:     config.Devtestnet,
		FeeSink:     sinkAddr.String(),
		RewardsPool: poolAddr.String(),
		DevMode:     true,
	}
	tempDir := t.TempDir()
	mainNode, err := MakeFull(log1, tempDir, cfg, []string{}, genesis)
	require.NoError(t, err)
	err = mainNode.Start()
	require.NoError(t, err)

	// setupFollowNode
	f2, _ := os.Create(t.Name() + "-follower.log")
	log2 := logging.NewLogger()
	log2.SetOutput(f2)
	log2.SetLevel(logging.Debug)
	log2.SetJSONFormatter()
	cfg2 := config.GetDefaultLocal()
	cfg2.EnableFollowMode = true
	cfg2.MaxAcctLookback = 64
	cfg2.CatchupParallelBlocks = 64
	cfg2.CatchupBlockValidateMode = 3
	cfg2.BaseLoggerDebugLevel = 5
	genesis2 := followNodeDefaultGenesis()
	tempDir2 := t.TempDir()
	followerNode, err := MakeFollower(log2, tempDir2, cfg2, []string{}, genesis2)
	require.NoError(t, err)
	err = followerNode.Start()
	require.NoError(t, err)

	// test

	// // send a whole pile of transactions to the main node
	// // This only works if created the main node using the node_test code
	// filename := filepath.Join(nodes[0].genesisDirs.RootGenesisDir, wallets[0])
	// access, err := db.MakeAccessor(filename, false, false)
	// require.NoError(t, err)
	// root, err := account.RestoreRoot(access)
	// access.Close()
	// require.NoError(t, err)

	// addr2 := root.Address()
	// secrets2 := root.Secrets()
	// txn := transactions.Transaction{
	// 	Type: protocol.PaymentTx,
	// 	Header: transactions.Header{
	// 		Sender:      addr2,
	// 		FirstValid:  1,
	// 		LastValid:   100,
	// 		Fee:         basics.MicroAlgos{Raw: 1000},
	// 		GenesisID:   nodes[0].genesisID,
	// 		GenesisHash: nodes[0].genesisHash,
	// 	},
	// 	PaymentTxnFields: transactions.PaymentTxnFields{
	// 		Receiver: addr2,
	// 		Amount:   basics.MicroAlgos{Raw: 0},
	// 	},
	// }
	// signature := secrets2.Sign(txn)
	// stxn := transactions.SignedTxn{
	// 	Sig: signature,
	// 	Txn: txn,
	// }

	// err = nodes[0].BroadcastSignedTxGroup([]transactions.SignedTxn{stxn})
	// require.NoError(t, err)

	// // add a block to the main node
	// b := bookkeeping.Block{
	// 	BlockHeader: bookkeeping.BlockHeader{
	// 		Round: 1,
	// 	},
	// }
	// b.CurrentProtocol = protocol.ConsensusCurrentVersion
	// err = mainNode.Ledger().AddBlock(b, agreement.Certificate{})
	// require.NoError(t, err)

	// wait for the initial transactions to completed
	initialRound := mainNode.ledger.NextRound()
	targetRound := initialRound + 1
	t.Logf("Waiting for round %d (initial %d)", targetRound, initialRound)

	// ensure tx properly propagated to main node
	select {
	case <-mainNode.ledger.Wait(targetRound):
		b, err := mainNode.ledger.Block(targetRound)
		require.NoError(t, err)
		require.Greater(t, b.TxnCounter, uint64(1000)) // new initial value after AppForbidLowResources
	case <-time.After(1 * time.Minute):
		require.Fail(t, "no block notification")
	}

	dbRound := followerNode.Ledger().LatestTrackerCommitted()
	// Sync Round should be initialized to the ledger's dbRound + 1
	//require.Equal(t, dbRound+1, nodes[1].GetSyncRound())
	// Set a new sync round
	require.NoError(t, followerNode.SetSyncRound(dbRound+11))
	require.NoError(t, followerNode.SetSyncRound(dbRound+12))
	require.NoError(t, followerNode.SetSyncRound(dbRound+13))
	require.NoError(t, followerNode.SetSyncRound(dbRound+14))
	// Ensure it is persisted
	require.Equal(t, dbRound+14, followerNode.GetSyncRound())
	// Unset the sync round and make sure get returns 0
	followerNode.UnsetSyncRound()
	require.Zero(t, followerNode.GetSyncRound())

}

func TestErrors(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// Validates that expected functions are disabled
	node := setupFollowNode(t)
	require.Error(t, node.BroadcastSignedTxGroup([]transactions.SignedTxn{}))
	require.Error(t, node.BroadcastInternalSignedTxGroup([]transactions.SignedTxn{}))
	_, err := node.Simulate(simulation.Request{})
	require.Error(t, err)
	_, err = node.GetParticipationKey(account.ParticipationID{})
	require.Error(t, err)
	require.Error(t, node.RemoveParticipationKey(account.ParticipationID{}))
	require.Error(t, node.AppendParticipationKeys(account.ParticipationID{}, account.StateProofKeys{}))
	_, err = node.InstallParticipationKey([]byte{})
	require.Error(t, err)
}

func TestDevModeWarning(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cfg := config.GetDefaultLocal()
	cfg.EnableFollowMode = true
	genesis := followNodeDefaultGenesis()
	genesis.DevMode = true

	logger, hook := test.NewNullLogger()
	tlogger := logging.NewWrappedLogger(logger)
	root := t.TempDir()
	_, err := MakeFollower(tlogger, root, cfg, []string{}, genesis)
	require.NoError(t, err)

	// check for the warning
	var foundEntry *logrus.Entry
	entries := hook.AllEntries()
	for i := range entries {
		if entries[i].Level == logrus.WarnLevel {
			foundEntry = entries[i]
		}
	}
	require.NotNil(t, foundEntry)
	require.Contains(t, foundEntry.Message, "Follower running on a devMode network. Must submit txns to a different node.")
}

func TestFastCatchupResume(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	node := setupFollowNode(t)
	node.ctx = context.Background()

	// Initialize sync round to a future round.
	syncRound := basics.Round(10000)
	node.SetSyncRound(syncRound)
	require.Equal(t, syncRound, node.GetSyncRound())

	// Force catchpoint catchup mode to end, this should set the sync round to the current ledger round (0).
	out := node.SetCatchpointCatchupMode(false)
	<-out

	// Verify the sync was reset.
	assert.Zero(t, node.GetSyncRound())
}

// TestDefaultResourcePaths confirms that when no extra configuration is provided, all resources are created in the dataDir
func TestDefaultResourcePaths_Follower(t *testing.T) {
	partitiontest.PartitionTest(t)

	testDirectory := t.TempDir()

	genesis := bookkeeping.Genesis{
		SchemaID:    "go-test-node-genesis",
		Proto:       protocol.ConsensusCurrentVersion,
		Network:     config.Devtestnet,
		FeeSink:     sinkAddr.String(),
		RewardsPool: poolAddr.String(),
	}

	cfg := config.GetDefaultLocal()

	// the logger is set up by the server, so we don't test this here
	log := logging.Base()

	n, err := MakeFollower(log, testDirectory, cfg, []string{}, genesis)
	require.NoError(t, err)

	n.Start()
	defer n.Stop()

	// confirm genesis dir exists in the data dir, and that resources exist in the expected locations
	require.DirExists(t, filepath.Join(testDirectory, genesis.ID()))

	require.FileExists(t, filepath.Join(testDirectory, genesis.ID(), "ledger.tracker.sqlite"))
	require.FileExists(t, filepath.Join(testDirectory, genesis.ID(), "ledger.block.sqlite"))
}

// TestConfiguredDataDirs tests to see that when HotDataDir and ColdDataDir are set, underlying resources are created in the correct locations
// Not all resources are tested here, because not all resources use the paths provided to them immediately. For example, catchpoint only creates
// a directory when writing a catchpoint file, which is not being done here with this simple node
func TestConfiguredDataDirs_Follower(t *testing.T) {
	partitiontest.PartitionTest(t)

	testDirectory := t.TempDir()
	testDirHot := t.TempDir()
	testDirCold := t.TempDir()

	genesis := bookkeeping.Genesis{
		SchemaID:    "go-test-node-genesis",
		Proto:       protocol.ConsensusCurrentVersion,
		Network:     config.Devtestnet,
		FeeSink:     sinkAddr.String(),
		RewardsPool: poolAddr.String(),
	}

	cfg := config.GetDefaultLocal()

	cfg.HotDataDir = testDirHot
	cfg.ColdDataDir = testDirCold
	cfg.CatchpointTracking = 2
	cfg.CatchpointInterval = 1

	// the logger is set up by the server, so we don't test this here
	log := logging.Base()

	n, err := MakeFollower(log, testDirectory, cfg, []string{}, genesis)
	require.NoError(t, err)

	n.Start()
	defer n.Stop()

	// confirm hot data dir exists and contains a genesis dir
	require.DirExists(t, filepath.Join(testDirHot, genesis.ID()))

	// confirm the tracker is in the genesis dir of hot data dir
	require.FileExists(t, filepath.Join(testDirHot, genesis.ID(), "ledger.tracker.sqlite"))

	// confirm cold data dir exists and contains a genesis dir
	require.DirExists(t, filepath.Join(testDirCold, genesis.ID()))

	// confirm the blockdb is in the genesis dir of cold data dir
	require.FileExists(t, filepath.Join(testDirCold, genesis.ID(), "ledger.block.sqlite"))

}

// TestConfiguredResourcePaths tests to see that when individual paths are set, underlying resources are created in the correct locations
func TestConfiguredResourcePaths_Follower(t *testing.T) {
	partitiontest.PartitionTest(t)

	testDirectory := t.TempDir()
	testDirHot := t.TempDir()
	testDirCold := t.TempDir()

	// add a path for each resource now
	trackerPath := filepath.Join(testDirectory, "custom_tracker")
	blockPath := filepath.Join(testDirectory, "custom_block")

	genesis := bookkeeping.Genesis{
		SchemaID:    "go-test-node-genesis",
		Proto:       protocol.ConsensusCurrentVersion,
		Network:     config.Devtestnet,
		FeeSink:     sinkAddr.String(),
		RewardsPool: poolAddr.String(),
	}

	cfg := config.GetDefaultLocal()

	// Configure everything even though a follower node will only use Tracker and Block DBs
	cfg.HotDataDir = testDirHot
	cfg.ColdDataDir = testDirCold
	cfg.TrackerDBDir = trackerPath
	cfg.BlockDBDir = blockPath
	cfg.CatchpointTracking = 2
	cfg.CatchpointInterval = 1

	// the logger is set up by the server, so we don't test this here
	log := logging.Base()

	n, err := MakeFollower(log, testDirectory, cfg, []string{}, genesis)
	require.NoError(t, err)

	n.Start()
	defer n.Stop()

	// confirm hot data dir exists and contains a genesis dir
	require.DirExists(t, filepath.Join(testDirHot, genesis.ID()))

	// the tracker shouldn't be in the hot data dir, but rather the custom path's genesis dir
	require.NoFileExists(t, filepath.Join(testDirHot, genesis.ID(), "ledger.tracker.sqlite"))
	require.FileExists(t, filepath.Join(cfg.TrackerDBDir, genesis.ID(), "ledger.tracker.sqlite"))

	// confirm cold data dir exists and contains a genesis dir
	require.DirExists(t, filepath.Join(testDirCold, genesis.ID()))

	// block db shouldn't be in the cold data dir, but rather the custom path's genesis dir
	require.NoFileExists(t, filepath.Join(testDirCold, genesis.ID(), "ledger.block.sqlite"))
	require.FileExists(t, filepath.Join(cfg.BlockDBDir, genesis.ID(), "ledger.block.sqlite"))
}

func TestSimulate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	node := setupFollowNode(t)

	round := node.ledger.LastRound()

	stxn := txntest.Txn{
		Type:        protocol.PaymentTx,
		Sender:      testAddr,
		Receiver:    poolAddr,
		Amount:      1,
		Fee:         1000,
		FirstValid:  round,
		LastValid:   round + 1000,
		GenesisHash: node.ledger.GenesisHash(),
	}.SignedTxn()

	request := simulation.Request{
		TxnGroups:            [][]transactions.SignedTxn{{stxn}},
		AllowEmptySignatures: true,
	}

	result, err := node.Simulate(request)
	require.NoError(t, err)

	require.Len(t, result.TxnGroups, 1)
	require.Len(t, result.TxnGroups[0].Txns, 1)
	require.Equal(t, stxn, result.TxnGroups[0].Txns[0].Txn.SignedTxn)
	require.Empty(t, result.TxnGroups[0].FailureMessage)
}
