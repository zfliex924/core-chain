package systemcontracts

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

type UpgradeConfig struct {
	BeforeUpgrade upgradeHook
	AfterUpgrade  upgradeHook
	ContractAddr  common.Address
	CommitUrl     string
	Code          string
}

type Upgrade struct {
	UpgradeName string
	Configs     []*UpgradeConfig
}

type upgradeHook func(blockNumber *big.Int, contractAddr common.Address, statedb vm.StateDB) error

const (
	mainNet    = "Mainnet"
	pigeonNet  = "Pigeon"
	defaultNet = "Default"
)

const ()

var (
	GenesisHash common.Hash
	//upgrade config
	hashPowerUpgrade = make(map[string]*Upgrade)

	zeusUpgrade = make(map[string]*Upgrade)

	heraUpgrade = make(map[string]*Upgrade)

	poseidonUpgrade = make(map[string]*Upgrade)

	demeterUpgrade = make(map[string]*Upgrade)

	athenaUpgrade = make(map[string]*Upgrade)

	theseusUpgrade = make(map[string]*Upgrade)

	hermesUpgrade = make(map[string]*Upgrade)
)

func init() {
	// All historical upgrade configurations have been removed for z-chain.
	// New upgrade configurations will be added here when contract bytecodes are ready.
}

func TryUpdateBuildInSystemContract(config *params.ChainConfig, blockNumber *big.Int, lastBlockTime uint64, blockTime uint64, statedb vm.StateDB, atBlockBegin bool) {
	if atBlockBegin {
		if !config.IsHermes(blockNumber, lastBlockTime) {
			upgradeBuildInSystemContract(config, blockNumber, lastBlockTime, blockTime, statedb)
		}
		// HistoryStorageAddress is a special system contract in bsc, which can't be upgraded
		if config.IsOnPrague(blockNumber, lastBlockTime, blockTime) {
			statedb.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode)
			statedb.SetNonce(params.HistoryStorageAddress, 1, tracing.NonceChangeNewContract)
			log.Info("Set code for HistoryStorageAddress", "blockNumber", blockNumber.Int64(), "blockTime", blockTime)
		}
	} else {
		if config.IsHermes(blockNumber, lastBlockTime) {
			upgradeBuildInSystemContract(config, blockNumber, lastBlockTime, blockTime, statedb)
		}
	}
}

func upgradeBuildInSystemContract(config *params.ChainConfig, blockNumber *big.Int, lastBlockTime uint64, blockTime uint64, statedb vm.StateDB) {
	if config == nil || blockNumber == nil || statedb == nil || reflect.ValueOf(statedb).IsNil() {
		return
	}

	var network string
	switch GenesisHash {
	/* Add mainnet genesis hash */
	case params.CoreGenesisHash:
		network = mainNet
	case params.PigeonGenesisHash:
		network = pigeonNet
	default:
		network = defaultNet
	}

	logger := log.New("system-contract-upgrade", network)
	/*
		apply other upgrades
	*/
	_ = logger
	_ = hashPowerUpgrade
	_ = zeusUpgrade
	_ = heraUpgrade
	_ = poseidonUpgrade
	_ = demeterUpgrade
	_ = athenaUpgrade
	_ = theseusUpgrade
	_ = hermesUpgrade
}

func applySystemContractUpgrade(upgrade *Upgrade, blockNumber *big.Int, statedb vm.StateDB, logger log.Logger) {
	if upgrade == nil {
		logger.Info("Empty upgrade config", "height", blockNumber.String())
		return
	}

	logger.Info(fmt.Sprintf("Apply upgrade %s at height %d", upgrade.UpgradeName, blockNumber.Int64()))
	for _, cfg := range upgrade.Configs {
		logger.Info(fmt.Sprintf("Upgrade contract %s to commit %s", cfg.ContractAddr.String(), cfg.CommitUrl))

		if cfg.BeforeUpgrade != nil {
			err := cfg.BeforeUpgrade(blockNumber, cfg.ContractAddr, statedb)
			if err != nil {
				panic(fmt.Errorf("contract address: %s, execute beforeUpgrade error: %s", cfg.ContractAddr.String(), err.Error()))
			}
		}

		newContractCode, err := hex.DecodeString(strings.TrimSpace(cfg.Code))
		if err != nil {
			panic(fmt.Errorf("failed to decode new contract code: %s", err.Error()))
		}
		statedb.SetCode(cfg.ContractAddr, newContractCode)

		if cfg.AfterUpgrade != nil {
			err := cfg.AfterUpgrade(blockNumber, cfg.ContractAddr, statedb)
			if err != nil {
				panic(fmt.Errorf("contract address: %s, execute afterUpgrade error: %s", cfg.ContractAddr.String(), err.Error()))
			}
		}
	}
}
