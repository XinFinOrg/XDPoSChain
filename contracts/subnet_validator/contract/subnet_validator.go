// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contract

import (
	"math/big"
	"strings"

	ethereum "github.com/XinFinOrg/XDPoSChain"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/event"
)

// SafeMathABI is the input ABI used to generate the binding from.
const SafeMathABI = "[]"

// SafeMathBin is the compiled bytecode used for deploying new contracts.
const SafeMathBin = `0x604c602c600b82828239805160001a60731460008114601c57601e565bfe5b5030600052607381538281f30073000000000000000000000000000000000000000030146060604052600080fd00a165627a7a72305820b9407d48ebc7efee5c9f08b3b3a957df2939281f5913225e8c1291f069b900490029`

// DeploySafeMath deploys a new Ethereum contract, binding an instance of SafeMath to it.
func DeploySafeMath(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *SafeMath, error) {
	parsed, err := abi.JSON(strings.NewReader(SafeMathABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(SafeMathBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &SafeMath{SafeMathCaller: SafeMathCaller{contract: contract}, SafeMathTransactor: SafeMathTransactor{contract: contract}, SafeMathFilterer: SafeMathFilterer{contract: contract}}, nil
}

// SafeMath is an auto generated Go binding around an Ethereum contract.
type SafeMath struct {
	SafeMathCaller     // Read-only binding to the contract
	SafeMathTransactor // Write-only binding to the contract
	SafeMathFilterer   // Log filterer for contract events
}

// SafeMathCaller is an auto generated read-only Go binding around an Ethereum contract.
type SafeMathCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SafeMathTransactor is an auto generated write-only Go binding around an Ethereum contract.
type SafeMathTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SafeMathFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type SafeMathFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SafeMathSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type SafeMathSession struct {
	Contract     *SafeMath         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// SafeMathCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type SafeMathCallerSession struct {
	Contract *SafeMathCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// SafeMathTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type SafeMathTransactorSession struct {
	Contract     *SafeMathTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// SafeMathRaw is an auto generated low-level Go binding around an Ethereum contract.
type SafeMathRaw struct {
	Contract *SafeMath // Generic contract binding to access the raw methods on
}

// SafeMathCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type SafeMathCallerRaw struct {
	Contract *SafeMathCaller // Generic read-only contract binding to access the raw methods on
}

// SafeMathTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type SafeMathTransactorRaw struct {
	Contract *SafeMathTransactor // Generic write-only contract binding to access the raw methods on
}

// NewSafeMath creates a new instance of SafeMath, bound to a specific deployed contract.
func NewSafeMath(address common.Address, backend bind.ContractBackend) (*SafeMath, error) {
	contract, err := bindSafeMath(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &SafeMath{SafeMathCaller: SafeMathCaller{contract: contract}, SafeMathTransactor: SafeMathTransactor{contract: contract}, SafeMathFilterer: SafeMathFilterer{contract: contract}}, nil
}

// NewSafeMathCaller creates a new read-only instance of SafeMath, bound to a specific deployed contract.
func NewSafeMathCaller(address common.Address, caller bind.ContractCaller) (*SafeMathCaller, error) {
	contract, err := bindSafeMath(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &SafeMathCaller{contract: contract}, nil
}

// NewSafeMathTransactor creates a new write-only instance of SafeMath, bound to a specific deployed contract.
func NewSafeMathTransactor(address common.Address, transactor bind.ContractTransactor) (*SafeMathTransactor, error) {
	contract, err := bindSafeMath(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &SafeMathTransactor{contract: contract}, nil
}

// NewSafeMathFilterer creates a new log filterer instance of SafeMath, bound to a specific deployed contract.
func NewSafeMathFilterer(address common.Address, filterer bind.ContractFilterer) (*SafeMathFilterer, error) {
	contract, err := bindSafeMath(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &SafeMathFilterer{contract: contract}, nil
}

// bindSafeMath binds a generic wrapper to an already deployed contract.
func bindSafeMath(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(SafeMathABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SafeMath *SafeMathRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SafeMath.Contract.SafeMathCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SafeMath *SafeMathRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SafeMath.Contract.SafeMathTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SafeMath *SafeMathRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SafeMath.Contract.SafeMathTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SafeMath *SafeMathCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SafeMath.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SafeMath *SafeMathTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SafeMath.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SafeMath *SafeMathTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SafeMath.Contract.contract.Transact(opts, method, params...)
}

// XDCValidatorABI is the input ABI used to generate the binding from.
const XDCValidatorABI = "[{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"owners\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"ownerCount\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"address\"}],\"name\":\"hasVotedInvalid\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"ownerToCandidate\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"candidates\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"grandMasterMap\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"KYCString\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"grandMasters\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"invalidKYCCount\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"candidateCount\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"voterWithdrawDelay\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"maxValidatorNumber\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"candidateWithdrawDelay\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"minCandidateCap\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"minVoterCap\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"_candidates\",\"type\":\"address[]\"},{\"name\":\"_caps\",\"type\":\"uint256[]\"},{\"name\":\"_firstOwner\",\"type\":\"address\"},{\"name\":\"_minCandidateCap\",\"type\":\"uint256\"},{\"name\":\"_minVoterCap\",\"type\":\"uint256\"},{\"name\":\"_maxValidatorNumber\",\"type\":\"uint256\"},{\"name\":\"_candidateWithdrawDelay\",\"type\":\"uint256\"},{\"name\":\"_voterWithdrawDelay\",\"type\":\"uint256\"},{\"name\":\"_grandMasters\",\"type\":\"address[]\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"_voter\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_candidate\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_cap\",\"type\":\"uint256\"}],\"name\":\"Vote\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"_voter\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_candidate\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_cap\",\"type\":\"uint256\"}],\"name\":\"Unvote\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"_owner\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_candidate\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_cap\",\"type\":\"uint256\"}],\"name\":\"Propose\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"_owner\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_candidate\",\"type\":\"address\"}],\"name\":\"Resign\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"_owner\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_blockNumber\",\"type\":\"uint256\"},{\"indexed\":false,\"name\":\"_cap\",\"type\":\"uint256\"}],\"name\":\"Withdraw\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"_owner\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"kycHash\",\"type\":\"string\"}],\"name\":\"UploadedKYC\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"_masternodeOwner\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"_masternodes\",\"type\":\"address[]\"}],\"name\":\"InvalidatedNode\",\"type\":\"event\"},{\"constant\":false,\"inputs\":[{\"name\":\"kychash\",\"type\":\"string\"}],\"name\":\"uploadKYC\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_candidate\",\"type\":\"address\"}],\"name\":\"propose\",\"outputs\":[],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_candidate\",\"type\":\"address\"}],\"name\":\"vote\",\"outputs\":[],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getCandidates\",\"outputs\":[{\"name\":\"\",\"type\":\"address[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getGrandMasters\",\"outputs\":[{\"name\":\"\",\"type\":\"address[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_candidate\",\"type\":\"address\"}],\"name\":\"getCandidateCap\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_candidate\",\"type\":\"address\"}],\"name\":\"getCandidateOwner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_candidate\",\"type\":\"address\"},{\"name\":\"_voter\",\"type\":\"address\"}],\"name\":\"getVoterCap\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_candidate\",\"type\":\"address\"}],\"name\":\"getVoters\",\"outputs\":[{\"name\":\"\",\"type\":\"address[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_candidate\",\"type\":\"address\"}],\"name\":\"isCandidate\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getWithdrawBlockNumbers\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_blockNumber\",\"type\":\"uint256\"}],\"name\":\"getWithdrawCap\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_candidate\",\"type\":\"address\"},{\"name\":\"_cap\",\"type\":\"uint256\"}],\"name\":\"unvote\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_candidate\",\"type\":\"address\"}],\"name\":\"resign\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_invalidCandidate\",\"type\":\"address\"}],\"name\":\"voteInvalidKYC\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_invalidCandidate\",\"type\":\"address\"}],\"name\":\"invalidPercent\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getOwnerCount\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_address\",\"type\":\"address\"}],\"name\":\"getLatestKYC\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_address\",\"type\":\"address\"}],\"name\":\"getHashCount\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_blockNumber\",\"type\":\"uint256\"},{\"name\":\"_index\",\"type\":\"uint256\"}],\"name\":\"withdraw\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

// XDCValidatorBin is the compiled bytecode used for deploying new contracts.
const XDCValidatorBin = `0x606060405260006009556000600a5534156200001a57600080fd5b604051620043ec380380620043ec8339810160405280805182019190602001805182019190602001805190602001909190805190602001909190805190602001909190805190602001909190805190602001909190805190602001909190805182019190505060006200008c620006da565b87600b8190555086600c8190555085600d8190555084600e8190555083600f819055508a5160098190555060078054806001018281620000cd9190620006ee565b916000526020600020900160008b909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050600a60008154809291906001019190505550600091505b8a51821015620004f25760088054806001018281620001539190620006ee565b916000526020600020900160008d858151811015156200016f57fe5b90602001906020020151909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550506060604051908101604052808a73ffffffffffffffffffffffffffffffffffffffff1681526020016001151581526020018b84815181101515620001fa57fe5b90602001906020020151815250600160008d858151811015156200021a57fe5b9060200190602002015173ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060208201518160000160146101000a81548160ff02191690831515021790555060408201518160010155905050600260008c84815181101515620002e557fe5b9060200190602002015173ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002080548060010182816200033d9190620006ee565b916000526020600020900160008b909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050600660008a73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208054806001018281620003df9190620006ee565b916000526020600020900160008d85815181101515620003fb57fe5b90602001906020020151909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050600b54600160008d858151811015156200045c57fe5b9060200190602002015173ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160008b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550818060010192505062000133565b6040805190810160405280600b81526020017f6772616e646d61737465720000000000000000000000000000000000000000008152509050600091505b8251821015620006c957601080548060010182816200054f9190620006ee565b9160005260206000209001600085858151811015156200056b57fe5b90602001906020020151909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550506001601160008585815181101515620005cb57fe5b9060200190602002015173ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff0219169083151502179055506003600084848151811015156200063957fe5b9060200190602002015173ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002080548060010182816200069191906200071d565b916000526020600020900160008390919091509080519060200190620006b99291906200074c565b505081806001019250506200052f565b505050505050505050505062000878565b602060405190810160405280600081525090565b8154818355818115116200071857818360005260206000209182019101620007179190620007d3565b5b505050565b8154818355818115116200074757818360005260206000209182019101620007469190620007fb565b5b505050565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106200078f57805160ff1916838001178555620007c0565b82800160010185558215620007c0579182015b82811115620007bf578251825591602001919060010190620007a2565b5b509050620007cf9190620007d3565b5090565b620007f891905b80821115620007f4576000816000905550600101620007da565b5090565b90565b6200082991905b808211156200082557600081816200081b91906200082c565b5060010162000802565b5090565b90565b50805460018160011615610100020316600290046000825580601f1062000854575062000875565b601f016020900490600052602060002090810190620008749190620007d3565b5b50565b613b6480620008886000396000f3006060604052600436106101b7576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806301267951146101bc578063025e7c27146101ea57806302aa9be21461024d57806306a49fce1461028f5780630db02622146102f95780630e3e4fb81461032257806315febd68146103925780632a3640b1146103c95780632d15cc041461044b5780632f9c4bba146104d9578063302b68721461054357806332658652146105af5780633477ee2e14610661578063441a3e70146106c457806352b3ed16146106f057806358e7525f1461075a5780635b6e3963146107a75780635b860d27146107f85780635b9cd8cc146108455780636132cd83146109005780636dd7d8ea1461096357806372e44a3814610991578063a9a981a3146109de578063a9ff959e14610a07578063ae6e43f514610a30578063b642facd14610a69578063c45607df14610ae2578063d09f1ab414610b2f578063d161c76714610b58578063d51b9e9314610b81578063d55b7dff14610bd2578063ef18374a14610bfb578063f2ee3c7d14610c24578063f5c9512514610c5d578063f8ac9dd514610c8b575b600080fd5b6101e8600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610cb4565b005b34156101f557600080fd5b61020b600480803590602001909190505061139a565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b341561025857600080fd5b61028d600480803573ffffffffffffffffffffffffffffffffffffffff169060200190919080359060200190919050506113d9565b005b341561029a57600080fd5b6102a2611934565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b838110156102e55780820151818401526020810190506102ca565b505050509050019250505060405180910390f35b341561030457600080fd5b61030c6119c8565b6040518082815260200191505060405180910390f35b341561032d57600080fd5b610378600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff169060200190919050506119ce565b604051808215151515815260200191505060405180910390f35b341561039d57600080fd5b6103b360048080359060200190919050506119fd565b6040518082815260200191505060405180910390f35b34156103d457600080fd5b610409600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091908035906020019091905050611a59565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b341561045657600080fd5b610482600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050611aa7565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b838110156104c55780820151818401526020810190506104aa565b505050509050019250505060405180910390f35b34156104e457600080fd5b6104ec611b7a565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b8381101561052f578082015181840152602081019050610514565b505050509050019250505060405180910390f35b341561054e57600080fd5b610599600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050611c17565b6040518082815260200191505060405180910390f35b34156105ba57600080fd5b6105e6600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050611ca1565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561062657808201518184015260208101905061060b565b50505050905090810190601f1680156106535780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561066c57600080fd5b6106826004808035906020019091905050611f40565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34156106cf57600080fd5b6106ee6004808035906020019091908035906020019091905050611f7f565b005b34156106fb57600080fd5b61070361222b565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b8381101561074657808201518184015260208101905061072b565b505050509050019250505060405180910390f35b341561076557600080fd5b610791600480803573ffffffffffffffffffffffffffffffffffffffff169060200190919050506122bf565b6040518082815260200191505060405180910390f35b34156107b257600080fd5b6107de600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190505061230b565b604051808215151515815260200191505060405180910390f35b341561080357600080fd5b61082f600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190505061232b565b6040518082815260200191505060405180910390f35b341561085057600080fd5b610885600480803573ffffffffffffffffffffffffffffffffffffffff169060200190919080359060200190919050506123f3565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156108c55780820151818401526020810190506108aa565b50505050905090810190601f1680156108f25780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561090b57600080fd5b61092160048080359060200190919050506124bc565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b61098f600480803573ffffffffffffffffffffffffffffffffffffffff169060200190919050506124fb565b005b341561099c57600080fd5b6109c8600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050612943565b6040518082815260200191505060405180910390f35b34156109e957600080fd5b6109f161295b565b6040518082815260200191505060405180910390f35b3415610a1257600080fd5b610a1a612961565b6040518082815260200191505060405180910390f35b3415610a3b57600080fd5b610a67600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050612967565b005b3415610a7457600080fd5b610aa0600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050612f26565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b3415610aed57600080fd5b610b19600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050612f92565b6040518082815260200191505060405180910390f35b3415610b3a57600080fd5b610b42612fde565b6040518082815260200191505060405180910390f35b3415610b6357600080fd5b610b6b612fe4565b6040518082815260200191505060405180910390f35b3415610b8c57600080fd5b610bb8600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050612fea565b604051808215151515815260200191505060405180910390f35b3415610bdd57600080fd5b610be5613043565b6040518082815260200191505060405180910390f35b3415610c0657600080fd5b610c0e613049565b6040518082815260200191505060405180910390f35b3415610c2f57600080fd5b610c5b600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050613053565b005b3415610c6857600080fd5b610c89600480803590602001908201803590602001919091929050506137e1565b005b3415610c9657600080fd5b610c9e6138e0565b6040518082815260200191505060405180910390f35b6000600b543410151515610cc757600080fd5b6000600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002080549050141580610d5b57506000600660003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002080549050115b1515610d6657600080fd5b81600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160149054906101000a900460ff16151515610dc357600080fd5b60011515601160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff161515141515610e2257600080fd5b610e7734600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101546138e690919063ffffffff16565b915060088054806001018281610e8d919061391d565b9160005260206000209001600085909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550506060604051908101604052803373ffffffffffffffffffffffffffffffffffffffff16815260200160011515815260200183815250600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060208201518160000160146101000a81548160ff0219169083151502179055506040820151816001015590505061105634600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546138e690919063ffffffff16565b600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506110ef60016009546138e690919063ffffffff16565b6009819055506000600660003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208054905014156111b65760078054806001018281611154919061391d565b9160005260206000209001600033909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050600a600081548092919060010191905055505b600660003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208054806001018281611207919061391d565b9160005260206000209001600085909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050600260008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002080548060010182816112a7919061391d565b9160005260206000209001600033909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550507f7635f1d87b47fba9f2b09e56eb4be75cca030e0cb179c1602ac9261d39a8f5c1338434604051808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001828152602001935050505060405180910390a1505050565b6007818154811015156113a957fe5b90600052602060002090016000915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000828280600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541015151561146b57600080fd5b3373ffffffffffffffffffffffffffffffffffffffff16600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614156115a457600b5461159682600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461390490919063ffffffff16565b101515156115a357600080fd5b5b6115f984600160008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206001015461390490919063ffffffff16565b600160008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101819055506116d184600160008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461390490919063ffffffff16565b600160008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555061176943600f546138e690919063ffffffff16565b92506117d0846000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000016000868152602001908152602001600020546138e690919063ffffffff16565b6000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000016000858152602001908152602001600020819055506000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010180548060010182816118799190613949565b9160005260206000209001600085909190915055507faa0e554f781c3c3b2be110a0557f260f11af9a8aa2c64bc1e7a31dbb21e32fa2338686604051808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001828152602001935050505060405180910390a15050505050565b61193c613975565b60088054806020026020016040519081016040528092919081815260200182805480156119be57602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311611974575b5050505050905090565b600a5481565b60056020528160005260406000206020528060005260406000206000915091509054906101000a900460ff1681565b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000016000838152602001908152602001600020549050919050565b600660205281600052604060002081815481101515611a7457fe5b90600052602060002090016000915091509054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b611aaf613975565b600260008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805480602002602001604051908101604052809291908181526020018280548015611b6e57602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311611b24575b50505050509050919050565b611b82613989565b6000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101805480602002602001604051908101604052809291908181526020018280548015611c0d57602002820191906000526020600020905b815481526020019060010190808311611bf9575b5050505050905090565b6000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b611ca961399d565b611cb282612fea565b15611e035760036000611cc484612f26565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600160036000611d0d86612f26565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208054905003815481101515611d5857fe5b90600052602060002090018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015611df75780601f10611dcc57610100808354040283529160200191611df7565b820191906000526020600020905b815481529060010190602001808311611dda57829003601f168201915b50505050509050611f3b565b600360008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206001600360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208054905003815481101515611e9457fe5b90600052602060002090018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015611f335780601f10611f0857610100808354040283529160200191611f33565b820191906000526020600020905b815481529060010190602001808311611f1657829003601f168201915b505050505090505b919050565b600881815481101515611f4f57fe5b90600052602060002090016000915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008282600082111515611f9257600080fd5b814310151515611fa157600080fd5b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160008481526020019081526020016000205411151561200257600080fd5b816000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206001018281548110151561205157fe5b90600052602060002090015414151561206957600080fd5b6000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160008681526020019081526020016000205492506000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000016000868152602001908152602001600020600090556000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206001018481548110151561216257fe5b9060005260206000209001600090553373ffffffffffffffffffffffffffffffffffffffff166108fc849081150290604051600060405180830381858888f1935050505015156121b157600080fd5b7ff279e6a1f5e320cca91135676d9cb6e44ca8a08c0b88342bcdb1144f6511b568338685604051808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001838152602001828152602001935050505060405180910390a15050505050565b612233613975565b60108054806020026020016040519081016040528092919081815260200182805480156122b557602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001906001019080831161226b575b5050505050905090565b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101549050919050565b60116020528060005260406000206000915054906101000a900460ff1681565b60008082600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160149054906101000a900460ff16151561238a57600080fd5b61239384612f26565b915061239d613049565b6064600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054028115156123e957fe5b0492505050919050565b60036020528160005260406000208181548110151561240e57fe5b9060005260206000209001600091509150508054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156124b45780601f10612489576101008083540402835291602001916124b4565b820191906000526020600020905b81548152906001019060200180831161249757829003601f168201915b505050505081565b6010818154811015156124cb57fe5b90600052602060002090016000915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600c54341015151561250c57600080fd5b80600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160149054906101000a900460ff16151561256857600080fd5b60011515601160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff1615151415156125c757600080fd5b61261c34600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101546138e690919063ffffffff16565b600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101819055506000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054141561278b57600260008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805480600101828161273b919061391d565b9160005260206000209001600033909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550505b61281d34600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546138e690919063ffffffff16565b600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055507f66a9138482c99e9baf08860110ef332cc0c23b4a199a53593d8db0fc8f96fbfc338334604051808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001828152602001935050505060405180910390a15050565b60046020528060005260406000206000915090505481565b60095481565b600f5481565b6000806000833373ffffffffffffffffffffffffffffffffffffffff16600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16141515612a0957600080fd5b84600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160149054906101000a900460ff161515612a6557600080fd5b6000600160008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160146101000a81548160ff021916908315150217905550612ad6600160095461390490919063ffffffff16565b600981905550600094505b600880549050851015612bab578573ffffffffffffffffffffffffffffffffffffffff16600886815481101515612b1457fe5b906000526020600020900160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161415612b9e57600885815481101515612b6b57fe5b906000526020600020900160006101000a81549073ffffffffffffffffffffffffffffffffffffffff0219169055612bab565b8480600101955050612ae1565b600160008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549350612c8284600160008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206001015461390490919063ffffffff16565b600160008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101819055506000600160008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550612d6243600e546138e690919063ffffffff16565b9250612dc9846000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000016000868152602001908152602001600020546138e690919063ffffffff16565b6000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000016000858152602001908152602001600020819055506000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206001018054806001018281612e729190613949565b9160005260206000209001600085909190915055507f4edf3e325d0063213a39f9085522994a1c44bea5f39e7d63ef61260a1e58c6d33387604051808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019250505060405180910390a1505050505050565b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b6000600360008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805490509050919050565b600d5481565b600e5481565b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160149054906101000a900460ff169050919050565b600b5481565b6000600a54905090565b60008061305e613975565b600080600033600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160149054906101000a900460ff1615156130bf57600080fd5b87600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160149054906101000a900460ff16151561311b57600080fd5b61312433612f26565b975061312f89612f26565b9650600560008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff161515156131c757600080fd5b6001600560008a73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff0219169083151502179055506001600460008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282540192505081905550604b6132b4613049565b6064600460008b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020540281151561330057fe5b041015156137d65760016008805490500360405180591061331e5750595b9080825280602002602001820160405250955060009450600093505b600880549050841015613647578673ffffffffffffffffffffffffffffffffffffffff166133a160088681548110151561337057fe5b906000526020600020900160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16612f26565b73ffffffffffffffffffffffffffffffffffffffff16141561363a576133d3600160095461390490919063ffffffff16565b6009819055506008848154811015156133e857fe5b906000526020600020900160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16868680600101975081518110151561342857fe5b9060200190602002019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff168152505060088481548110151561347357fe5b906000526020600020900160006101000a81549073ffffffffffffffffffffffffffffffffffffffff0219169055600160006008868154811015156134b457fe5b906000526020600020900160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600080820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556000820160146101000a81549060ff021916905560018201600090555050600360008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006135ab91906139b1565b600660008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006135f691906139d2565b600460008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600090555b838060010194505061333a565b600092505b600780549050831015613729578673ffffffffffffffffffffffffffffffffffffffff1660078481548110151561367f57fe5b906000526020600020900160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16141561371c576007838154811015156136d657fe5b906000526020600020900160006101000a81549073ffffffffffffffffffffffffffffffffffffffff0219169055600a6000815480929190600190039190505550613729565b828060010193505061364c565b7fe18d61a5bf4aa2ab40afc88aa9039d27ae17ff4ec1c65f5f414df6f02ce8b35e8787604051808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200180602001828103825283818151815260200191508051906020019060200280838360005b838110156137c15780820151818401526020810190506137a6565b50505050905001935050505060405180910390a15b505050505050505050565b600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805480600101828161383291906139f3565b916000526020600020900160008484909192909192509190613855929190613a1f565b50507f949360d814b28a3b393a68909efe1fee120ee09cac30f360a0f80ab5415a611a338383604051808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001806020018281038252848482818152602001925080828437820191505094505050505060405180910390a15050565b600c5481565b60008082840190508381101515156138fa57fe5b8091505092915050565b600082821115151561391257fe5b818303905092915050565b815481835581811511613944578183600052602060002091820191016139439190613a9f565b5b505050565b8154818355818115116139705781836000526020600020918201910161396f9190613a9f565b5b505050565b602060405190810160405280600081525090565b602060405190810160405280600081525090565b602060405190810160405280600081525090565b50805460008255906000526020600020908101906139cf9190613ac4565b50565b50805460008255906000526020600020908101906139f09190613a9f565b50565b815481835581811511613a1a57818360005260206000209182019101613a199190613ac4565b5b505050565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f10613a6057803560ff1916838001178555613a8e565b82800160010185558215613a8e579182015b82811115613a8d578235825591602001919060010190613a72565b5b509050613a9b9190613a9f565b5090565b613ac191905b80821115613abd576000816000905550600101613aa5565b5090565b90565b613aed91905b80821115613ae95760008181613ae09190613af0565b50600101613aca565b5090565b90565b50805460018160011615610100020316600290046000825580601f10613b165750613b35565b601f016020900490600052602060002090810190613b349190613a9f565b5b505600a165627a7a723058206cc88e4a7644089f97a9fbb30ce517eee86595dfa256c692c1b8269048d0d7480029`

// DeployXDCValidator deploys a new Ethereum contract, binding an instance of XDCValidator to it.
func DeployXDCValidator(auth *bind.TransactOpts, backend bind.ContractBackend, _candidates []common.Address, _caps []*big.Int, _firstOwner common.Address, _minCandidateCap *big.Int, _minVoterCap *big.Int, _maxValidatorNumber *big.Int, _candidateWithdrawDelay *big.Int, _voterWithdrawDelay *big.Int, _grandMasters []common.Address) (common.Address, *types.Transaction, *XDCValidator, error) {
	parsed, err := abi.JSON(strings.NewReader(XDCValidatorABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(XDCValidatorBin), backend, _candidates, _caps, _firstOwner, _minCandidateCap, _minVoterCap, _maxValidatorNumber, _candidateWithdrawDelay, _voterWithdrawDelay, _grandMasters)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &XDCValidator{XDCValidatorCaller: XDCValidatorCaller{contract: contract}, XDCValidatorTransactor: XDCValidatorTransactor{contract: contract}, XDCValidatorFilterer: XDCValidatorFilterer{contract: contract}}, nil
}

// XDCValidator is an auto generated Go binding around an Ethereum contract.
type XDCValidator struct {
	XDCValidatorCaller     // Read-only binding to the contract
	XDCValidatorTransactor // Write-only binding to the contract
	XDCValidatorFilterer   // Log filterer for contract events
}

// XDCValidatorCaller is an auto generated read-only Go binding around an Ethereum contract.
type XDCValidatorCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// XDCValidatorTransactor is an auto generated write-only Go binding around an Ethereum contract.
type XDCValidatorTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// XDCValidatorFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type XDCValidatorFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// XDCValidatorSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type XDCValidatorSession struct {
	Contract     *XDCValidator     // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// XDCValidatorCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type XDCValidatorCallerSession struct {
	Contract *XDCValidatorCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts       // Call options to use throughout this session
}

// XDCValidatorTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type XDCValidatorTransactorSession struct {
	Contract     *XDCValidatorTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts       // Transaction auth options to use throughout this session
}

// XDCValidatorRaw is an auto generated low-level Go binding around an Ethereum contract.
type XDCValidatorRaw struct {
	Contract *XDCValidator // Generic contract binding to access the raw methods on
}

// XDCValidatorCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type XDCValidatorCallerRaw struct {
	Contract *XDCValidatorCaller // Generic read-only contract binding to access the raw methods on
}

// XDCValidatorTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type XDCValidatorTransactorRaw struct {
	Contract *XDCValidatorTransactor // Generic write-only contract binding to access the raw methods on
}

// NewXDCValidator creates a new instance of XDCValidator, bound to a specific deployed contract.
func NewXDCValidator(address common.Address, backend bind.ContractBackend) (*XDCValidator, error) {
	contract, err := bindXDCValidator(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &XDCValidator{XDCValidatorCaller: XDCValidatorCaller{contract: contract}, XDCValidatorTransactor: XDCValidatorTransactor{contract: contract}, XDCValidatorFilterer: XDCValidatorFilterer{contract: contract}}, nil
}

// NewXDCValidatorCaller creates a new read-only instance of XDCValidator, bound to a specific deployed contract.
func NewXDCValidatorCaller(address common.Address, caller bind.ContractCaller) (*XDCValidatorCaller, error) {
	contract, err := bindXDCValidator(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &XDCValidatorCaller{contract: contract}, nil
}

// NewXDCValidatorTransactor creates a new write-only instance of XDCValidator, bound to a specific deployed contract.
func NewXDCValidatorTransactor(address common.Address, transactor bind.ContractTransactor) (*XDCValidatorTransactor, error) {
	contract, err := bindXDCValidator(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &XDCValidatorTransactor{contract: contract}, nil
}

// NewXDCValidatorFilterer creates a new log filterer instance of XDCValidator, bound to a specific deployed contract.
func NewXDCValidatorFilterer(address common.Address, filterer bind.ContractFilterer) (*XDCValidatorFilterer, error) {
	contract, err := bindXDCValidator(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &XDCValidatorFilterer{contract: contract}, nil
}

// bindXDCValidator binds a generic wrapper to an already deployed contract.
func bindXDCValidator(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(XDCValidatorABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_XDCValidator *XDCValidatorRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _XDCValidator.Contract.XDCValidatorCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_XDCValidator *XDCValidatorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _XDCValidator.Contract.XDCValidatorTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_XDCValidator *XDCValidatorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _XDCValidator.Contract.XDCValidatorTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_XDCValidator *XDCValidatorCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _XDCValidator.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_XDCValidator *XDCValidatorTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _XDCValidator.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_XDCValidator *XDCValidatorTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _XDCValidator.Contract.contract.Transact(opts, method, params...)
}

// KYCString is a free data retrieval call binding the contract method 0x5b9cd8cc.
//
// Solidity: function KYCString( address,  uint256) constant returns(string)
func (_XDCValidator *XDCValidatorCaller) KYCString(opts *bind.CallOpts, arg0 common.Address, arg1 *big.Int) (string, error) {
	var (
		ret0 = new(string)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "KYCString", arg0, arg1)
	return *ret0, err
}

// KYCString is a free data retrieval call binding the contract method 0x5b9cd8cc.
//
// Solidity: function KYCString( address,  uint256) constant returns(string)
func (_XDCValidator *XDCValidatorSession) KYCString(arg0 common.Address, arg1 *big.Int) (string, error) {
	return _XDCValidator.Contract.KYCString(&_XDCValidator.CallOpts, arg0, arg1)
}

// KYCString is a free data retrieval call binding the contract method 0x5b9cd8cc.
//
// Solidity: function KYCString( address,  uint256) constant returns(string)
func (_XDCValidator *XDCValidatorCallerSession) KYCString(arg0 common.Address, arg1 *big.Int) (string, error) {
	return _XDCValidator.Contract.KYCString(&_XDCValidator.CallOpts, arg0, arg1)
}

// CandidateCount is a free data retrieval call binding the contract method 0xa9a981a3.
//
// Solidity: function candidateCount() constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) CandidateCount(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "candidateCount")
	return *ret0, err
}

// CandidateCount is a free data retrieval call binding the contract method 0xa9a981a3.
//
// Solidity: function candidateCount() constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) CandidateCount() (*big.Int, error) {
	return _XDCValidator.Contract.CandidateCount(&_XDCValidator.CallOpts)
}

// CandidateCount is a free data retrieval call binding the contract method 0xa9a981a3.
//
// Solidity: function candidateCount() constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) CandidateCount() (*big.Int, error) {
	return _XDCValidator.Contract.CandidateCount(&_XDCValidator.CallOpts)
}

// CandidateWithdrawDelay is a free data retrieval call binding the contract method 0xd161c767.
//
// Solidity: function candidateWithdrawDelay() constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) CandidateWithdrawDelay(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "candidateWithdrawDelay")
	return *ret0, err
}

// CandidateWithdrawDelay is a free data retrieval call binding the contract method 0xd161c767.
//
// Solidity: function candidateWithdrawDelay() constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) CandidateWithdrawDelay() (*big.Int, error) {
	return _XDCValidator.Contract.CandidateWithdrawDelay(&_XDCValidator.CallOpts)
}

// CandidateWithdrawDelay is a free data retrieval call binding the contract method 0xd161c767.
//
// Solidity: function candidateWithdrawDelay() constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) CandidateWithdrawDelay() (*big.Int, error) {
	return _XDCValidator.Contract.CandidateWithdrawDelay(&_XDCValidator.CallOpts)
}

// Candidates is a free data retrieval call binding the contract method 0x3477ee2e.
//
// Solidity: function candidates( uint256) constant returns(address)
func (_XDCValidator *XDCValidatorCaller) Candidates(opts *bind.CallOpts, arg0 *big.Int) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "candidates", arg0)
	return *ret0, err
}

// Candidates is a free data retrieval call binding the contract method 0x3477ee2e.
//
// Solidity: function candidates( uint256) constant returns(address)
func (_XDCValidator *XDCValidatorSession) Candidates(arg0 *big.Int) (common.Address, error) {
	return _XDCValidator.Contract.Candidates(&_XDCValidator.CallOpts, arg0)
}

// Candidates is a free data retrieval call binding the contract method 0x3477ee2e.
//
// Solidity: function candidates( uint256) constant returns(address)
func (_XDCValidator *XDCValidatorCallerSession) Candidates(arg0 *big.Int) (common.Address, error) {
	return _XDCValidator.Contract.Candidates(&_XDCValidator.CallOpts, arg0)
}

// GetCandidateCap is a free data retrieval call binding the contract method 0x58e7525f.
//
// Solidity: function getCandidateCap(_candidate address) constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) GetCandidateCap(opts *bind.CallOpts, _candidate common.Address) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "getCandidateCap", _candidate)
	return *ret0, err
}

// GetCandidateCap is a free data retrieval call binding the contract method 0x58e7525f.
//
// Solidity: function getCandidateCap(_candidate address) constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) GetCandidateCap(_candidate common.Address) (*big.Int, error) {
	return _XDCValidator.Contract.GetCandidateCap(&_XDCValidator.CallOpts, _candidate)
}

// GetCandidateCap is a free data retrieval call binding the contract method 0x58e7525f.
//
// Solidity: function getCandidateCap(_candidate address) constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) GetCandidateCap(_candidate common.Address) (*big.Int, error) {
	return _XDCValidator.Contract.GetCandidateCap(&_XDCValidator.CallOpts, _candidate)
}

// GetCandidateOwner is a free data retrieval call binding the contract method 0xb642facd.
//
// Solidity: function getCandidateOwner(_candidate address) constant returns(address)
func (_XDCValidator *XDCValidatorCaller) GetCandidateOwner(opts *bind.CallOpts, _candidate common.Address) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "getCandidateOwner", _candidate)
	return *ret0, err
}

// GetCandidateOwner is a free data retrieval call binding the contract method 0xb642facd.
//
// Solidity: function getCandidateOwner(_candidate address) constant returns(address)
func (_XDCValidator *XDCValidatorSession) GetCandidateOwner(_candidate common.Address) (common.Address, error) {
	return _XDCValidator.Contract.GetCandidateOwner(&_XDCValidator.CallOpts, _candidate)
}

// GetCandidateOwner is a free data retrieval call binding the contract method 0xb642facd.
//
// Solidity: function getCandidateOwner(_candidate address) constant returns(address)
func (_XDCValidator *XDCValidatorCallerSession) GetCandidateOwner(_candidate common.Address) (common.Address, error) {
	return _XDCValidator.Contract.GetCandidateOwner(&_XDCValidator.CallOpts, _candidate)
}

// GetCandidates is a free data retrieval call binding the contract method 0x06a49fce.
//
// Solidity: function getCandidates() constant returns(address[])
func (_XDCValidator *XDCValidatorCaller) GetCandidates(opts *bind.CallOpts) ([]common.Address, error) {
	var (
		ret0 = new([]common.Address)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "getCandidates")
	return *ret0, err
}

// GetCandidates is a free data retrieval call binding the contract method 0x06a49fce.
//
// Solidity: function getCandidates() constant returns(address[])
func (_XDCValidator *XDCValidatorSession) GetCandidates() ([]common.Address, error) {
	return _XDCValidator.Contract.GetCandidates(&_XDCValidator.CallOpts)
}

// GetCandidates is a free data retrieval call binding the contract method 0x06a49fce.
//
// Solidity: function getCandidates() constant returns(address[])
func (_XDCValidator *XDCValidatorCallerSession) GetCandidates() ([]common.Address, error) {
	return _XDCValidator.Contract.GetCandidates(&_XDCValidator.CallOpts)
}

// GetGrandMasters is a free data retrieval call binding the contract method 0x52b3ed16.
//
// Solidity: function getGrandMasters() constant returns(address[])
func (_XDCValidator *XDCValidatorCaller) GetGrandMasters(opts *bind.CallOpts) ([]common.Address, error) {
	var (
		ret0 = new([]common.Address)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "getGrandMasters")
	return *ret0, err
}

// GetGrandMasters is a free data retrieval call binding the contract method 0x52b3ed16.
//
// Solidity: function getGrandMasters() constant returns(address[])
func (_XDCValidator *XDCValidatorSession) GetGrandMasters() ([]common.Address, error) {
	return _XDCValidator.Contract.GetGrandMasters(&_XDCValidator.CallOpts)
}

// GetGrandMasters is a free data retrieval call binding the contract method 0x52b3ed16.
//
// Solidity: function getGrandMasters() constant returns(address[])
func (_XDCValidator *XDCValidatorCallerSession) GetGrandMasters() ([]common.Address, error) {
	return _XDCValidator.Contract.GetGrandMasters(&_XDCValidator.CallOpts)
}

// GetHashCount is a free data retrieval call binding the contract method 0xc45607df.
//
// Solidity: function getHashCount(_address address) constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) GetHashCount(opts *bind.CallOpts, _address common.Address) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "getHashCount", _address)
	return *ret0, err
}

// GetHashCount is a free data retrieval call binding the contract method 0xc45607df.
//
// Solidity: function getHashCount(_address address) constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) GetHashCount(_address common.Address) (*big.Int, error) {
	return _XDCValidator.Contract.GetHashCount(&_XDCValidator.CallOpts, _address)
}

// GetHashCount is a free data retrieval call binding the contract method 0xc45607df.
//
// Solidity: function getHashCount(_address address) constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) GetHashCount(_address common.Address) (*big.Int, error) {
	return _XDCValidator.Contract.GetHashCount(&_XDCValidator.CallOpts, _address)
}

// GetLatestKYC is a free data retrieval call binding the contract method 0x32658652.
//
// Solidity: function getLatestKYC(_address address) constant returns(string)
func (_XDCValidator *XDCValidatorCaller) GetLatestKYC(opts *bind.CallOpts, _address common.Address) (string, error) {
	var (
		ret0 = new(string)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "getLatestKYC", _address)
	return *ret0, err
}

// GetLatestKYC is a free data retrieval call binding the contract method 0x32658652.
//
// Solidity: function getLatestKYC(_address address) constant returns(string)
func (_XDCValidator *XDCValidatorSession) GetLatestKYC(_address common.Address) (string, error) {
	return _XDCValidator.Contract.GetLatestKYC(&_XDCValidator.CallOpts, _address)
}

// GetLatestKYC is a free data retrieval call binding the contract method 0x32658652.
//
// Solidity: function getLatestKYC(_address address) constant returns(string)
func (_XDCValidator *XDCValidatorCallerSession) GetLatestKYC(_address common.Address) (string, error) {
	return _XDCValidator.Contract.GetLatestKYC(&_XDCValidator.CallOpts, _address)
}

// GetOwnerCount is a free data retrieval call binding the contract method 0xef18374a.
//
// Solidity: function getOwnerCount() constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) GetOwnerCount(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "getOwnerCount")
	return *ret0, err
}

// GetOwnerCount is a free data retrieval call binding the contract method 0xef18374a.
//
// Solidity: function getOwnerCount() constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) GetOwnerCount() (*big.Int, error) {
	return _XDCValidator.Contract.GetOwnerCount(&_XDCValidator.CallOpts)
}

// GetOwnerCount is a free data retrieval call binding the contract method 0xef18374a.
//
// Solidity: function getOwnerCount() constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) GetOwnerCount() (*big.Int, error) {
	return _XDCValidator.Contract.GetOwnerCount(&_XDCValidator.CallOpts)
}

// GetVoterCap is a free data retrieval call binding the contract method 0x302b6872.
//
// Solidity: function getVoterCap(_candidate address, _voter address) constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) GetVoterCap(opts *bind.CallOpts, _candidate common.Address, _voter common.Address) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "getVoterCap", _candidate, _voter)
	return *ret0, err
}

// GetVoterCap is a free data retrieval call binding the contract method 0x302b6872.
//
// Solidity: function getVoterCap(_candidate address, _voter address) constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) GetVoterCap(_candidate common.Address, _voter common.Address) (*big.Int, error) {
	return _XDCValidator.Contract.GetVoterCap(&_XDCValidator.CallOpts, _candidate, _voter)
}

// GetVoterCap is a free data retrieval call binding the contract method 0x302b6872.
//
// Solidity: function getVoterCap(_candidate address, _voter address) constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) GetVoterCap(_candidate common.Address, _voter common.Address) (*big.Int, error) {
	return _XDCValidator.Contract.GetVoterCap(&_XDCValidator.CallOpts, _candidate, _voter)
}

// GetVoters is a free data retrieval call binding the contract method 0x2d15cc04.
//
// Solidity: function getVoters(_candidate address) constant returns(address[])
func (_XDCValidator *XDCValidatorCaller) GetVoters(opts *bind.CallOpts, _candidate common.Address) ([]common.Address, error) {
	var (
		ret0 = new([]common.Address)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "getVoters", _candidate)
	return *ret0, err
}

// GetVoters is a free data retrieval call binding the contract method 0x2d15cc04.
//
// Solidity: function getVoters(_candidate address) constant returns(address[])
func (_XDCValidator *XDCValidatorSession) GetVoters(_candidate common.Address) ([]common.Address, error) {
	return _XDCValidator.Contract.GetVoters(&_XDCValidator.CallOpts, _candidate)
}

// GetVoters is a free data retrieval call binding the contract method 0x2d15cc04.
//
// Solidity: function getVoters(_candidate address) constant returns(address[])
func (_XDCValidator *XDCValidatorCallerSession) GetVoters(_candidate common.Address) ([]common.Address, error) {
	return _XDCValidator.Contract.GetVoters(&_XDCValidator.CallOpts, _candidate)
}

// GetWithdrawBlockNumbers is a free data retrieval call binding the contract method 0x2f9c4bba.
//
// Solidity: function getWithdrawBlockNumbers() constant returns(uint256[])
func (_XDCValidator *XDCValidatorCaller) GetWithdrawBlockNumbers(opts *bind.CallOpts) ([]*big.Int, error) {
	var (
		ret0 = new([]*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "getWithdrawBlockNumbers")
	return *ret0, err
}

// GetWithdrawBlockNumbers is a free data retrieval call binding the contract method 0x2f9c4bba.
//
// Solidity: function getWithdrawBlockNumbers() constant returns(uint256[])
func (_XDCValidator *XDCValidatorSession) GetWithdrawBlockNumbers() ([]*big.Int, error) {
	return _XDCValidator.Contract.GetWithdrawBlockNumbers(&_XDCValidator.CallOpts)
}

// GetWithdrawBlockNumbers is a free data retrieval call binding the contract method 0x2f9c4bba.
//
// Solidity: function getWithdrawBlockNumbers() constant returns(uint256[])
func (_XDCValidator *XDCValidatorCallerSession) GetWithdrawBlockNumbers() ([]*big.Int, error) {
	return _XDCValidator.Contract.GetWithdrawBlockNumbers(&_XDCValidator.CallOpts)
}

// GetWithdrawCap is a free data retrieval call binding the contract method 0x15febd68.
//
// Solidity: function getWithdrawCap(_blockNumber uint256) constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) GetWithdrawCap(opts *bind.CallOpts, _blockNumber *big.Int) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "getWithdrawCap", _blockNumber)
	return *ret0, err
}

// GetWithdrawCap is a free data retrieval call binding the contract method 0x15febd68.
//
// Solidity: function getWithdrawCap(_blockNumber uint256) constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) GetWithdrawCap(_blockNumber *big.Int) (*big.Int, error) {
	return _XDCValidator.Contract.GetWithdrawCap(&_XDCValidator.CallOpts, _blockNumber)
}

// GetWithdrawCap is a free data retrieval call binding the contract method 0x15febd68.
//
// Solidity: function getWithdrawCap(_blockNumber uint256) constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) GetWithdrawCap(_blockNumber *big.Int) (*big.Int, error) {
	return _XDCValidator.Contract.GetWithdrawCap(&_XDCValidator.CallOpts, _blockNumber)
}

// GrandMasterMap is a free data retrieval call binding the contract method 0x5b6e3963.
//
// Solidity: function grandMasterMap( address) constant returns(bool)
func (_XDCValidator *XDCValidatorCaller) GrandMasterMap(opts *bind.CallOpts, arg0 common.Address) (bool, error) {
	var (
		ret0 = new(bool)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "grandMasterMap", arg0)
	return *ret0, err
}

// GrandMasterMap is a free data retrieval call binding the contract method 0x5b6e3963.
//
// Solidity: function grandMasterMap( address) constant returns(bool)
func (_XDCValidator *XDCValidatorSession) GrandMasterMap(arg0 common.Address) (bool, error) {
	return _XDCValidator.Contract.GrandMasterMap(&_XDCValidator.CallOpts, arg0)
}

// GrandMasterMap is a free data retrieval call binding the contract method 0x5b6e3963.
//
// Solidity: function grandMasterMap( address) constant returns(bool)
func (_XDCValidator *XDCValidatorCallerSession) GrandMasterMap(arg0 common.Address) (bool, error) {
	return _XDCValidator.Contract.GrandMasterMap(&_XDCValidator.CallOpts, arg0)
}

// GrandMasters is a free data retrieval call binding the contract method 0x6132cd83.
//
// Solidity: function grandMasters( uint256) constant returns(address)
func (_XDCValidator *XDCValidatorCaller) GrandMasters(opts *bind.CallOpts, arg0 *big.Int) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "grandMasters", arg0)
	return *ret0, err
}

// GrandMasters is a free data retrieval call binding the contract method 0x6132cd83.
//
// Solidity: function grandMasters( uint256) constant returns(address)
func (_XDCValidator *XDCValidatorSession) GrandMasters(arg0 *big.Int) (common.Address, error) {
	return _XDCValidator.Contract.GrandMasters(&_XDCValidator.CallOpts, arg0)
}

// GrandMasters is a free data retrieval call binding the contract method 0x6132cd83.
//
// Solidity: function grandMasters( uint256) constant returns(address)
func (_XDCValidator *XDCValidatorCallerSession) GrandMasters(arg0 *big.Int) (common.Address, error) {
	return _XDCValidator.Contract.GrandMasters(&_XDCValidator.CallOpts, arg0)
}

// HasVotedInvalid is a free data retrieval call binding the contract method 0x0e3e4fb8.
//
// Solidity: function hasVotedInvalid( address,  address) constant returns(bool)
func (_XDCValidator *XDCValidatorCaller) HasVotedInvalid(opts *bind.CallOpts, arg0 common.Address, arg1 common.Address) (bool, error) {
	var (
		ret0 = new(bool)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "hasVotedInvalid", arg0, arg1)
	return *ret0, err
}

// HasVotedInvalid is a free data retrieval call binding the contract method 0x0e3e4fb8.
//
// Solidity: function hasVotedInvalid( address,  address) constant returns(bool)
func (_XDCValidator *XDCValidatorSession) HasVotedInvalid(arg0 common.Address, arg1 common.Address) (bool, error) {
	return _XDCValidator.Contract.HasVotedInvalid(&_XDCValidator.CallOpts, arg0, arg1)
}

// HasVotedInvalid is a free data retrieval call binding the contract method 0x0e3e4fb8.
//
// Solidity: function hasVotedInvalid( address,  address) constant returns(bool)
func (_XDCValidator *XDCValidatorCallerSession) HasVotedInvalid(arg0 common.Address, arg1 common.Address) (bool, error) {
	return _XDCValidator.Contract.HasVotedInvalid(&_XDCValidator.CallOpts, arg0, arg1)
}

// InvalidKYCCount is a free data retrieval call binding the contract method 0x72e44a38.
//
// Solidity: function invalidKYCCount( address) constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) InvalidKYCCount(opts *bind.CallOpts, arg0 common.Address) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "invalidKYCCount", arg0)
	return *ret0, err
}

// InvalidKYCCount is a free data retrieval call binding the contract method 0x72e44a38.
//
// Solidity: function invalidKYCCount( address) constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) InvalidKYCCount(arg0 common.Address) (*big.Int, error) {
	return _XDCValidator.Contract.InvalidKYCCount(&_XDCValidator.CallOpts, arg0)
}

// InvalidKYCCount is a free data retrieval call binding the contract method 0x72e44a38.
//
// Solidity: function invalidKYCCount( address) constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) InvalidKYCCount(arg0 common.Address) (*big.Int, error) {
	return _XDCValidator.Contract.InvalidKYCCount(&_XDCValidator.CallOpts, arg0)
}

// InvalidPercent is a free data retrieval call binding the contract method 0x5b860d27.
//
// Solidity: function invalidPercent(_invalidCandidate address) constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) InvalidPercent(opts *bind.CallOpts, _invalidCandidate common.Address) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "invalidPercent", _invalidCandidate)
	return *ret0, err
}

// InvalidPercent is a free data retrieval call binding the contract method 0x5b860d27.
//
// Solidity: function invalidPercent(_invalidCandidate address) constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) InvalidPercent(_invalidCandidate common.Address) (*big.Int, error) {
	return _XDCValidator.Contract.InvalidPercent(&_XDCValidator.CallOpts, _invalidCandidate)
}

// InvalidPercent is a free data retrieval call binding the contract method 0x5b860d27.
//
// Solidity: function invalidPercent(_invalidCandidate address) constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) InvalidPercent(_invalidCandidate common.Address) (*big.Int, error) {
	return _XDCValidator.Contract.InvalidPercent(&_XDCValidator.CallOpts, _invalidCandidate)
}

// IsCandidate is a free data retrieval call binding the contract method 0xd51b9e93.
//
// Solidity: function isCandidate(_candidate address) constant returns(bool)
func (_XDCValidator *XDCValidatorCaller) IsCandidate(opts *bind.CallOpts, _candidate common.Address) (bool, error) {
	var (
		ret0 = new(bool)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "isCandidate", _candidate)
	return *ret0, err
}

// IsCandidate is a free data retrieval call binding the contract method 0xd51b9e93.
//
// Solidity: function isCandidate(_candidate address) constant returns(bool)
func (_XDCValidator *XDCValidatorSession) IsCandidate(_candidate common.Address) (bool, error) {
	return _XDCValidator.Contract.IsCandidate(&_XDCValidator.CallOpts, _candidate)
}

// IsCandidate is a free data retrieval call binding the contract method 0xd51b9e93.
//
// Solidity: function isCandidate(_candidate address) constant returns(bool)
func (_XDCValidator *XDCValidatorCallerSession) IsCandidate(_candidate common.Address) (bool, error) {
	return _XDCValidator.Contract.IsCandidate(&_XDCValidator.CallOpts, _candidate)
}

// MaxValidatorNumber is a free data retrieval call binding the contract method 0xd09f1ab4.
//
// Solidity: function maxValidatorNumber() constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) MaxValidatorNumber(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "maxValidatorNumber")
	return *ret0, err
}

// MaxValidatorNumber is a free data retrieval call binding the contract method 0xd09f1ab4.
//
// Solidity: function maxValidatorNumber() constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) MaxValidatorNumber() (*big.Int, error) {
	return _XDCValidator.Contract.MaxValidatorNumber(&_XDCValidator.CallOpts)
}

// MaxValidatorNumber is a free data retrieval call binding the contract method 0xd09f1ab4.
//
// Solidity: function maxValidatorNumber() constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) MaxValidatorNumber() (*big.Int, error) {
	return _XDCValidator.Contract.MaxValidatorNumber(&_XDCValidator.CallOpts)
}

// MinCandidateCap is a free data retrieval call binding the contract method 0xd55b7dff.
//
// Solidity: function minCandidateCap() constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) MinCandidateCap(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "minCandidateCap")
	return *ret0, err
}

// MinCandidateCap is a free data retrieval call binding the contract method 0xd55b7dff.
//
// Solidity: function minCandidateCap() constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) MinCandidateCap() (*big.Int, error) {
	return _XDCValidator.Contract.MinCandidateCap(&_XDCValidator.CallOpts)
}

// MinCandidateCap is a free data retrieval call binding the contract method 0xd55b7dff.
//
// Solidity: function minCandidateCap() constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) MinCandidateCap() (*big.Int, error) {
	return _XDCValidator.Contract.MinCandidateCap(&_XDCValidator.CallOpts)
}

// MinVoterCap is a free data retrieval call binding the contract method 0xf8ac9dd5.
//
// Solidity: function minVoterCap() constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) MinVoterCap(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "minVoterCap")
	return *ret0, err
}

// MinVoterCap is a free data retrieval call binding the contract method 0xf8ac9dd5.
//
// Solidity: function minVoterCap() constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) MinVoterCap() (*big.Int, error) {
	return _XDCValidator.Contract.MinVoterCap(&_XDCValidator.CallOpts)
}

// MinVoterCap is a free data retrieval call binding the contract method 0xf8ac9dd5.
//
// Solidity: function minVoterCap() constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) MinVoterCap() (*big.Int, error) {
	return _XDCValidator.Contract.MinVoterCap(&_XDCValidator.CallOpts)
}

// OwnerCount is a free data retrieval call binding the contract method 0x0db02622.
//
// Solidity: function ownerCount() constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) OwnerCount(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "ownerCount")
	return *ret0, err
}

// OwnerCount is a free data retrieval call binding the contract method 0x0db02622.
//
// Solidity: function ownerCount() constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) OwnerCount() (*big.Int, error) {
	return _XDCValidator.Contract.OwnerCount(&_XDCValidator.CallOpts)
}

// OwnerCount is a free data retrieval call binding the contract method 0x0db02622.
//
// Solidity: function ownerCount() constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) OwnerCount() (*big.Int, error) {
	return _XDCValidator.Contract.OwnerCount(&_XDCValidator.CallOpts)
}

// OwnerToCandidate is a free data retrieval call binding the contract method 0x2a3640b1.
//
// Solidity: function ownerToCandidate( address,  uint256) constant returns(address)
func (_XDCValidator *XDCValidatorCaller) OwnerToCandidate(opts *bind.CallOpts, arg0 common.Address, arg1 *big.Int) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "ownerToCandidate", arg0, arg1)
	return *ret0, err
}

// OwnerToCandidate is a free data retrieval call binding the contract method 0x2a3640b1.
//
// Solidity: function ownerToCandidate( address,  uint256) constant returns(address)
func (_XDCValidator *XDCValidatorSession) OwnerToCandidate(arg0 common.Address, arg1 *big.Int) (common.Address, error) {
	return _XDCValidator.Contract.OwnerToCandidate(&_XDCValidator.CallOpts, arg0, arg1)
}

// OwnerToCandidate is a free data retrieval call binding the contract method 0x2a3640b1.
//
// Solidity: function ownerToCandidate( address,  uint256) constant returns(address)
func (_XDCValidator *XDCValidatorCallerSession) OwnerToCandidate(arg0 common.Address, arg1 *big.Int) (common.Address, error) {
	return _XDCValidator.Contract.OwnerToCandidate(&_XDCValidator.CallOpts, arg0, arg1)
}

// Owners is a free data retrieval call binding the contract method 0x025e7c27.
//
// Solidity: function owners( uint256) constant returns(address)
func (_XDCValidator *XDCValidatorCaller) Owners(opts *bind.CallOpts, arg0 *big.Int) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "owners", arg0)
	return *ret0, err
}

// Owners is a free data retrieval call binding the contract method 0x025e7c27.
//
// Solidity: function owners( uint256) constant returns(address)
func (_XDCValidator *XDCValidatorSession) Owners(arg0 *big.Int) (common.Address, error) {
	return _XDCValidator.Contract.Owners(&_XDCValidator.CallOpts, arg0)
}

// Owners is a free data retrieval call binding the contract method 0x025e7c27.
//
// Solidity: function owners( uint256) constant returns(address)
func (_XDCValidator *XDCValidatorCallerSession) Owners(arg0 *big.Int) (common.Address, error) {
	return _XDCValidator.Contract.Owners(&_XDCValidator.CallOpts, arg0)
}

// VoterWithdrawDelay is a free data retrieval call binding the contract method 0xa9ff959e.
//
// Solidity: function voterWithdrawDelay() constant returns(uint256)
func (_XDCValidator *XDCValidatorCaller) VoterWithdrawDelay(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
	}
	err := _XDCValidator.contract.Call(opts, out, "voterWithdrawDelay")
	return *ret0, err
}

// VoterWithdrawDelay is a free data retrieval call binding the contract method 0xa9ff959e.
//
// Solidity: function voterWithdrawDelay() constant returns(uint256)
func (_XDCValidator *XDCValidatorSession) VoterWithdrawDelay() (*big.Int, error) {
	return _XDCValidator.Contract.VoterWithdrawDelay(&_XDCValidator.CallOpts)
}

// VoterWithdrawDelay is a free data retrieval call binding the contract method 0xa9ff959e.
//
// Solidity: function voterWithdrawDelay() constant returns(uint256)
func (_XDCValidator *XDCValidatorCallerSession) VoterWithdrawDelay() (*big.Int, error) {
	return _XDCValidator.Contract.VoterWithdrawDelay(&_XDCValidator.CallOpts)
}

// Propose is a paid mutator transaction binding the contract method 0x01267951.
//
// Solidity: function propose(_candidate address) returns()
func (_XDCValidator *XDCValidatorTransactor) Propose(opts *bind.TransactOpts, _candidate common.Address) (*types.Transaction, error) {
	return _XDCValidator.contract.Transact(opts, "propose", _candidate)
}

// Propose is a paid mutator transaction binding the contract method 0x01267951.
//
// Solidity: function propose(_candidate address) returns()
func (_XDCValidator *XDCValidatorSession) Propose(_candidate common.Address) (*types.Transaction, error) {
	return _XDCValidator.Contract.Propose(&_XDCValidator.TransactOpts, _candidate)
}

// Propose is a paid mutator transaction binding the contract method 0x01267951.
//
// Solidity: function propose(_candidate address) returns()
func (_XDCValidator *XDCValidatorTransactorSession) Propose(_candidate common.Address) (*types.Transaction, error) {
	return _XDCValidator.Contract.Propose(&_XDCValidator.TransactOpts, _candidate)
}

// Resign is a paid mutator transaction binding the contract method 0xae6e43f5.
//
// Solidity: function resign(_candidate address) returns()
func (_XDCValidator *XDCValidatorTransactor) Resign(opts *bind.TransactOpts, _candidate common.Address) (*types.Transaction, error) {
	return _XDCValidator.contract.Transact(opts, "resign", _candidate)
}

// Resign is a paid mutator transaction binding the contract method 0xae6e43f5.
//
// Solidity: function resign(_candidate address) returns()
func (_XDCValidator *XDCValidatorSession) Resign(_candidate common.Address) (*types.Transaction, error) {
	return _XDCValidator.Contract.Resign(&_XDCValidator.TransactOpts, _candidate)
}

// Resign is a paid mutator transaction binding the contract method 0xae6e43f5.
//
// Solidity: function resign(_candidate address) returns()
func (_XDCValidator *XDCValidatorTransactorSession) Resign(_candidate common.Address) (*types.Transaction, error) {
	return _XDCValidator.Contract.Resign(&_XDCValidator.TransactOpts, _candidate)
}

// Unvote is a paid mutator transaction binding the contract method 0x02aa9be2.
//
// Solidity: function unvote(_candidate address, _cap uint256) returns()
func (_XDCValidator *XDCValidatorTransactor) Unvote(opts *bind.TransactOpts, _candidate common.Address, _cap *big.Int) (*types.Transaction, error) {
	return _XDCValidator.contract.Transact(opts, "unvote", _candidate, _cap)
}

// Unvote is a paid mutator transaction binding the contract method 0x02aa9be2.
//
// Solidity: function unvote(_candidate address, _cap uint256) returns()
func (_XDCValidator *XDCValidatorSession) Unvote(_candidate common.Address, _cap *big.Int) (*types.Transaction, error) {
	return _XDCValidator.Contract.Unvote(&_XDCValidator.TransactOpts, _candidate, _cap)
}

// Unvote is a paid mutator transaction binding the contract method 0x02aa9be2.
//
// Solidity: function unvote(_candidate address, _cap uint256) returns()
func (_XDCValidator *XDCValidatorTransactorSession) Unvote(_candidate common.Address, _cap *big.Int) (*types.Transaction, error) {
	return _XDCValidator.Contract.Unvote(&_XDCValidator.TransactOpts, _candidate, _cap)
}

// UploadKYC is a paid mutator transaction binding the contract method 0xf5c95125.
//
// Solidity: function uploadKYC(kychash string) returns()
func (_XDCValidator *XDCValidatorTransactor) UploadKYC(opts *bind.TransactOpts, kychash string) (*types.Transaction, error) {
	return _XDCValidator.contract.Transact(opts, "uploadKYC", kychash)
}

// UploadKYC is a paid mutator transaction binding the contract method 0xf5c95125.
//
// Solidity: function uploadKYC(kychash string) returns()
func (_XDCValidator *XDCValidatorSession) UploadKYC(kychash string) (*types.Transaction, error) {
	return _XDCValidator.Contract.UploadKYC(&_XDCValidator.TransactOpts, kychash)
}

// UploadKYC is a paid mutator transaction binding the contract method 0xf5c95125.
//
// Solidity: function uploadKYC(kychash string) returns()
func (_XDCValidator *XDCValidatorTransactorSession) UploadKYC(kychash string) (*types.Transaction, error) {
	return _XDCValidator.Contract.UploadKYC(&_XDCValidator.TransactOpts, kychash)
}

// Vote is a paid mutator transaction binding the contract method 0x6dd7d8ea.
//
// Solidity: function vote(_candidate address) returns()
func (_XDCValidator *XDCValidatorTransactor) Vote(opts *bind.TransactOpts, _candidate common.Address) (*types.Transaction, error) {
	return _XDCValidator.contract.Transact(opts, "vote", _candidate)
}

// Vote is a paid mutator transaction binding the contract method 0x6dd7d8ea.
//
// Solidity: function vote(_candidate address) returns()
func (_XDCValidator *XDCValidatorSession) Vote(_candidate common.Address) (*types.Transaction, error) {
	return _XDCValidator.Contract.Vote(&_XDCValidator.TransactOpts, _candidate)
}

// Vote is a paid mutator transaction binding the contract method 0x6dd7d8ea.
//
// Solidity: function vote(_candidate address) returns()
func (_XDCValidator *XDCValidatorTransactorSession) Vote(_candidate common.Address) (*types.Transaction, error) {
	return _XDCValidator.Contract.Vote(&_XDCValidator.TransactOpts, _candidate)
}

// VoteInvalidKYC is a paid mutator transaction binding the contract method 0xf2ee3c7d.
//
// Solidity: function voteInvalidKYC(_invalidCandidate address) returns()
func (_XDCValidator *XDCValidatorTransactor) VoteInvalidKYC(opts *bind.TransactOpts, _invalidCandidate common.Address) (*types.Transaction, error) {
	return _XDCValidator.contract.Transact(opts, "voteInvalidKYC", _invalidCandidate)
}

// VoteInvalidKYC is a paid mutator transaction binding the contract method 0xf2ee3c7d.
//
// Solidity: function voteInvalidKYC(_invalidCandidate address) returns()
func (_XDCValidator *XDCValidatorSession) VoteInvalidKYC(_invalidCandidate common.Address) (*types.Transaction, error) {
	return _XDCValidator.Contract.VoteInvalidKYC(&_XDCValidator.TransactOpts, _invalidCandidate)
}

// VoteInvalidKYC is a paid mutator transaction binding the contract method 0xf2ee3c7d.
//
// Solidity: function voteInvalidKYC(_invalidCandidate address) returns()
func (_XDCValidator *XDCValidatorTransactorSession) VoteInvalidKYC(_invalidCandidate common.Address) (*types.Transaction, error) {
	return _XDCValidator.Contract.VoteInvalidKYC(&_XDCValidator.TransactOpts, _invalidCandidate)
}

// Withdraw is a paid mutator transaction binding the contract method 0x441a3e70.
//
// Solidity: function withdraw(_blockNumber uint256, _index uint256) returns()
func (_XDCValidator *XDCValidatorTransactor) Withdraw(opts *bind.TransactOpts, _blockNumber *big.Int, _index *big.Int) (*types.Transaction, error) {
	return _XDCValidator.contract.Transact(opts, "withdraw", _blockNumber, _index)
}

// Withdraw is a paid mutator transaction binding the contract method 0x441a3e70.
//
// Solidity: function withdraw(_blockNumber uint256, _index uint256) returns()
func (_XDCValidator *XDCValidatorSession) Withdraw(_blockNumber *big.Int, _index *big.Int) (*types.Transaction, error) {
	return _XDCValidator.Contract.Withdraw(&_XDCValidator.TransactOpts, _blockNumber, _index)
}

// Withdraw is a paid mutator transaction binding the contract method 0x441a3e70.
//
// Solidity: function withdraw(_blockNumber uint256, _index uint256) returns()
func (_XDCValidator *XDCValidatorTransactorSession) Withdraw(_blockNumber *big.Int, _index *big.Int) (*types.Transaction, error) {
	return _XDCValidator.Contract.Withdraw(&_XDCValidator.TransactOpts, _blockNumber, _index)
}

// XDCValidatorInvalidatedNodeIterator is returned from FilterInvalidatedNode and is used to iterate over the raw logs and unpacked data for InvalidatedNode events raised by the XDCValidator contract.
type XDCValidatorInvalidatedNodeIterator struct {
	Event *XDCValidatorInvalidatedNode // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *XDCValidatorInvalidatedNodeIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(XDCValidatorInvalidatedNode)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(XDCValidatorInvalidatedNode)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *XDCValidatorInvalidatedNodeIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *XDCValidatorInvalidatedNodeIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// XDCValidatorInvalidatedNode represents a InvalidatedNode event raised by the XDCValidator contract.
type XDCValidatorInvalidatedNode struct {
	MasternodeOwner common.Address
	Masternodes     []common.Address
	Raw             types.Log // Blockchain specific contextual infos
}

// FilterInvalidatedNode is a free log retrieval operation binding the contract event 0xe18d61a5bf4aa2ab40afc88aa9039d27ae17ff4ec1c65f5f414df6f02ce8b35e.
//
// Solidity: event InvalidatedNode(_masternodeOwner address, _masternodes address[])
func (_XDCValidator *XDCValidatorFilterer) FilterInvalidatedNode(opts *bind.FilterOpts) (*XDCValidatorInvalidatedNodeIterator, error) {

	logs, sub, err := _XDCValidator.contract.FilterLogs(opts, "InvalidatedNode")
	if err != nil {
		return nil, err
	}
	return &XDCValidatorInvalidatedNodeIterator{contract: _XDCValidator.contract, event: "InvalidatedNode", logs: logs, sub: sub}, nil
}

// WatchInvalidatedNode is a free log subscription operation binding the contract event 0xe18d61a5bf4aa2ab40afc88aa9039d27ae17ff4ec1c65f5f414df6f02ce8b35e.
//
// Solidity: event InvalidatedNode(_masternodeOwner address, _masternodes address[])
func (_XDCValidator *XDCValidatorFilterer) WatchInvalidatedNode(opts *bind.WatchOpts, sink chan<- *XDCValidatorInvalidatedNode) (event.Subscription, error) {

	logs, sub, err := _XDCValidator.contract.WatchLogs(opts, "InvalidatedNode")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(XDCValidatorInvalidatedNode)
				if err := _XDCValidator.contract.UnpackLog(event, "InvalidatedNode", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// XDCValidatorProposeIterator is returned from FilterPropose and is used to iterate over the raw logs and unpacked data for Propose events raised by the XDCValidator contract.
type XDCValidatorProposeIterator struct {
	Event *XDCValidatorPropose // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *XDCValidatorProposeIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(XDCValidatorPropose)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(XDCValidatorPropose)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *XDCValidatorProposeIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *XDCValidatorProposeIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// XDCValidatorPropose represents a Propose event raised by the XDCValidator contract.
type XDCValidatorPropose struct {
	Owner     common.Address
	Candidate common.Address
	Cap       *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterPropose is a free log retrieval operation binding the contract event 0x7635f1d87b47fba9f2b09e56eb4be75cca030e0cb179c1602ac9261d39a8f5c1.
//
// Solidity: event Propose(_owner address, _candidate address, _cap uint256)
func (_XDCValidator *XDCValidatorFilterer) FilterPropose(opts *bind.FilterOpts) (*XDCValidatorProposeIterator, error) {

	logs, sub, err := _XDCValidator.contract.FilterLogs(opts, "Propose")
	if err != nil {
		return nil, err
	}
	return &XDCValidatorProposeIterator{contract: _XDCValidator.contract, event: "Propose", logs: logs, sub: sub}, nil
}

// WatchPropose is a free log subscription operation binding the contract event 0x7635f1d87b47fba9f2b09e56eb4be75cca030e0cb179c1602ac9261d39a8f5c1.
//
// Solidity: event Propose(_owner address, _candidate address, _cap uint256)
func (_XDCValidator *XDCValidatorFilterer) WatchPropose(opts *bind.WatchOpts, sink chan<- *XDCValidatorPropose) (event.Subscription, error) {

	logs, sub, err := _XDCValidator.contract.WatchLogs(opts, "Propose")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(XDCValidatorPropose)
				if err := _XDCValidator.contract.UnpackLog(event, "Propose", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// XDCValidatorResignIterator is returned from FilterResign and is used to iterate over the raw logs and unpacked data for Resign events raised by the XDCValidator contract.
type XDCValidatorResignIterator struct {
	Event *XDCValidatorResign // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *XDCValidatorResignIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(XDCValidatorResign)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(XDCValidatorResign)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *XDCValidatorResignIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *XDCValidatorResignIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// XDCValidatorResign represents a Resign event raised by the XDCValidator contract.
type XDCValidatorResign struct {
	Owner     common.Address
	Candidate common.Address
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterResign is a free log retrieval operation binding the contract event 0x4edf3e325d0063213a39f9085522994a1c44bea5f39e7d63ef61260a1e58c6d3.
//
// Solidity: event Resign(_owner address, _candidate address)
func (_XDCValidator *XDCValidatorFilterer) FilterResign(opts *bind.FilterOpts) (*XDCValidatorResignIterator, error) {

	logs, sub, err := _XDCValidator.contract.FilterLogs(opts, "Resign")
	if err != nil {
		return nil, err
	}
	return &XDCValidatorResignIterator{contract: _XDCValidator.contract, event: "Resign", logs: logs, sub: sub}, nil
}

// WatchResign is a free log subscription operation binding the contract event 0x4edf3e325d0063213a39f9085522994a1c44bea5f39e7d63ef61260a1e58c6d3.
//
// Solidity: event Resign(_owner address, _candidate address)
func (_XDCValidator *XDCValidatorFilterer) WatchResign(opts *bind.WatchOpts, sink chan<- *XDCValidatorResign) (event.Subscription, error) {

	logs, sub, err := _XDCValidator.contract.WatchLogs(opts, "Resign")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(XDCValidatorResign)
				if err := _XDCValidator.contract.UnpackLog(event, "Resign", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// XDCValidatorUnvoteIterator is returned from FilterUnvote and is used to iterate over the raw logs and unpacked data for Unvote events raised by the XDCValidator contract.
type XDCValidatorUnvoteIterator struct {
	Event *XDCValidatorUnvote // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *XDCValidatorUnvoteIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(XDCValidatorUnvote)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(XDCValidatorUnvote)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *XDCValidatorUnvoteIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *XDCValidatorUnvoteIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// XDCValidatorUnvote represents a Unvote event raised by the XDCValidator contract.
type XDCValidatorUnvote struct {
	Voter     common.Address
	Candidate common.Address
	Cap       *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterUnvote is a free log retrieval operation binding the contract event 0xaa0e554f781c3c3b2be110a0557f260f11af9a8aa2c64bc1e7a31dbb21e32fa2.
//
// Solidity: event Unvote(_voter address, _candidate address, _cap uint256)
func (_XDCValidator *XDCValidatorFilterer) FilterUnvote(opts *bind.FilterOpts) (*XDCValidatorUnvoteIterator, error) {

	logs, sub, err := _XDCValidator.contract.FilterLogs(opts, "Unvote")
	if err != nil {
		return nil, err
	}
	return &XDCValidatorUnvoteIterator{contract: _XDCValidator.contract, event: "Unvote", logs: logs, sub: sub}, nil
}

// WatchUnvote is a free log subscription operation binding the contract event 0xaa0e554f781c3c3b2be110a0557f260f11af9a8aa2c64bc1e7a31dbb21e32fa2.
//
// Solidity: event Unvote(_voter address, _candidate address, _cap uint256)
func (_XDCValidator *XDCValidatorFilterer) WatchUnvote(opts *bind.WatchOpts, sink chan<- *XDCValidatorUnvote) (event.Subscription, error) {

	logs, sub, err := _XDCValidator.contract.WatchLogs(opts, "Unvote")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(XDCValidatorUnvote)
				if err := _XDCValidator.contract.UnpackLog(event, "Unvote", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// XDCValidatorUploadedKYCIterator is returned from FilterUploadedKYC and is used to iterate over the raw logs and unpacked data for UploadedKYC events raised by the XDCValidator contract.
type XDCValidatorUploadedKYCIterator struct {
	Event *XDCValidatorUploadedKYC // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *XDCValidatorUploadedKYCIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(XDCValidatorUploadedKYC)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(XDCValidatorUploadedKYC)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *XDCValidatorUploadedKYCIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *XDCValidatorUploadedKYCIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// XDCValidatorUploadedKYC represents a UploadedKYC event raised by the XDCValidator contract.
type XDCValidatorUploadedKYC struct {
	Owner   common.Address
	KycHash string
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterUploadedKYC is a free log retrieval operation binding the contract event 0x949360d814b28a3b393a68909efe1fee120ee09cac30f360a0f80ab5415a611a.
//
// Solidity: event UploadedKYC(_owner address, kycHash string)
func (_XDCValidator *XDCValidatorFilterer) FilterUploadedKYC(opts *bind.FilterOpts) (*XDCValidatorUploadedKYCIterator, error) {

	logs, sub, err := _XDCValidator.contract.FilterLogs(opts, "UploadedKYC")
	if err != nil {
		return nil, err
	}
	return &XDCValidatorUploadedKYCIterator{contract: _XDCValidator.contract, event: "UploadedKYC", logs: logs, sub: sub}, nil
}

// WatchUploadedKYC is a free log subscription operation binding the contract event 0x949360d814b28a3b393a68909efe1fee120ee09cac30f360a0f80ab5415a611a.
//
// Solidity: event UploadedKYC(_owner address, kycHash string)
func (_XDCValidator *XDCValidatorFilterer) WatchUploadedKYC(opts *bind.WatchOpts, sink chan<- *XDCValidatorUploadedKYC) (event.Subscription, error) {

	logs, sub, err := _XDCValidator.contract.WatchLogs(opts, "UploadedKYC")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(XDCValidatorUploadedKYC)
				if err := _XDCValidator.contract.UnpackLog(event, "UploadedKYC", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// XDCValidatorVoteIterator is returned from FilterVote and is used to iterate over the raw logs and unpacked data for Vote events raised by the XDCValidator contract.
type XDCValidatorVoteIterator struct {
	Event *XDCValidatorVote // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *XDCValidatorVoteIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(XDCValidatorVote)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(XDCValidatorVote)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *XDCValidatorVoteIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *XDCValidatorVoteIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// XDCValidatorVote represents a Vote event raised by the XDCValidator contract.
type XDCValidatorVote struct {
	Voter     common.Address
	Candidate common.Address
	Cap       *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterVote is a free log retrieval operation binding the contract event 0x66a9138482c99e9baf08860110ef332cc0c23b4a199a53593d8db0fc8f96fbfc.
//
// Solidity: event Vote(_voter address, _candidate address, _cap uint256)
func (_XDCValidator *XDCValidatorFilterer) FilterVote(opts *bind.FilterOpts) (*XDCValidatorVoteIterator, error) {

	logs, sub, err := _XDCValidator.contract.FilterLogs(opts, "Vote")
	if err != nil {
		return nil, err
	}
	return &XDCValidatorVoteIterator{contract: _XDCValidator.contract, event: "Vote", logs: logs, sub: sub}, nil
}

// WatchVote is a free log subscription operation binding the contract event 0x66a9138482c99e9baf08860110ef332cc0c23b4a199a53593d8db0fc8f96fbfc.
//
// Solidity: event Vote(_voter address, _candidate address, _cap uint256)
func (_XDCValidator *XDCValidatorFilterer) WatchVote(opts *bind.WatchOpts, sink chan<- *XDCValidatorVote) (event.Subscription, error) {

	logs, sub, err := _XDCValidator.contract.WatchLogs(opts, "Vote")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(XDCValidatorVote)
				if err := _XDCValidator.contract.UnpackLog(event, "Vote", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// XDCValidatorWithdrawIterator is returned from FilterWithdraw and is used to iterate over the raw logs and unpacked data for Withdraw events raised by the XDCValidator contract.
type XDCValidatorWithdrawIterator struct {
	Event *XDCValidatorWithdraw // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *XDCValidatorWithdrawIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(XDCValidatorWithdraw)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(XDCValidatorWithdraw)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *XDCValidatorWithdrawIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *XDCValidatorWithdrawIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// XDCValidatorWithdraw represents a Withdraw event raised by the XDCValidator contract.
type XDCValidatorWithdraw struct {
	Owner       common.Address
	BlockNumber *big.Int
	Cap         *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterWithdraw is a free log retrieval operation binding the contract event 0xf279e6a1f5e320cca91135676d9cb6e44ca8a08c0b88342bcdb1144f6511b568.
//
// Solidity: event Withdraw(_owner address, _blockNumber uint256, _cap uint256)
func (_XDCValidator *XDCValidatorFilterer) FilterWithdraw(opts *bind.FilterOpts) (*XDCValidatorWithdrawIterator, error) {

	logs, sub, err := _XDCValidator.contract.FilterLogs(opts, "Withdraw")
	if err != nil {
		return nil, err
	}
	return &XDCValidatorWithdrawIterator{contract: _XDCValidator.contract, event: "Withdraw", logs: logs, sub: sub}, nil
}

// WatchWithdraw is a free log subscription operation binding the contract event 0xf279e6a1f5e320cca91135676d9cb6e44ca8a08c0b88342bcdb1144f6511b568.
//
// Solidity: event Withdraw(_owner address, _blockNumber uint256, _cap uint256)
func (_XDCValidator *XDCValidatorFilterer) WatchWithdraw(opts *bind.WatchOpts, sink chan<- *XDCValidatorWithdraw) (event.Subscription, error) {

	logs, sub, err := _XDCValidator.contract.WatchLogs(opts, "Withdraw")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(XDCValidatorWithdraw)
				if err := _XDCValidator.contract.UnpackLog(event, "Withdraw", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}
