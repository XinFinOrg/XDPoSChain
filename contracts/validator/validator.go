// Copyright (c) 2018 XDPoSChain
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package validator

import (
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/contracts/validator/contract"
)

type Validator struct {
	*contract.XDCValidatorSession
	contractBackend bind.ContractBackend
}

func NewValidator(transactOpts *bind.TransactOpts, contractAddr common.Address, contractBackend bind.ContractBackend) (*Validator, error) {
	validator, err := contract.NewXDCValidator(contractAddr, contractBackend)
	if err != nil {
		return nil, err
	}

	return &Validator{
		&contract.XDCValidatorSession{
			Contract:     validator,
			TransactOpts: *transactOpts,
		},
		contractBackend,
	}, nil
}

func DeployValidator(transactOpts *bind.TransactOpts, contractBackend bind.ContractBackend, validatorAddress []common.Address, caps []*big.Int, ownerAddress common.Address, minDeposit *big.Int, minVoterCap *big.Int) (common.Address, *Validator, error) {
	if minDeposit == nil {
		minDeposit = new(big.Int)
		minDeposit.SetString("10000000", 10)         // 10M
		minDeposit.Mul(minDeposit, big.NewInt(1e18)) //convert to wei
	}
	if minVoterCap == nil {
		minVoterCap = new(big.Int).Set(minDeposit)
		minVoterCap.Div(minVoterCap, big.NewInt(400)) //set votercap to 0.25% of candidate deposit (25K XDC)
	}

	// Deposit 10M XDC
	// Min Voter Cap 25K XDC
	// 108 masternodes
	// Candidate Delay Withdraw 30 days = 1296000 blocks
	// Voter Delay Withdraw 10 days = 432000 blocks
	validatorAddr, _, _, err := contract.DeployXDCValidator(transactOpts, contractBackend, validatorAddress, caps, ownerAddress, minDeposit, minVoterCap, big.NewInt(108), big.NewInt(1296000), big.NewInt(432000))
	if err != nil {
		return validatorAddr, nil, err
	}

	validator, err := NewValidator(transactOpts, validatorAddr, contractBackend)
	if err != nil {
		return validatorAddr, nil, err
	}

	return validatorAddr, validator, nil
}
