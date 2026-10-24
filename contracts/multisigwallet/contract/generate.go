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
// along with XDPoSChain. If not, see <http://www.gnu.org/licenses/>.

// Regenerate the bindings in this directory with: go generate ./contracts/...

package contract

//go:generate go run github.com/XinFinOrg/XDPoSChain/cmd/abigen --pkg contract --combined-json multisigwallet.json --out multisigwallet.go
