package common

import "math/big"

// CloneBigInt returns a deep copy of value. It returns nil if value is nil.
func CloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}
