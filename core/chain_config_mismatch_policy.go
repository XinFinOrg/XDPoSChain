package core

import (
	"fmt"
	"strings"
)

// ChainConfigMismatchPolicy controls startup behavior when the resolved runtime
// chain config is incompatible with the stored chain config.
type ChainConfigMismatchPolicy string

const (
	MismatchExit             ChainConfigMismatchPolicy = "exit"
	MismatchRewindAndUpdate  ChainConfigMismatchPolicy = "rewind-and-update"
	MismatchUpdateConfigOnly ChainConfigMismatchPolicy = "update-config-only"
	MismatchIgnoreMismatch   ChainConfigMismatchPolicy = "ignore-mismatch"
)

const DefaultChainConfigMismatchPolicy = MismatchExit

func (p ChainConfigMismatchPolicy) String() string {
	if p == "" {
		return string(DefaultChainConfigMismatchPolicy)
	}
	return string(p)
}

// NormalizeChainConfigMismatchPolicy converts empty policy values to default.
func NormalizeChainConfigMismatchPolicy(policy ChainConfigMismatchPolicy) ChainConfigMismatchPolicy {
	if policy == "" {
		return DefaultChainConfigMismatchPolicy
	}
	return policy
}

// ParseChainConfigMismatchPolicy parses and validates a startup mismatch policy.
func ParseChainConfigMismatchPolicy(input string) (ChainConfigMismatchPolicy, error) {
	policy := NormalizeChainConfigMismatchPolicy(ChainConfigMismatchPolicy(strings.TrimSpace(input)))
	switch policy {
	case MismatchExit,
		MismatchRewindAndUpdate,
		MismatchUpdateConfigOnly,
		MismatchIgnoreMismatch:
		return policy, nil
	default:
		return "", fmt.Errorf("invalid chain config mismatch policy %q (supported: %q, %q, %q, %q)", input,
			MismatchExit,
			MismatchRewindAndUpdate,
			MismatchUpdateConfigOnly,
			MismatchIgnoreMismatch,
		)
	}
}

// ValidateAndNormalizeCompatPolicy normalizes and validates a mismatch policy.
// It converts empty policy values to the default and rejects unknown values.
// NOTE: enforcing the "exit" behavior when compatErr is non-nil is handled
// by the blockchain open path.
func ValidateAndNormalizeCompatPolicy(policy ChainConfigMismatchPolicy) (ChainConfigMismatchPolicy, error) {
	return ParseChainConfigMismatchPolicy(string(policy))
}
