package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"testing"
	"unsafe"

	"github.com/XinFinOrg/XDPoSChain/params"
)

var chainConfigDigestCoveredFields = []string{
	"BerlinBlock",
	"ByzantiumBlock",
	"CancunBlock",
	"ChainID",
	"Clique",
	"ConstantinopleBlock",
	"DAOForkBlock",
	"DAOForkSupport",
	"DenylistBlock",
	"DynamicGasLimitBlock",
	"EIP150Block",
	"EIP155Block",
	"EIP158Block",
	"EIP1559Block",
	"Ethash",
	"Gas50xBlock",
	"HomesteadBlock",
	"IstanbulBlock",
	"LendingRegistrationSMC",
	"LondonBlock",
	"MergeBlock",
	"OsakaBlock",
	"PetersburgBlock",
	"PragueBlock",
	"RelayerRegistrationSMC",
	"ShanghaiBlock",
	"TIP2019Block",
	"TIPEpochHalvingBlock",
	"TIPIncreaseMasternodesBlock",
	"TIPNoHalvingMNRewardBlock",
	"TIPRandomizeBlock",
	"TIPSigningBlock",
	"TIPTRC21FeeBlock",
	"TIPUpgradePenaltyBlock",
	"TIPUpgradeRewardBlock",
	"TIPXDCXCancellationFeeBlock",
	"TIPXDCXBlock",
	"TIPXDCXLendingBlock",
	"TIPXDCXMinerDisableBlock",
	"TIPXDCXReceiverDisableBlock",
	"TRC21IssuerSMC",
	"XDCXListingSMC",
	"XDPoS",
}

// chainConfigSemanticallyEqual compares chain configs while ignoring JSON field
// presence bookkeeping.
func chainConfigSemanticallyEqual(a, b *params.ChainConfig) bool {
	return a.Equal(b)
}

// TestChainConfigSemanticallyEqualRejectsScalarDrift tests chain config semantically equal rejects scalar drift.
func TestChainConfigSemanticallyEqualRejectsScalarDrift(t *testing.T) {
	left := &params.ChainConfig{
		ChainID:          big.NewInt(1),
		DAOForkSupport:   false,
		TIPTRC21FeeBlock: big.NewInt(0),
		Ethash:           new(params.EthashConfig),
	}
	right := left.Clone()
	right.DAOForkSupport = true

	if chainConfigSemanticallyEqual(left, right) {
		t.Fatalf("expected semantic comparison to reject scalar drift: left=%v right=%v", left, right)
	}
}

// TestChainConfigSemanticallyEqualRejectsXDPoSV2AllConfigsDrift tests chain config semantically equal rejects xd po sv 2 all configs drift.
func TestChainConfigSemanticallyEqualRejectsXDPoSV2AllConfigsDrift(t *testing.T) {
	left := params.TestnetChainConfig.Clone()
	right := params.TestnetChainConfig.Clone()
	right.XDPoS = right.XDPoS.Clone()
	right.XDPoS.V2 = right.XDPoS.V2.Clone()
	right.XDPoS.V2.AllConfigs = map[uint64]*params.V2Config{}
	for key, cfg := range right.XDPoS.V2.AllConfigs {
		right.XDPoS.V2.AllConfigs[key] = cfg.Clone()
	}
	right.XDPoS.V2.AllConfigs[999999] = right.XDPoS.V2.CurrentConfig.Clone()

	if chainConfigSemanticallyEqual(left, right) {
		t.Fatalf("expected semantic comparison to reject XDPoS V2 AllConfigs drift")
	}
}

// TestChainConfigJSONEqualFastPathPointerIdentity tests chain config json equal fast path pointer identity.
func TestChainConfigJSONEqualFastPathPointerIdentity(t *testing.T) {
	deps := defaultGenesisDeps
	marshalCalls := 0
	deps.jsonMarshal = func(v any) ([]byte, error) {
		marshalCalls++
		return json.Marshal(v)
	}

	cfg := params.TestnetChainConfig.Clone()
	equal, err := deps.chainConfigJSONEqual(cfg, cfg)
	if err != nil {
		t.Fatalf("chainConfigJSONEqual failed: %v", err)
	}
	if !equal {
		t.Fatal("expected identical pointers to compare equal")
	}
	if marshalCalls != 0 {
		t.Fatalf("expected pointer fast path to avoid marshal, got %d calls", marshalCalls)
	}
}

// TestChainConfigJSONEqualFastPathStructuralEquality tests chain config json equal fast path structural equality.
func TestChainConfigJSONEqualFastPathStructuralEquality(t *testing.T) {
	deps := defaultGenesisDeps
	marshalCalls := 0
	deps.jsonMarshal = func(v any) ([]byte, error) {
		marshalCalls++
		return json.Marshal(v)
	}

	left := params.TestnetChainConfig.Clone()
	right := params.TestnetChainConfig.Clone()

	equal, err := deps.chainConfigJSONEqual(left, right)
	if err != nil {
		t.Fatalf("chainConfigJSONEqual failed: %v", err)
	}
	if !equal {
		t.Fatal("expected structurally equal configs to compare equal")
	}
	if marshalCalls != 0 {
		t.Fatalf("expected structural fast path to avoid marshal, got %d calls", marshalCalls)
	}
}

// TestChainConfigJSONEqualFastPathRejectsForkDrift tests chain config json equal fast path rejects fork drift.
func TestChainConfigJSONEqualFastPathRejectsForkDrift(t *testing.T) {
	deps := defaultGenesisDeps
	marshalCalls := 0
	deps.jsonMarshal = func(v any) ([]byte, error) {
		marshalCalls++
		return json.Marshal(v)
	}

	left := params.TestnetChainConfig.Clone()
	right := params.TestnetChainConfig.Clone()
	right.BerlinBlock = big.NewInt(123456)

	equal, err := deps.chainConfigJSONEqual(left, right)
	if err != nil {
		t.Fatalf("chainConfigJSONEqual failed: %v", err)
	}
	if equal {
		t.Fatal("expected fork drift to compare unequal")
	}
	if marshalCalls != 0 {
		t.Fatalf("expected fork fast reject to avoid marshal, got %d calls", marshalCalls)
	}
}

func TestFastEqualFallsBackToSemanticComparisonWhenDigestVersionBumps(t *testing.T) {
	deps := defaultGenesisDeps
	marshalCalls := 0
	deps.jsonMarshal = func(v any) ([]byte, error) {
		marshalCalls++
		return json.Marshal(v)
	}

	left := params.TestnetChainConfig.Clone()
	right := params.TestnetChainConfig.Clone()

	call := 0
	deps.hashChainConfigSemanticVersioned = func(cfg *params.ChainConfig) (byte, [32]byte) {
		call++
		version := chainConfigDigestVersion
		if call == 1 {
			version++
		}
		digest := hashChainConfigSemantic(cfg)
		return version, digest
	}

	equal, err := deps.chainConfigJSONEqual(left, right)
	if err != nil {
		t.Fatalf("chainConfigJSONEqual failed: %v", err)
	}
	if !equal {
		t.Fatal("expected semantic fallback to preserve equality across digest version bumps")
	}
	if marshalCalls != 0 {
		t.Fatalf("expected digest version mismatch to avoid JSON comparison, got %d marshal calls", marshalCalls)
	}
}

func TestFastEqualSemanticFallbackRejectsDriftWhenDigestVersionBumps(t *testing.T) {
	deps := defaultGenesisDeps
	marshalCalls := 0
	deps.jsonMarshal = func(v any) ([]byte, error) {
		marshalCalls++
		return json.Marshal(v)
	}

	left := params.TestnetChainConfig.Clone()
	right := params.TestnetChainConfig.Clone()
	right.PragueBlock = big.NewInt(123456)

	deps.hashChainConfigSemanticVersioned = func(cfg *params.ChainConfig) (byte, [32]byte) {
		version := chainConfigDigestVersion
		digest := hashChainConfigSemantic(cfg)
		return version + 1, digest
	}

	equal, err := deps.chainConfigJSONEqual(left, right)
	if err != nil {
		t.Fatalf("chainConfigJSONEqual failed: %v", err)
	}
	if equal {
		t.Fatal("expected semantic fallback to reject drift across digest version bumps")
	}
	if marshalCalls != 0 {
		t.Fatalf("expected digest version mismatch drift check to avoid JSON comparison, got %d marshal calls", marshalCalls)
	}
}

func TestHashChainConfigSemanticIgnoresV2ConfigIndexOrder(t *testing.T) {
	left := newChainConfigWithV2ConfigsForTest()
	right := newChainConfigWithV2ConfigsForTest()
	setV2ConfigIndexForTest(t, left.XDPoS.V2, []uint64{10, 0})
	setV2ConfigIndexForTest(t, right.XDPoS.V2, []uint64{0, 10})

	if !left.Equal(right) {
		t.Fatal("expected configIndex order drift to be semantically ignored")
	}

	leftDigest := hashChainConfigSemantic(left)
	rightDigest := hashChainConfigSemantic(right)
	if leftDigest != rightDigest {
		t.Fatalf("expected configIndex order to not affect digest: left=%x right=%x", leftDigest, rightDigest)
	}
}

func TestChainConfigJSONEqualImpliesSemanticEqual(t *testing.T) {
	testPairs := []struct {
		name  string
		left  *params.ChainConfig
		right *params.ChainConfig
	}{
		{name: "both nil"},
		{name: "same pointer", left: params.TestnetChainConfig, right: params.TestnetChainConfig},
		{name: "builtin clones", left: params.TestnetChainConfig.Clone(), right: params.TestnetChainConfig.Clone()},
		{name: "localnet clones", left: params.LocalnetChainConfig.Clone(), right: params.LocalnetChainConfig.Clone()},
		{name: "explicit null json", left: mustUnmarshalChainConfigJSONForTest(t, []byte("null")), right: mustUnmarshalChainConfigJSONForTest(t, []byte("null"))},
		{name: "round-tripped builtin json", left: mustRoundTripChainConfigForTest(t, params.MainnetChainConfig.Clone()), right: mustRoundTripChainConfigForTest(t, params.MainnetChainConfig.Clone())},
	}

	for _, test := range testPairs {
		t.Run(test.name, func(t *testing.T) {
			equal, err := defaultGenesisDeps.chainConfigJSONEqual(test.left, test.right)
			if err != nil {
				t.Fatalf("chainConfigJSONEqual failed: %v", err)
			}
			if equal && !chainConfigSemanticallyEqual(test.left, test.right) {
				t.Fatalf("chainConfigJSONEqual must not report equality when semantic Equal is false: left=%+v right=%+v", test.left, test.right)
			}
		})
	}
}

func FuzzChainConfigJSONEqualImpliesSemanticEqual(f *testing.F) {
	seedConfigs := []*params.ChainConfig{
		nil,
		params.MainnetChainConfig.Clone(),
		params.TestnetChainConfig.Clone(),
		params.LocalnetChainConfig.Clone(),
	}
	for _, cfg := range seedConfigs {
		f.Add(mustMarshalChainConfigJSONForTest(f, cfg), mustMarshalChainConfigJSONForTest(f, cfg))
	}
	f.Add([]byte("null"), []byte("null"))

	f.Fuzz(func(t *testing.T, leftJSON, rightJSON []byte) {
		left, ok := unmarshalChainConfigJSONForFuzz(leftJSON)
		if !ok {
			return
		}
		right, ok := unmarshalChainConfigJSONForFuzz(rightJSON)
		if !ok {
			return
		}
		equal, err := defaultGenesisDeps.chainConfigJSONEqual(left, right)
		if err != nil {
			t.Fatalf("chainConfigJSONEqual failed: %v", err)
		}
		if equal && !chainConfigSemanticallyEqual(left, right) {
			t.Fatalf("chainConfigJSONEqual must imply semantic Equal\nleftJSON=%s\nrightJSON=%s\nleft=%+v\nright=%+v", leftJSON, rightJSON, left, right)
		}
	})
}

func mustRoundTripChainConfigForTest(t *testing.T, cfg *params.ChainConfig) *params.ChainConfig {
	t.Helper()
	return mustUnmarshalChainConfigJSONForTest(t, mustMarshalChainConfigJSONForTest(t, cfg))
}

func mustMarshalChainConfigJSONForTest(tb testing.TB, cfg *params.ChainConfig) []byte {
	tb.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		tb.Fatalf("failed to marshal chain config: %v", err)
	}
	return data
}

func mustUnmarshalChainConfigJSONForTest(t *testing.T, data []byte) *params.ChainConfig {
	t.Helper()
	cfg, ok := unmarshalChainConfigJSONForFuzz(data)
	if !ok {
		t.Fatalf("failed to unmarshal chain config JSON: %q", data)
	}
	return cfg
}

func unmarshalChainConfigJSONForFuzz(data []byte) (*params.ChainConfig, bool) {
	var cfg *params.ChainConfig
	if err := json.Unmarshal(data, &cfg); err == nil {
		return cfg, true
	}
	var value params.ChainConfig
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, false
	}
	return &value, true
}

func semanticChainConfigFieldNames() []string {
	typ := reflect.TypeOf(params.ChainConfig{})
	fields := make([]string, 0, typ.NumField())
	for idx := 0; idx < typ.NumField(); idx++ {
		field := typ.Field(idx)
		if field.PkgPath != "" {
			continue
		}
		if field.Tag.Get("json") == "-" {
			continue
		}
		fields = append(fields, field.Name)
	}
	sort.Strings(fields)
	return fields
}

// TestChainConfigDigestCoversAllSemanticFields tests chain config digest covers all semantic fields.
func TestChainConfigDigestCoversAllSemanticFields(t *testing.T) {
	got := append([]string(nil), chainConfigDigestCoveredFields...)
	sort.Strings(got)
	want := semanticChainConfigFieldNames()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("digest field coverage mismatch:\ncovered=%v\nsemantic=%v", got, want)
	}
}

func setV2ConfigIndexForTest(t *testing.T, v2 *params.V2, configIndex []uint64) {
	t.Helper()
	v2Value := reflect.ValueOf(v2).Elem().FieldByName("configIndex")
	if !v2Value.IsValid() {
		t.Fatal("params.V2.configIndex field not found")
	}
	reflect.NewAt(v2Value.Type(), unsafe.Pointer(v2Value.UnsafeAddr())).Elem().Set(reflect.ValueOf(append([]uint64(nil), configIndex...)))
}

func newChainConfigWithV2ConfigsForTest() *params.ChainConfig {
	defaultConfig := &params.V2Config{
		MaxMasternodes:            18,
		MaxProtectorNodes:         3,
		MaxObverserNodes:          2,
		SwitchRound:               0,
		MinePeriod:                2,
		TimeoutSyncThreshold:      3,
		TimeoutPeriod:             4,
		CertThreshold:             0.667,
		MasternodeReward:          0.9,
		ProtectorReward:           0.08,
		ObserverReward:            0.02,
		MinimumMinerBlockPerEpoch: 10,
		LimitPenaltyEpoch:         4,
		MinimumSigningTx:          6,
		ExpTimeoutConfig: params.ExpTimeoutConfig{
			Base:        1.5,
			MaxExponent: 5,
		},
	}
	upgradedConfig := defaultConfig.Clone()
	upgradedConfig.SwitchRound = 10
	upgradedConfig.TimeoutPeriod = 6

	return &params.ChainConfig{
		ChainID: big.NewInt(50),
		XDPoS: &params.XDPoSConfig{
			Period:               2,
			Epoch:                900,
			Reward:               1,
			RewardCheckpoint:     900,
			Gap:                  450,
			MaxMasternodesV2:     18,
			FoundationWalletAddr: params.TestnetChainConfig.XDPoS.FoundationWalletAddr,
			V2: &params.V2{
				SwitchEpoch:   900,
				SwitchBlock:   big.NewInt(12345),
				CurrentConfig: upgradedConfig.Clone(),
				AllConfigs: map[uint64]*params.V2Config{
					0:  defaultConfig,
					10: upgradedConfig,
				},
			},
		},
	}
}
func TestHashChainConfigSemanticGoldenVectors(t *testing.T) {
	testnetBerlinDrift := params.TestnetChainConfig.Clone()
	testnetBerlinDrift.BerlinBlock = big.NewInt(123456)

	tests := []struct {
		name string
		cfg  *params.ChainConfig
		want string
	}{
		{name: "nil", cfg: nil, want: "47dc540c94ceb704a23875c11273e16bb0b8a87aed84de911f2133568115f254"},
		{name: "testnet", cfg: params.TestnetChainConfig.Clone(), want: "7dbc7e67764fdbb08a5774c63f2b73e9ea3cc1d483f1b3f360944b1c97fd4b08"},
		{name: "mainnet", cfg: params.XDCMainnetChainConfig.Clone(), want: "9076222c6783f37836c868190b78c7abe0b4d0d3fce93dc0aa12a6bc8b6ddcd3"},
		{name: "testnet-berlin-drift", cfg: testnetBerlinDrift, want: "365842abd836bdd13ab9dd40ef66357145f3233ff0a1b455c71f5401c4c8dc71"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := hashChainConfigSemantic(test.cfg)
			if gotHex := fmt.Sprintf("%x", got); gotHex != test.want {
				t.Fatalf("unexpected semantic hash: have %s want %s", gotHex, test.want)
			}
		})
	}
}

func benchmarkChainConfigJSONEqualBaseline(a, b *params.ChainConfig) (bool, error) {
	aData, err := json.Marshal(a.CloneForJSON())
	if err != nil {
		return false, err
	}
	bData, err := json.Marshal(b.CloneForJSON())
	if err != nil {
		return false, err
	}
	return bytes.Equal(aData, bData), nil
}

func benchmarkChainConfigJSONEqualCase(b *testing.B, left, right *params.ChainConfig, compare func(*params.ChainConfig, *params.ChainConfig) (bool, error)) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		equal, err := compare(left, right)
		if err != nil {
			b.Fatalf("compare failed: %v", err)
		}
		if !equal && left == right {
			b.Fatal("identical pointers must compare equal")
		}
	}
}

func BenchmarkChainConfigJSONEqualPointerIdentityFastPath(b *testing.B) {
	cfg := params.TestnetChainConfig.Clone()
	benchmarkChainConfigJSONEqualCase(b, cfg, cfg, defaultGenesisDeps.chainConfigJSONEqual)
}

func BenchmarkChainConfigJSONEqualPointerIdentityJSONBaseline(b *testing.B) {
	cfg := params.TestnetChainConfig.Clone()
	benchmarkChainConfigJSONEqualCase(b, cfg, cfg, benchmarkChainConfigJSONEqualBaseline)
}

func BenchmarkChainConfigJSONEqualStructuralEqualityFastPath(b *testing.B) {
	left := params.TestnetChainConfig.Clone()
	right := params.TestnetChainConfig.Clone()
	benchmarkChainConfigJSONEqualCase(b, left, right, defaultGenesisDeps.chainConfigJSONEqual)
}

func BenchmarkChainConfigJSONEqualStructuralEqualityJSONBaseline(b *testing.B) {
	left := params.TestnetChainConfig.Clone()
	right := params.TestnetChainConfig.Clone()
	benchmarkChainConfigJSONEqualCase(b, left, right, benchmarkChainConfigJSONEqualBaseline)
}

func BenchmarkChainConfigJSONEqualForkDriftFastPath(b *testing.B) {
	left := params.TestnetChainConfig.Clone()
	right := params.TestnetChainConfig.Clone()
	right.BerlinBlock = big.NewInt(123456)
	benchmarkChainConfigJSONEqualCase(b, left, right, defaultGenesisDeps.chainConfigJSONEqual)
}

func BenchmarkChainConfigJSONEqualForkDriftJSONBaseline(b *testing.B) {
	left := params.TestnetChainConfig.Clone()
	right := params.TestnetChainConfig.Clone()
	right.BerlinBlock = big.NewInt(123456)
	benchmarkChainConfigJSONEqualCase(b, left, right, benchmarkChainConfigJSONEqualBaseline)
}
