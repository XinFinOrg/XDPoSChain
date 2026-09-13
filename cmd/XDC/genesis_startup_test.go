package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	cmdutils "github.com/XinFinOrg/XDPoSChain/cmd/utils"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

const startupTestXDPoSConfig = `
			"XDPoS": {
				"period": 2,
				"epoch": 900,
				"reward": 5000,
				"rewardCheckpoint": 900,
				"gap": 450,
				"foundationWalletAddr": "0x0000000000000000000000000000000000000068",
				"maxMasternodesV2": 108,
				"v2": {
					"switchEpoch": 1111111,
					"switchBlock": 999999900,
					"config": {
						"maxMasternodes": 108,
						"switchRound": 0,
						"minePeriod": 2,
						"timeoutSyncThreshold": 3,
						"timeoutPeriod": 10,
						"certificateThreshold": 0.667,
						"expTimeoutConfig": {
							"base": 1,
							"maxExponent": 0
						}
					},
					"allConfigs": {
						"0": {
							"maxMasternodes": 108,
							"switchRound": 0,
							"minePeriod": 2,
							"timeoutSyncThreshold": 3,
							"timeoutPeriod": 10,
							"certificateThreshold": 0.667,
							"expTimeoutConfig": {
								"base": 1,
								"maxExponent": 0
							}
						}
					}
				}
			}`

// startupTestGenesis builds a minimal genesis JSON string with a caller-
// supplied config fragment.
func startupTestGenesis(configBody string) string {
	return fmt.Sprintf(`{
		"alloc"      : {},
		"coinbase"   : "0x0000000000000000000000000000000000000000",
		"difficulty" : "0x20000",
		"extraData"  : "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"gasLimit"   : "0x2fefd8",
		"nonce"      : "0x0000000000000042",
		"mixhash"    : "0x0000000000000000000000000000000000000000000000000000000000000000",
		"parentHash" : "0x0000000000000000000000000000000000000000000000000000000000000000",
		"timestamp"  : "0x00",
		"config"     : {
			"chainId" : 1337,
			%s
		%s
		}
	}`, configBody, startupTestXDPoSConfig)
}

// skipIfFatalfBypassesStderr skips a test that asserts on chain-config error text
// leaving through utils.Fatalf. Fatalf writes to stdout alone on Windows, and the
// test harness captures only the child's stderr, so the text is unreachable from the
// parent there and the assertions would fail for a reason that is not the config.
// These test cases therefore run on every other platform only.
func skipIfFatalfBypassesStderr(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("utils.Fatalf writes to stdout alone on Windows, which cmdtest does not capture")
	}
}

// assertCommandFailsWithChainConfigError checks that a test command fails with
// the expected chain-config-related error text.
func assertCommandFailsWithChainConfigError(t *testing.T, cmd *testXDC, want string) {
	t.Helper()
	assertCommandFailsWithChainConfigErrors(t, cmd, want)
}

// assertCommandFailsWithChainConfigErrors checks that a test command fails with
// all expected chain-config-related error text fragments.
func assertCommandFailsWithChainConfigErrors(t *testing.T, cmd *testXDC, wants ...string) {
	t.Helper()

	cmd.WaitExit()
	if status := cmd.ExitStatus(); status == 0 {
		t.Fatalf("expected command to fail, got exit status 0, stderr=%q", cmd.StderrText())
	}
	stderr := cmd.StderrText()
	for _, want := range wants {
		if !strings.Contains(stderr, want) {
			t.Fatalf("expected stderr to contain %q, got %q", want, stderr)
		}
	}
}

// assertCommandSucceeds checks that a test command exits successfully.
func assertCommandSucceeds(t *testing.T, cmd *testXDC) {
	t.Helper()

	cmd.WaitExit()
	if status := cmd.ExitStatus(); status != 0 {
		t.Fatalf("expected command to succeed, exit status=%d stderr=%q", status, cmd.StderrText())
	}
}

func startTestnetConsole(t *testing.T, datadir string, extraArgs ...string) {
	t.Helper()

	args := []string{
		"--testnet", "console", "--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none", "--ipcdisable",
		"--datadir", datadir,
	}
	args = append(args, extraArgs...)
	args = append(args, "--exec", "2+2")

	startupCmd := runXDC(t, args...)
	assertCommandSucceeds(t, startupCmd)
}

// openTestChainDB retries shortly when a reexec'd child has just released the
// LevelDB lock but the parent races to reopen it.
func openTestChainDB(t *testing.T, path string) ethdb.Database {
	t.Helper()

	var lastErr error
	for range 50 {
		db, err := rawdb.NewLevelDBDatabase(path, 0, 0, "", false)
		if err == nil {
			return db
		}
		lastErr = err
		if !strings.Contains(err.Error(), "resource temporarily unavailable") {
			t.Fatalf("failed to open test database: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("failed to open test database: %v", lastErr)
	return nil
}

// assertNoCanonicalGenesis checks that a failed init left no canonical genesis
// hash in the test datadir.
func assertNoCanonicalGenesis(t *testing.T, datadir string) {
	t.Helper()

	path := filepath.Join(datadir, "XDC", "chaindata")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("failed to stat chaindata path: %v", err)
	}
	db := openTestChainDB(t, path)
	defer db.Close()

	if got := rawdb.ReadCanonicalHash(db, 0); got != (common.Hash{}) {
		t.Fatalf("expected failed init to leave no canonical genesis, got %s", got.Hex())
	}
}

// readStoredChainConfig loads the canonical genesis hash and persisted chain
// config from the test datadir.
func readStoredChainConfig(t *testing.T, datadir string) (common.Hash, *params.ChainConfig) {
	t.Helper()

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)
	defer db.Close()

	genesisHash := rawdb.ReadCanonicalHash(db, 0)
	if genesisHash == (common.Hash{}) {
		t.Fatal("expected canonical genesis hash")
	}
	config, err := rawdb.ReadChainConfig(db, genesisHash)
	if err != nil {
		t.Fatalf("failed to read chain config: %v", err)
	}
	if config == nil {
		t.Fatal("expected stored chain config")
	}
	return genesisHash, config
}

// overwriteStoredIssuer replaces the stored TRC21 issuer address in the test
// chain config.
func overwriteStoredIssuer(t *testing.T, datadir string, issuer common.Address) {
	t.Helper()

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)
	defer db.Close()

	genesisHash := rawdb.ReadCanonicalHash(db, 0)
	if genesisHash == (common.Hash{}) {
		t.Fatal("expected canonical genesis hash")
	}
	config, err := rawdb.ReadChainConfig(db, genesisHash)
	if err != nil {
		t.Fatalf("failed to read chain config: %v", err)
	}
	if config == nil {
		t.Fatal("expected stored chain config")
	}
	config.TRC21IssuerSMC = issuer
	rawdb.WriteChainConfig(db, genesisHash, config)
}

// deleteStoredChainConfig removes the persisted chain-config blob from the test
// datadir and returns the canonical genesis hash.
func deleteStoredChainConfig(t *testing.T, datadir string) common.Hash {
	t.Helper()

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)

	genesisHash := rawdb.ReadCanonicalHash(db, 0)
	if genesisHash == (common.Hash{}) {
		t.Fatal("expected canonical genesis hash")
	}
	if err := db.Delete(append([]byte("ethereum-config-"), genesisHash.Bytes()...)); err != nil {
		t.Fatalf("failed to delete stored chain config: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close test database after delete: %v", err)
	}

	db = openTestChainDB(t, path)
	defer db.Close()

	config, err := rawdb.ReadChainConfig(db, genesisHash)
	if !errors.Is(err, rawdb.ErrChainConfigNotFound) {
		t.Fatalf("expected missing chain config after delete, config=%v err=%v", config, err)
	}
	return genesisHash
}

// overwriteStoredBerlinBlock updates the stored Berlin activation block in the
// test chain config.
func overwriteStoredBerlinBlock(t *testing.T, datadir string, block *big.Int) common.Hash {
	t.Helper()

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)
	defer db.Close()

	genesisHash := rawdb.ReadCanonicalHash(db, 0)
	if genesisHash == (common.Hash{}) {
		t.Fatal("expected canonical genesis hash")
	}
	config, err := rawdb.ReadChainConfig(db, genesisHash)
	if err != nil {
		t.Fatalf("failed to read chain config: %v", err)
	}
	if config == nil {
		t.Fatal("expected stored chain config")
	}
	config.BerlinBlock = common.CloneBigInt(block)
	rawdb.WriteChainConfig(db, genesisHash, config)
	return genesisHash
}

// overwriteStoredEIP150Block updates the stored EIP150 activation block in the
// test chain config.
func overwriteStoredEIP150Block(t *testing.T, datadir string, block *big.Int) common.Hash {
	t.Helper()

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)
	defer db.Close()

	genesisHash := rawdb.ReadCanonicalHash(db, 0)
	if genesisHash == (common.Hash{}) {
		t.Fatal("expected canonical genesis hash")
	}
	config, err := rawdb.ReadChainConfig(db, genesisHash)
	if err != nil {
		t.Fatalf("failed to read chain config: %v", err)
	}
	if config == nil {
		t.Fatal("expected stored chain config")
	}
	config.EIP150Block = common.CloneBigInt(block)
	rawdb.WriteChainConfig(db, genesisHash, config)
	return genesisHash
}

// overwriteStoredGap updates the stored XDPoS gap in the test chain config, so a
// directory whose schedule the upgrade refuses can be rebuilt.
func overwriteStoredGap(t *testing.T, datadir string, gap uint64) common.Hash {
	t.Helper()

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)
	defer db.Close()

	genesisHash := rawdb.ReadCanonicalHash(db, 0)
	if genesisHash == (common.Hash{}) {
		t.Fatal("expected canonical genesis hash")
	}
	config, err := rawdb.ReadChainConfig(db, genesisHash)
	if err != nil {
		t.Fatalf("failed to read chain config: %v", err)
	}
	if config == nil || config.XDPoS == nil {
		t.Fatal("expected stored XDPoS chain config")
	}
	config.XDPoS.Gap = gap
	rawdb.WriteChainConfig(db, genesisHash, config)
	return genesisHash
}

// injectCanonicalHeadBlock inserts a synthetic canonical head block into the
// test datadir.
func injectCanonicalHeadBlock(t *testing.T, datadir string, genesisHash common.Hash, number uint64) common.Hash {
	t.Helper()

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)

	genesis := rawdb.ReadBlock(db, genesisHash, 0)
	if genesis == nil {
		db.Close()
		t.Fatal("expected stored genesis block")
	}
	root := genesis.Root()
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close test database: %v", err)
	}
	return injectCanonicalHeadBlockWithRoot(t, datadir, genesisHash, number, root)
}

// injectCanonicalHeadBlockWithRoot inserts a synthetic canonical head block
// into the test datadir with the provided state root.
func injectCanonicalHeadBlockWithRoot(t *testing.T, datadir string, genesisHash common.Hash, number uint64, root common.Hash) common.Hash {
	t.Helper()

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)
	defer db.Close()

	genesis := rawdb.ReadBlock(db, genesisHash, 0)
	if genesis == nil {
		t.Fatal("expected stored genesis block")
	}
	head := types.NewBlockWithHeader(&types.Header{
		Number:     new(big.Int).SetUint64(number),
		ParentHash: genesisHash,
		Root:       root,
		Time:       genesis.Time() + number,
		GasLimit:   genesis.GasLimit(),
		Difficulty: genesis.Difficulty(),
	})
	rawdb.WriteTd(db, head.Hash(), number, new(big.Int).Add(genesis.Difficulty(), big.NewInt(int64(number))))
	rawdb.WriteBlock(db, head)
	rawdb.WriteCanonicalHash(db, head.Hash(), number)
	rawdb.WriteHeadHeaderHash(db, head.Hash())
	rawdb.WriteHeadBlockHash(db, head.Hash())
	rawdb.WriteHeadFastBlockHash(db, head.Hash())
	return head.Hash()
}

// deleteStoredGenesisState removes the persisted genesis trie node and returns
// the genesis hash and root.
func deleteStoredGenesisState(t *testing.T, datadir string) (common.Hash, common.Hash) {
	t.Helper()

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)
	defer db.Close()

	genesisHash := rawdb.ReadCanonicalHash(db, 0)
	if genesisHash == (common.Hash{}) {
		t.Fatal("expected canonical genesis hash")
	}
	genesis := rawdb.ReadBlock(db, genesisHash, 0)
	if genesis == nil {
		t.Fatal("expected stored genesis block")
	}
	rawdb.DeleteLegacyTrieNode(db, genesis.Root())
	return genesisHash, genesis.Root()
}

// copyDir copies a test datadir while skipping lock files.
func copyDir(t *testing.T, src, dst string) {
	t.Helper()

	if err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		if info.Name() == "LOCK" {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}
		defer out.Close()
		if _, err := io.Copy(out, in); err != nil {
			return err
		}
		return out.Close()
	}); err != nil {
		t.Fatalf("failed to copy %s to %s: %v", src, dst, err)
	}
}

// TestInitRejectsBadGenesisConfigAtStartup tests init rejects bad genesis config at startup.
func TestInitRejectsBadGenesisConfigAtStartup(t *testing.T) {
	skipIfFatalfBypassesStderr(t)

	datadir := t.TempDir()
	json := filepath.Join(datadir, "genesis.json")
	badConfig := strings.Replace(daoFutureForkConfig,
		`"trc21IssuerSMC" : "0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee",`,
		`"trc21IssuerSMC" : "0x0000000000000000000000000000000000000000",`, 1)
	if err := os.WriteFile(json, []byte(startupTestGenesis(badConfig)), 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	cmd := runXDC(t, "init", "--datadir", datadir, json)
	assertCommandFailsWithChainConfigErrors(t, cmd,
		"invalid chain config: missing fork switch: TRC21IssuerSMC",
		"ensure the persisted chain config or external genesis JSON includes TIPTRC21FeeBlock, Gas50xBlock",
	)
	assertNoCanonicalGenesis(t, datadir)
}

// startupTestGenesisWithoutEpoch returns the shared startup genesis with the
// XDPoS epoch omitted and the gap replaced by the caller's value, so a genesis
// that relies on the engine default epoch can be exercised through init.
func startupTestGenesisWithoutEpoch(t *testing.T, gap string) string {
	t.Helper()

	body := strings.Replace(startupTestGenesis(daoFutureForkConfig), `"epoch": 900,`, "", 1)
	if !strings.Contains(body, `"gap": 450,`) {
		t.Fatal("startup XDPoS config no longer carries the expected gap stanza")
	}
	return strings.Replace(body, `"gap": 450,`, `"gap": `+gap+`,`, 1)
}

// startupTestGenesisWithoutEpochAndSwitchBlock returns startupTestGenesisWithoutEpoch
// with the v2 switch block replaced as well, so the alignment rule the default epoch
// applies to an epoch-less config can be exercised through init.
func startupTestGenesisWithoutEpochAndSwitchBlock(t *testing.T, gap, switchBlock string) string {
	t.Helper()

	body := startupTestGenesisWithoutEpoch(t, gap)
	if !strings.Contains(body, `"switchBlock": 999999900,`) {
		t.Fatal("startup XDPoS config no longer carries the expected switchBlock stanza")
	}
	return strings.Replace(body, `"switchBlock": 999999900,`, `"switchBlock": `+switchBlock+`,`, 1)
}

// startupTestGenesisWithoutEpochAndSwitchEpoch returns startupTestGenesisWithoutEpoch
// with the v2 switch epoch replaced as well, so the pairing rule the default epoch
// applies to an epoch-less config can be exercised through init.
func startupTestGenesisWithoutEpochAndSwitchEpoch(t *testing.T, gap, switchEpoch string) string {
	t.Helper()

	body := startupTestGenesisWithoutEpoch(t, gap)
	if !strings.Contains(body, `"switchEpoch": 1111111,`) {
		t.Fatal("startup XDPoS config no longer carries the expected switchEpoch stanza")
	}
	return strings.Replace(body, `"switchEpoch": 1111111,`, `"switchEpoch": `+switchEpoch+`,`, 1)
}

// TestInitRejectsOmittedEpochWithUnusableGap pins that init reaches the same
// verdict as node startup when a genesis omits the epoch. XDPoS.New fills the
// engine default epoch before judging the gap schedule, so without the same fill
// here an unusable schedule would be written to disk and only refused at the
// first node start, leaving the operator to redo the init. The rejection is judged
// against that default, so the hint has to be the one that says the epoch in the
// message is not a value the file wrote.
func TestInitRejectsOmittedEpochWithUnusableGap(t *testing.T) {
	skipIfFatalfBypassesStderr(t)

	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")
	if err := os.WriteFile(jsonPath, []byte(startupTestGenesisWithoutEpoch(t, "0")), 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	cmd := runXDC(t, "init", "--datadir", datadir, jsonPath)
	assertCommandFailsWithChainConfigErrors(t, cmd,
		"unusable gap schedule",
		cmdutils.UnusableGapScheduleDefaultEpochHint,
	)
	assertNoCanonicalGenesis(t, datadir)
}

// TestInitAcceptsOmittedEpochWithUsableGap is the counterpart: an omitted epoch
// stays acceptable while the gap schedule is usable once the engine default is
// filled in, and the epoch is stored as written, so a genesis that omits it
// keeps matching the config that was committed.
func TestInitAcceptsOmittedEpochWithUsableGap(t *testing.T) {
	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")
	if err := os.WriteFile(jsonPath, []byte(startupTestGenesisWithoutEpoch(t, "450")), 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	cmd := runXDC(t, "init", "--datadir", datadir, jsonPath)
	assertCommandSucceeds(t, cmd)

	_, stored := readStoredChainConfig(t, datadir)
	if stored.XDPoS == nil {
		t.Fatal("expected a stored XDPoS config")
	}
	if stored.XDPoS.Epoch != 0 {
		t.Fatalf("expected the stored epoch to stay as written (0), have %d", stored.XDPoS.Epoch)
	}
}

// TestInitRefusesScheduleRepairOnNonEmptyDataDir pins the operator-facing half of
// the recovery boundary the schedule hints now spell out: on a directory that has
// already imported blocks, a corrected schedule cannot be applied by init.
//
// The corrected schedule changes XDPoS.Gap, which is a historical change, so
// SetupGenesisBlock returns a ConfigCompatError and init aborts with
// "Failed to write chain config" instead of rewriting the stored config. Without
// this test the hints could keep naming a recovery path the command refuses.
func TestInitRefusesScheduleRepairOnNonEmptyDataDir(t *testing.T) {
	skipIfFatalfBypassesStderr(t)

	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")
	genesisJSON := startupTestGenesis(daoFutureForkConfig)
	if err := os.WriteFile(jsonPath, []byte(genesisJSON), 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}
	assertCommandSucceeds(t, runXDC(t, "init", "--datadir", datadir, jsonPath))

	// Make the stored schedule unusable and give the directory a head: this is a
	// node that has produced blocks and would be refused on the next start.
	genesisHash := overwriteStoredGap(t, datadir, 0)
	injectCanonicalHeadBlock(t, datadir, genesisHash, 1)

	// Re-running init with the corrected schedule must be refused, and must leave
	// the stored config as it was.
	cmd := runXDC(t, "init", "--datadir", datadir, jsonPath)
	assertCommandFailsWithChainConfigErrors(t, cmd, "Failed to write chain config", "XDPoS.Gap")

	_, stored := readStoredChainConfig(t, datadir)
	if stored.XDPoS == nil || stored.XDPoS.Gap != 0 {
		t.Fatalf("a refused schedule repair must not rewrite the stored config, have %v", stored.XDPoS)
	}
}

// TestInitRejectsOmittedEpochWithUnalignedSwitchBlock pins the other rule the
// default epoch brings with it. Filling DefaultXDPoSEpoch in lets the whole
// schedule be judged, so an epoch-less genesis whose switch block is not a
// multiple of that default is refused with the alignment error - naming an epoch
// the genesis never wrote - and never reaches the disk. The node could not have
// started with this schedule either way: XDPoS.New filled the same default before
// it validated.
func TestInitRejectsOmittedEpochWithUnalignedSwitchBlock(t *testing.T) {
	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")
	genesisJSON := startupTestGenesisWithoutEpochAndSwitchBlock(t, "450", "2")
	if err := os.WriteFile(jsonPath, []byte(genesisJSON), 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	cmd := runXDC(t, "init", "--datadir", datadir, jsonPath)
	assertCommandFailsWithChainConfigErrors(t, cmd,
		params.ErrWrongForkSwitchOrder.Error(),
		"not aligned to XDPoS.Epoch 900",
	)
	assertNoCanonicalGenesis(t, datadir)
}

// TestInitRejectsOmittedEpochWithMismatchedSwitchEpoch pins the third rule the
// default epoch brings with it. The pairing rule divides the switch block by the
// effective epoch, so filling DefaultXDPoSEpoch in judges the switch epoch against
// a schedule the file never described: the genesis below names epoch 1111112 for a
// block the default puts on epoch 1111111. The rejection is tagged as judged
// against that default, so the operator gets the hint that says where the 900 came
// from instead of the arithmetic one, which would send them after a defect the file
// does not have. The node could not have started with this pairing either way:
// XDPoS.New filled the same default before it validated.
func TestInitRejectsOmittedEpochWithMismatchedSwitchEpoch(t *testing.T) {
	skipIfFatalfBypassesStderr(t)

	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")
	genesisJSON := startupTestGenesisWithoutEpochAndSwitchEpoch(t, "450", "1111112")
	if err := os.WriteFile(jsonPath, []byte(genesisJSON), 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	cmd := runXDC(t, "init", "--datadir", datadir, jsonPath)
	assertCommandFailsWithChainConfigErrors(t, cmd,
		params.ErrSwitchEpochMismatch.Error(),
		"does not name the epoch XDPoS.V2.SwitchBlock 999999900 falls on (want 1111111 = XDPoS.V2.SwitchBlock / XDPoS.Epoch 900)",
		cmdutils.SwitchEpochMismatchAgainstDefaultEpochHint,
	)
	assertNoCanonicalGenesis(t, datadir)
}

// TestInitRejectsNegativeSwitchBlock pins that init refuses a switch block that
// has no meaning on the chain. A negative height is dangerous precisely because
// it looks aligned: SwitchBlock.Uint64() folds it to its absolute value, so -900
// satisfies the epoch alignment rule while the comparisons against the field keep
// seeing a negative block. Refusing it while the config is resolved keeps the
// stored config to a single meaning, and mirrors the puppeth wizard, which will
// not generate one.
func TestInitRejectsNegativeSwitchBlock(t *testing.T) {
	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")
	genesisJSON := startupTestGenesisWithoutEpochAndSwitchBlock(t, "450", "-900")
	if err := os.WriteFile(jsonPath, []byte(genesisJSON), 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	cmd := runXDC(t, "init", "--datadir", datadir, jsonPath)
	assertCommandFailsWithChainConfigErrors(t, cmd,
		params.ErrNegativeSwitchBlock.Error(),
		"XDPoS.V2.SwitchBlock -900 must be non-negative",
	)
	assertNoCanonicalGenesis(t, datadir)
}

// TestInitAcceptsSameHashCustomConfigOnEmptyDatadir tests init accepts same hash custom config on empty datadir.
func TestInitAcceptsSameHashCustomConfigOnEmptyDatadir(t *testing.T) {
	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")

	genesis := core.DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(99999)
	rawGenesis, err := json.Marshal(genesis)
	if err != nil {
		t.Fatalf("failed to marshal genesis file: %v", err)
	}
	if err := os.WriteFile(jsonPath, rawGenesis, 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	cmd := runXDC(t, "--allow-builtin-config-override", "init", "--datadir", datadir, jsonPath)
	assertCommandSucceeds(t, cmd)

	genesisHash, config := readStoredChainConfig(t, datadir)
	if genesisHash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", genesisHash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if config.ChainID == nil || config.ChainID.Cmp(big.NewInt(99999)) != 0 {
		t.Fatalf("expected persisted custom chain id, have %v", config.ChainID)
	}
	path := filepath.Join(datadir, "XDC", "chaindata")
	db, err := rawdb.NewLevelDBDatabase(path, 0, 0, "", false)
	if err != nil {
		t.Fatalf("failed to reopen test database: %v", err)
	}
	defer db.Close()
	marker, err := rawdb.ReadChainConfigOverride(db, genesisHash)
	if err != nil {
		t.Fatalf("failed to read override marker: %v", err)
	}
	if !marker {
		t.Fatal("expected same-hash custom config override marker")
	}
}

// TestStartupUsesPersistedSameHashCustomConfig tests startup uses persisted same hash custom config.
func TestStartupUsesPersistedSameHashCustomConfig(t *testing.T) {
	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")

	genesis := core.DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(99999)
	rawGenesis, err := json.Marshal(genesis)
	if err != nil {
		t.Fatalf("failed to marshal genesis file: %v", err)
	}
	if err := os.WriteFile(jsonPath, rawGenesis, 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	initCmd := runXDC(t, "--allow-builtin-config-override", "init", "--datadir", datadir, jsonPath)
	assertCommandSucceeds(t, initCmd)

	startupCmd := runXDC(t,
		"--allow-builtin-config-override", "console", "--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none", "--ipcdisable",
		"--datadir", datadir, "--exec", "2+2",
	)
	assertCommandSucceeds(t, startupCmd)

	genesisHash, config := readStoredChainConfig(t, datadir)
	if genesisHash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", genesisHash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if config.ChainID == nil || config.ChainID.Cmp(big.NewInt(99999)) != 0 {
		t.Fatalf("expected persisted custom chain id after restart, have %v", config.ChainID)
	}
}

func TestInitRejectsSameHashCustomOverrideWithoutBuiltinConfigOverrideFlag(t *testing.T) {
	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")

	genesis := core.DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(99999)
	rawGenesis, err := json.Marshal(genesis)
	if err != nil {
		t.Fatalf("failed to marshal genesis file: %v", err)
	}
	if err := os.WriteFile(jsonPath, rawGenesis, 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	cmd := runXDC(t, "init", "--datadir", datadir, jsonPath)
	assertCommandFailsWithChainConfigErrors(t, cmd,
		"provided genesis config conflicts with built-in chain config",
		"same-hash custom overrides on built-in networks require --allow-builtin-config-override",
	)
}

func TestStartupRejectsPersistedSameHashCustomConfigWithoutBuiltinConfigOverrideFlag(t *testing.T) {
	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")

	genesis := core.DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(99999)
	rawGenesis, err := json.Marshal(genesis)
	if err != nil {
		t.Fatalf("failed to marshal genesis file: %v", err)
	}
	if err := os.WriteFile(jsonPath, rawGenesis, 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	initCmd := runXDC(t, "--allow-builtin-config-override", "init", "--datadir", datadir, jsonPath)
	assertCommandSucceeds(t, initCmd)

	startupCmd := runXDC(t,
		"console", "--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none", "--ipcdisable",
		"--datadir", datadir, "--exec", "2+2",
	)
	assertCommandFailsWithChainConfigErrors(t, startupCmd,
		"provided genesis config conflicts with built-in chain config",
		"same-hash custom overrides on built-in networks require --allow-builtin-config-override",
	)
}

// TestStartupPreservesSameHashCustomConfigWithTestnetFlag tests startup preserves same hash custom config with testnet flag.
func TestStartupPreservesSameHashCustomConfigWithTestnetFlag(t *testing.T) {
	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")

	genesis := core.DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(99999)
	rawGenesis, err := json.Marshal(genesis)
	if err != nil {
		t.Fatalf("failed to marshal genesis file: %v", err)
	}
	if err := os.WriteFile(jsonPath, rawGenesis, 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	initCmd := runXDC(t, "--allow-builtin-config-override", "init", "--datadir", datadir, jsonPath)
	assertCommandSucceeds(t, initCmd)

	startupCmd := runXDC(t,
		"--allow-builtin-config-override", "--testnet", "console", "--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none", "--ipcdisable",
		"--datadir", datadir, "--exec", "2+2",
	)
	assertCommandSucceeds(t, startupCmd)

	genesisHash, config := readStoredChainConfig(t, datadir)
	if genesisHash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", genesisHash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if config.ChainID == nil || config.ChainID.Cmp(big.NewInt(99999)) != 0 {
		t.Fatalf("expected --testnet startup to preserve persisted custom chain id, have %v", config.ChainID)
	}
}

// TestLegacySameHashCustomConfigRequiresExplicitInitMigration tests operator
// startup must fail on a legacy pre-marker same-hash custom database until a
// writable init path is run with the matching explicit genesis.
func TestLegacySameHashCustomConfigRequiresExplicitInitMigration(t *testing.T) {
	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")

	startupCmd := runXDC(t,
		"--testnet", "console", "--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none", "--ipcdisable",
		"--datadir", datadir, "--exec", "2+2",
	)
	assertCommandSucceeds(t, startupCmd)

	path := filepath.Join(datadir, "XDC", "chaindata")
	db, err := rawdb.NewLevelDBDatabase(path, 0, 0, "", false)
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}

	legacyGenesis := core.DefaultTestnetGenesisBlock()
	legacyGenesis.Config = legacyGenesis.Config.Clone()
	legacyGenesis.Config.ChainID = big.NewInt(99999)
	rawdb.WriteChainConfig(db, params.TestnetGenesisHash, legacyGenesis.Config)
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close test database: %v", err)
	}

	db, err = rawdb.NewLevelDBDatabase(path, 0, 0, "", false)
	if err != nil {
		t.Fatalf("failed to reopen test database: %v", err)
	}
	marker, err := rawdb.ReadChainConfigOverride(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read override marker: %v", err)
	}
	if marker {
		t.Fatal("did not expect override marker before explicit migration")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close test database after marker check: %v", err)
	}

	failingStartupCmd := runXDC(t,
		"console", "--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none", "--ipcdisable",
		"--datadir", datadir, "--exec", "2+2",
	)
	assertCommandFailsWithChainConfigError(t, failingStartupCmd, "provided genesis config conflicts with built-in chain config")

	rawGenesis, err := json.Marshal(legacyGenesis)
	if err != nil {
		t.Fatalf("failed to marshal legacy genesis file: %v", err)
	}
	if err := os.WriteFile(jsonPath, rawGenesis, 0600); err != nil {
		t.Fatalf("failed to write legacy genesis file: %v", err)
	}

	initCmd := runXDC(t, "--allow-builtin-config-override", "init", "--datadir", datadir, jsonPath)
	assertCommandSucceeds(t, initCmd)

	genesisHash, config := readStoredChainConfig(t, datadir)
	if genesisHash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash after migration: have %s want %s", genesisHash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if config.ChainID == nil || config.ChainID.Cmp(legacyGenesis.Config.ChainID) != 0 {
		t.Fatalf("expected migrated custom chain id, have %v want %v", config.ChainID, legacyGenesis.Config.ChainID)
	}

	db, err = rawdb.NewLevelDBDatabase(path, 0, 0, "", false)
	if err != nil {
		t.Fatalf("failed to reopen test database after migration: %v", err)
	}

	marker, err = rawdb.ReadChainConfigOverride(db, genesisHash)
	if err != nil {
		t.Fatalf("failed to read override marker after migration: %v", err)
	}
	if !marker {
		t.Fatal("expected explicit init migration to persist override marker")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close test database after migration check: %v", err)
	}

	postMigrationStartupCmd := runXDC(t,
		"--allow-builtin-config-override", "console", "--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none", "--ipcdisable",
		"--datadir", datadir, "--exec", "2+2",
	)
	assertCommandSucceeds(t, postMigrationStartupCmd)
}

// TestStartupRejectsStoredBadChainConfig tests startup rejects stored bad chain config.
func TestStartupRejectsStoredBadChainConfig(t *testing.T) {
	skipIfFatalfBypassesStderr(t)

	datadir := t.TempDir()
	json := filepath.Join(datadir, "genesis.json")
	if err := os.WriteFile(json, []byte(startupTestGenesis(daoFutureForkConfig)), 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	initCmd := runXDC(t, "init", "--datadir", datadir, json)
	initCmd.WaitExit()
	if status := initCmd.ExitStatus(); status != 0 {
		t.Fatalf("expected init to succeed, exit=%d stderr=%q", status, initCmd.StderrText())
	}

	overwriteStoredIssuer(t, datadir, common.Address{})

	startupCmd := runXDC(t,
		"console", "--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none", "--ipcdisable",
		"--datadir", datadir, "--exec", "2+2",
	)
	assertCommandFailsWithChainConfigErrors(t, startupCmd,
		"invalid chain config: missing fork switch: TRC21IssuerSMC",
		"ensure the persisted chain config or external genesis JSON includes TIPTRC21FeeBlock, Gas50xBlock",
	)
}

// TestOfflineExportRejectsStoredBuiltInChainConfigDrift tests offline export rejects stored built in chain config drift.
func TestOfflineExportRejectsStoredBuiltInChainConfigDrift(t *testing.T) {
	skipIfFatalfBypassesStderr(t)

	datadir := t.TempDir()
	exportFile := filepath.Join(datadir, "chain.rlp")

	startupCmd := runXDC(t,
		"--testnet", "console", "--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none", "--ipcdisable",
		"--datadir", datadir, "--exec", "2+2",
	)
	startupCmd.WaitExit()
	if status := startupCmd.ExitStatus(); status != 0 {
		t.Fatalf("expected testnet startup to succeed, exit=%d stderr=%q", status, startupCmd.StderrText())
	}

	overwriteStoredIssuer(t, datadir, common.Address{})

	exportCmd := runXDC(t, "--datadir", datadir, "--testnet", "export", exportFile)
	assertCommandFailsWithChainConfigError(t, exportCmd, "provided genesis config conflicts with built-in chain config")
	if _, err := os.Stat(exportFile); err == nil {
		t.Fatalf("expected export to fail without creating %s", exportFile)
	} else if !os.IsNotExist(err) {
		t.Fatalf("failed to stat export file: %v", err)
	}
}

// TestOfflineExportAllowsMissingStoredBuiltInChainConfig tests offline export allows missing stored built in chain config.
func TestOfflineExportAllowsMissingStoredBuiltInChainConfig(t *testing.T) {
	sourceDatadir := t.TempDir()

	startTestnetConsole(t, sourceDatadir)

	deleteStoredChainConfig(t, sourceDatadir)

	exportDatadir := t.TempDir()
	copyDir(t, sourceDatadir, exportDatadir)
	exportFile := filepath.Join(exportDatadir, "chain.rlp")

	exportCmd := runXDC(t, "--datadir", exportDatadir, "--testnet", "export", exportFile)
	assertCommandSucceeds(t, exportCmd)
	if _, err := os.Stat(exportFile); err != nil {
		t.Fatalf("expected export file to exist, stat failed: %v", err)
	}
}

// TestOfflineExportRejectsMissingStoredChainConfigForSameHashCustomOverride tests offline export rejects missing stored chain config for same hash custom override.
func TestOfflineExportRejectsMissingStoredChainConfigForSameHashCustomOverride(t *testing.T) {
	skipIfFatalfBypassesStderr(t)

	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")
	exportFile := filepath.Join(datadir, "chain.rlp")

	genesis := core.DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(99999)
	rawGenesis, err := json.Marshal(genesis)
	if err != nil {
		t.Fatalf("failed to marshal genesis file: %v", err)
	}
	if err := os.WriteFile(jsonPath, rawGenesis, 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	initCmd := runXDC(t, "--allow-builtin-config-override", "init", "--datadir", datadir, jsonPath)
	assertCommandSucceeds(t, initCmd)

	deleteStoredChainConfig(t, datadir)

	exportCmd := runXDC(t, "--allow-builtin-config-override", "--datadir", datadir, "export", exportFile)
	assertCommandFailsWithChainConfigError(t, exportCmd, "genesis config conflict")
	if _, err := os.Stat(exportFile); err == nil {
		t.Fatalf("expected export to fail without creating %s", exportFile)
	} else if !os.IsNotExist(err) {
		t.Fatalf("failed to stat export file: %v", err)
	}
}

// TestOfflineExportUsesStoredSameHashCustomOverrideWithoutBuiltinConfigOverrideFlag
// tests readonly export can reuse an authoritative stored same-hash custom
// override without re-requiring the writable recovery flag.
func TestOfflineExportUsesStoredSameHashCustomOverrideWithoutBuiltinConfigOverrideFlag(t *testing.T) {
	datadir := t.TempDir()
	jsonPath := filepath.Join(datadir, "genesis.json")
	exportFile := filepath.Join(datadir, "chain.rlp")

	genesis := core.DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(99999)
	rawGenesis, err := json.Marshal(genesis)
	if err != nil {
		t.Fatalf("failed to marshal genesis file: %v", err)
	}
	if err := os.WriteFile(jsonPath, rawGenesis, 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	initCmd := runXDC(t, "--allow-builtin-config-override", "init", "--datadir", datadir, jsonPath)
	assertCommandSucceeds(t, initCmd)

	exportCmd := runXDC(t, "--datadir", datadir, "--testnet", "export", exportFile)
	assertCommandSucceeds(t, exportCmd)
	if _, err := os.Stat(exportFile); err != nil {
		t.Fatalf("expected export file to exist, stat failed: %v", err)
	}
	if info, err := os.Stat(exportFile); err != nil {
		t.Fatalf("failed to stat export file: %v", err)
	} else if info.Size() == 0 {
		t.Fatalf("expected exported chain data in %s", exportFile)
	}
}

// TestOfflineExportFailsReadonlyGenesisStateRecoveryWithoutMutation tests offline export fails readonly genesis state recovery without mutation.
func TestOfflineExportFailsReadonlyGenesisStateRecoveryWithoutMutation(t *testing.T) {
	skipIfFatalfBypassesStderr(t)

	sourceDatadir := t.TempDir()

	startupCmd := runXDC(t,
		"--testnet", "console", "--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none", "--ipcdisable",
		"--datadir", sourceDatadir, "--exec", "2+2",
	)
	assertCommandSucceeds(t, startupCmd)

	exportDatadir := t.TempDir()
	copyDir(t, sourceDatadir, exportDatadir)
	exportFile := filepath.Join(exportDatadir, "chain.rlp")
	genesisHash, genesisRoot := deleteStoredGenesisState(t, exportDatadir)

	exportCmd := runXDC(t, "--datadir", exportDatadir, "--testnet", "export", exportFile)
	assertCommandFailsWithChainConfigError(t, exportCmd, "Can't open blockchain in readonly mode: genesis state is missing and requires recovery. Reopen the database in writable mode to recover the missing genesis state, then retry.")
	if _, err := os.Stat(exportFile); err == nil {
		t.Fatalf("expected export to fail without creating %s", exportFile)
	} else if !os.IsNotExist(err) {
		t.Fatalf("failed to stat export file: %v", err)
	}

	path := filepath.Join(exportDatadir, "XDC", "chaindata")
	db, err := rawdb.NewLevelDBDatabase(path, 0, 0, "", false)
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}
	defer db.Close()

	if got := rawdb.ReadCanonicalHash(db, 0); got != genesisHash {
		t.Fatalf("expected canonical genesis hash to remain unchanged: have %s want %s", got.Hex(), genesisHash.Hex())
	}
	if _, err := state.New(genesisRoot, state.NewDatabase(db)); err == nil {
		t.Fatal("expected failed readonly export to leave genesis state missing")
	}
}

// TestOfflineExportFailsReadonlyConfigRewindWithoutMutation tests offline export fails readonly config rewind without mutation.
func TestOfflineExportFailsReadonlyConfigRewindWithoutMutation(t *testing.T) {
	skipIfFatalfBypassesStderr(t)

	datadir := t.TempDir()
	exportFile := filepath.Join(datadir, "chain.rlp")

	startTestnetConsole(t, datadir)

	genesisHash := overwriteStoredBerlinBlock(t, datadir, big.NewInt(100))
	injectedHeadHash := injectCanonicalHeadBlock(t, datadir, genesisHash, 101)

	exportCmd := runXDC(t, "--datadir", datadir, "--testnet", "export", exportFile)
	assertCommandFailsWithChainConfigErrors(
		t,
		exportCmd,
		"Can't open blockchain: mismatching",
		cmdutils.ChainConfigMismatchPolicyExitHint,
	)
	if _, err := os.Stat(exportFile); err == nil {
		t.Fatalf("expected export to fail without creating %s", exportFile)
	} else if !os.IsNotExist(err) {
		t.Fatalf("failed to stat export file: %v", err)
	}

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)
	defer db.Close()

	if got := rawdb.ReadCanonicalHash(db, 0); got != genesisHash {
		t.Fatalf("expected canonical genesis hash to remain unchanged: have %s want %s", got.Hex(), genesisHash.Hex())
	}
	if got := rawdb.ReadHeadBlockHash(db); got != injectedHeadHash {
		t.Fatalf("expected failed readonly export to leave head hash unchanged: have %s want %s", got.Hex(), injectedHeadHash.Hex())
	}
	config, err := rawdb.ReadChainConfig(db, genesisHash)
	if err != nil {
		t.Fatalf("failed to read stored chain config: %v", err)
	}
	if config == nil {
		t.Fatal("expected stored chain config")
	}
	if config.BerlinBlock == nil || config.BerlinBlock.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("expected failed readonly export to leave drifted BerlinBlock unchanged: have %v want 100", config.BerlinBlock)
	}
}

// TestOfflineExportFailsReadonlyHeadStateRepairWithoutMutation tests offline
// export fails readonly startup when the current head state is missing.
func TestOfflineExportFailsReadonlyHeadStateRepairWithoutMutation(t *testing.T) {
	skipIfFatalfBypassesStderr(t)

	datadir := t.TempDir()
	exportFile := filepath.Join(datadir, "chain.rlp")

	startTestnetConsole(t, datadir)

	genesisHash, _ := readStoredChainConfig(t, datadir)
	missingRoot := common.HexToHash("0x1234")
	injectedHeadHash := injectCanonicalHeadBlockWithRoot(t, datadir, genesisHash, 1, missingRoot)

	exportCmd := runXDC(t, "--datadir", datadir, "--testnet", "export", exportFile)
	assertCommandFailsWithChainConfigError(t, exportCmd, "Can't open blockchain in readonly mode: head state is missing and requires repair. Reopen the database in writable mode to repair the missing head state, then retry.")
	if _, err := os.Stat(exportFile); err == nil {
		t.Fatalf("expected export to fail without creating %s", exportFile)
	} else if !os.IsNotExist(err) {
		t.Fatalf("failed to stat export file: %v", err)
	}

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)
	defer db.Close()

	if got := rawdb.ReadHeadBlockHash(db); got != injectedHeadHash {
		t.Fatalf("expected failed readonly export to leave head hash unchanged: have %s want %s", got.Hex(), injectedHeadHash.Hex())
	}
	if _, err := state.New(missingRoot, state.NewDatabase(db)); err == nil {
		t.Fatal("expected failed readonly export to leave head state missing")
	}
}

// TestOfflineExportFailsReadonlyConfigRewindToZeroWithoutMutation tests
// offline export still fails readonly startup when the required rewind target is
// zero.
func TestOfflineExportFailsReadonlyConfigRewindToZeroWithoutMutation(t *testing.T) {
	skipIfFatalfBypassesStderr(t)

	datadir := t.TempDir()
	exportFile := filepath.Join(datadir, "chain.rlp")

	startTestnetConsole(t, datadir)

	genesisHash := overwriteStoredEIP150Block(t, datadir, big.NewInt(1))
	injectedHeadHash := injectCanonicalHeadBlock(t, datadir, genesisHash, 1)

	exportCmd := runXDC(t, "--datadir", datadir, "--testnet", "export", exportFile)
	assertCommandFailsWithChainConfigErrors(
		t,
		exportCmd,
		"Can't open blockchain: mismatching",
		cmdutils.ChainConfigMismatchPolicyExitHint,
	)
	if _, err := os.Stat(exportFile); err == nil {
		t.Fatalf("expected export to fail without creating %s", exportFile)
	} else if !os.IsNotExist(err) {
		t.Fatalf("failed to stat export file: %v", err)
	}

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)
	defer db.Close()

	if got := rawdb.ReadCanonicalHash(db, 0); got != genesisHash {
		t.Fatalf("expected canonical genesis hash to remain unchanged: have %s want %s", got.Hex(), genesisHash.Hex())
	}
	if got := rawdb.ReadHeadBlockHash(db); got != injectedHeadHash {
		t.Fatalf("expected failed readonly export to leave head hash unchanged: have %s want %s", got.Hex(), injectedHeadHash.Hex())
	}
	config, err := rawdb.ReadChainConfig(db, genesisHash)
	if err != nil {
		t.Fatalf("failed to read stored chain config: %v", err)
	}
	if config == nil {
		t.Fatal("expected stored chain config")
	}
	if config.EIP150Block == nil || config.EIP150Block.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("expected failed readonly export to leave drifted EIP150Block unchanged: have %v want 1", config.EIP150Block)
	}
}

// TestStartupRewindsStoredBuiltInHistoricalForkDrift tests startup rewinds stored built in historical fork drift.
func TestStartupRewindsStoredBuiltInHistoricalForkDrift(t *testing.T) {
	datadir := t.TempDir()

	startTestnetConsole(t, datadir)

	genesisHash := overwriteStoredBerlinBlock(t, datadir, big.NewInt(100))
	injectedHeadHash := injectCanonicalHeadBlock(t, datadir, genesisHash, 101)

	startTestnetConsole(t, datadir, "--chain-config-mismatch-policy", "rewind-and-update")

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)
	defer db.Close()

	config, err := rawdb.ReadChainConfig(db, genesisHash)
	if err != nil {
		t.Fatalf("failed to read chain config: %v", err)
	}
	if config == nil {
		t.Fatal("expected stored chain config")
	}
	if config.BerlinBlock == nil || config.BerlinBlock.Cmp(params.TestnetChainConfig.BerlinBlock) != 0 {
		t.Fatalf("expected BerlinBlock to be restored to bundled testnet value %v, have %v", params.TestnetChainConfig.BerlinBlock, config.BerlinBlock)
	}
	if got := rawdb.ReadHeadBlockHash(db); got == injectedHeadHash {
		t.Fatalf("expected startup rewind to move head away from injected drifted block %s", injectedHeadHash.Hex())
	}
}

// TestStartupRewindsStoredBuiltInConfigDriftToZero tests writable startup
// repairs built-in config drift even when the required rewind target is zero.
func TestStartupRewindsStoredBuiltInConfigDriftToZero(t *testing.T) {
	datadir := t.TempDir()

	startTestnetConsole(t, datadir, "--chain-config-mismatch-policy", "rewind-and-update")

	genesisHash := overwriteStoredEIP150Block(t, datadir, big.NewInt(1))
	injectedHeadHash := injectCanonicalHeadBlock(t, datadir, genesisHash, 1)

	startTestnetConsole(t, datadir, "--chain-config-mismatch-policy", "rewind-and-update")

	path := filepath.Join(datadir, "XDC", "chaindata")
	db := openTestChainDB(t, path)
	defer db.Close()

	config, err := rawdb.ReadChainConfig(db, genesisHash)
	if err != nil {
		t.Fatalf("failed to read chain config: %v", err)
	}
	if config == nil {
		t.Fatal("expected stored chain config")
	}
	if config.EIP150Block == nil || config.EIP150Block.Cmp(params.TestnetChainConfig.EIP150Block) != 0 {
		t.Fatalf("expected EIP150Block to be restored to bundled testnet value %v, have %v", params.TestnetChainConfig.EIP150Block, config.EIP150Block)
	}
	if got := rawdb.ReadHeadBlockHash(db); got == injectedHeadHash {
		t.Fatalf("expected startup rewind to move head away from injected drifted block %s", injectedHeadHash.Hex())
	}
	if got := rawdb.ReadHeadBlockHash(db); got != genesisHash {
		t.Fatalf("expected rewind-to-zero startup to reset head to genesis: have %s want %s", got.Hex(), genesisHash.Hex())
	}
}
