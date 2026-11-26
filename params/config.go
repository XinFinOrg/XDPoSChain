// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params/forks"
)

// Genesis hashes to enforce below configs on.
var (
	MainnetGenesisHash = common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
	HoleskyGenesisHash = common.HexToHash("0xb5f7f912443c940f21fd611f12828d75b534364ed9e95ca4e307729a4661bde4")
	SepoliaGenesisHash = common.HexToHash("0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9")
	HoodiGenesisHash   = common.HexToHash("0xbbe312868b376a3001692a646dd2d7d1e4406380dfd86b98aa8a34d1557c971b")

	// XDC Network genesis hashes
	XDCMainnetGenesisHash = common.HexToHash("0x4a9d748bd78a8d0385b67788c2435dcdb914f98a96250b68863a1f8b7642d6b1") // verified genesis (#75)
	XDCApothemGenesisHash = common.HexToHash("0xbdea512b4f12ff1135ec92c00dc047ffb93890c2ea1aa0eefe9b013d80640075")
	XDCDevnetGenesisHash  = common.HexToHash("0xb8be003946a9c2688e9f1e255a5567c3d144293ccde2ffb38452a5840081b402") // XDPoSChain dev-upgrade DefaultDevnetGenesisBlock (chain ID 5551)
)

func newUint64(val uint64) *uint64 { return &val }

var (
	MainnetTerminalTotalDifficulty, _ = new(big.Int).SetString("58_750_000_000_000_000_000_000", 0)

	// MainnetChainConfig is the chain parameters to run a node on the main network.
	MainnetChainConfig = &ChainConfig{
		ChainID:                 big.NewInt(1),
		HomesteadBlock:          big.NewInt(1_150_000),
		DAOForkBlock:            big.NewInt(1_920_000),
		DAOForkSupport:          true,
		EIP150Block:             big.NewInt(2_463_000),
		EIP155Block:             big.NewInt(2_675_000),
		EIP158Block:             big.NewInt(2_675_000),
		ByzantiumBlock:          big.NewInt(4_370_000),
		ConstantinopleBlock:     big.NewInt(7_280_000),
		PetersburgBlock:         big.NewInt(7_280_000),
		IstanbulBlock:           big.NewInt(9_069_000),
		MuirGlacierBlock:        big.NewInt(9_200_000),
		BerlinBlock:             big.NewInt(12_244_000),
		LondonBlock:             big.NewInt(12_965_000),
		ArrowGlacierBlock:       big.NewInt(13_773_000),
		GrayGlacierBlock:        big.NewInt(15_050_000),
		TerminalTotalDifficulty: MainnetTerminalTotalDifficulty, // 58_750_000_000_000_000_000_000
		ShanghaiTime:            newUint64(1681338455),
		CancunTime:              newUint64(1710338135),
		PragueTime:              newUint64(1746612311),
		OsakaTime:               newUint64(1764798551),
		BPO1Time:                newUint64(1765290071),
		BPO2Time:                newUint64(1767747671),
		BogotaTime:              nil,
		DepositContractAddress:  common.HexToAddress("0x00000000219ab540356cbb839cbe05303d7705fa"),
		Ethash:                  new(EthashConfig),
		BlobScheduleConfig: &BlobScheduleConfig{
			Cancun: DefaultCancunBlobConfig,
			Prague: DefaultPragueBlobConfig,
			BPO1:   DefaultBPO1BlobConfig,
			BPO2:   DefaultBPO2BlobConfig,
		},
	}
	// HoleskyChainConfig contains the chain parameters to run a node on the Holesky test network.
	HoleskyChainConfig = &ChainConfig{
		ChainID:                 big.NewInt(17000),
		HomesteadBlock:          big.NewInt(0),
		DAOForkBlock:            nil,
		DAOForkSupport:          true,
		EIP150Block:             big.NewInt(0),
		EIP155Block:             big.NewInt(0),
		EIP158Block:             big.NewInt(0),
		ByzantiumBlock:          big.NewInt(0),
		ConstantinopleBlock:     big.NewInt(0),
		PetersburgBlock:         big.NewInt(0),
		IstanbulBlock:           big.NewInt(0),
		MuirGlacierBlock:        nil,
		BerlinBlock:             big.NewInt(0),
		LondonBlock:             big.NewInt(0),
		ArrowGlacierBlock:       nil,
		GrayGlacierBlock:        nil,
		TerminalTotalDifficulty: big.NewInt(0),
		MergeNetsplitBlock:      nil,
		ShanghaiTime:            newUint64(1696000704),
		CancunTime:              newUint64(1707305664),
		PragueTime:              newUint64(1740434112),
		OsakaTime:               newUint64(1759308480),
		BPO1Time:                newUint64(1759800000),
		BPO2Time:                newUint64(1760389824),
		BogotaTime:              nil,
		DepositContractAddress:  common.HexToAddress("0x4242424242424242424242424242424242424242"),
		Ethash:                  new(EthashConfig),
		BlobScheduleConfig: &BlobScheduleConfig{
			Cancun: DefaultCancunBlobConfig,
			Prague: DefaultPragueBlobConfig,
			BPO1:   DefaultBPO1BlobConfig,
			BPO2:   DefaultBPO2BlobConfig,
		},
	}
	// SepoliaChainConfig contains the chain parameters to run a node on the Sepolia test network.
	SepoliaChainConfig = &ChainConfig{
		ChainID:                 big.NewInt(11155111),
		HomesteadBlock:          big.NewInt(0),
		DAOForkBlock:            nil,
		DAOForkSupport:          true,
		EIP150Block:             big.NewInt(0),
		EIP155Block:             big.NewInt(0),
		EIP158Block:             big.NewInt(0),
		ByzantiumBlock:          big.NewInt(0),
		ConstantinopleBlock:     big.NewInt(0),
		PetersburgBlock:         big.NewInt(0),
		IstanbulBlock:           big.NewInt(0),
		MuirGlacierBlock:        big.NewInt(0),
		BerlinBlock:             big.NewInt(0),
		LondonBlock:             big.NewInt(0),
		ArrowGlacierBlock:       nil,
		GrayGlacierBlock:        nil,
		TerminalTotalDifficulty: big.NewInt(17_000_000_000_000_000),
		MergeNetsplitBlock:      big.NewInt(1735371),
		ShanghaiTime:            newUint64(1677557088),
		CancunTime:              newUint64(1706655072),
		PragueTime:              newUint64(1741159776),
		OsakaTime:               newUint64(1760427360),
		BPO1Time:                newUint64(1761017184),
		BPO2Time:                newUint64(1761607008),
		BogotaTime:              nil,
		DepositContractAddress:  common.HexToAddress("0x7f02c3e3c98b133055b8b348b2ac625669ed295d"),
		Ethash:                  new(EthashConfig),
		BlobScheduleConfig: &BlobScheduleConfig{
			Cancun: DefaultCancunBlobConfig,
			Prague: DefaultPragueBlobConfig,
			BPO1:   DefaultBPO1BlobConfig,
			BPO2:   DefaultBPO2BlobConfig,
		},
	}
	// HoodiChainConfig contains the chain parameters to run a node on the Hoodi test network.
	HoodiChainConfig = &ChainConfig{
		ChainID:                 big.NewInt(560048),
		HomesteadBlock:          big.NewInt(0),
		DAOForkBlock:            nil,
		DAOForkSupport:          true,
		EIP150Block:             big.NewInt(0),
		EIP155Block:             big.NewInt(0),
		EIP158Block:             big.NewInt(0),
		ByzantiumBlock:          big.NewInt(0),
		ConstantinopleBlock:     big.NewInt(0),
		PetersburgBlock:         big.NewInt(0),
		IstanbulBlock:           big.NewInt(0),
		MuirGlacierBlock:        big.NewInt(0),
		BerlinBlock:             big.NewInt(0),
		LondonBlock:             big.NewInt(0),
		ArrowGlacierBlock:       nil,
		GrayGlacierBlock:        nil,
		TerminalTotalDifficulty: big.NewInt(0),
		MergeNetsplitBlock:      big.NewInt(0),
		ShanghaiTime:            newUint64(0),
		CancunTime:              newUint64(0),
		PragueTime:              newUint64(1742999832),
		OsakaTime:               newUint64(1761677592),
		BPO1Time:                newUint64(1762365720),
		BPO2Time:                newUint64(1762955544),
		BogotaTime:              nil,
		DepositContractAddress:  common.HexToAddress("0x00000000219ab540356cBB839Cbe05303d7705Fa"),
		Ethash:                  new(EthashConfig),
		BlobScheduleConfig: &BlobScheduleConfig{
			Cancun: DefaultCancunBlobConfig,
			Prague: DefaultPragueBlobConfig,
			BPO1:   DefaultBPO1BlobConfig,
			BPO2:   DefaultBPO2BlobConfig,
		},
	}

	// XDCMainnetChainConfig contains the chain parameters to run a node on the XDC mainnet.
	// Chain ID: 50
	// Fork blocks aligned with XDPoSChain v2.6.8/v2.7.0 (XDCMainnetChainConfig +
	// MainnetConstant). Pre-Byzantium fork blocks 1/2/3/3/4 match canonical;
	// Constantinople/Petersburg/Istanbul are set to BerlinBlock so they pass
	// CheckConfigForkOrder while the XDC-specific TIPXDCXCancellationFee
	// fallback in IsIstanbul/IsPetersburg activates them earlier (at block
	// 38,383,838 on mainnet) — matching canonical behaviour.
	XDCMainnetChainConfig = &ChainConfig{
		ChainID:             big.NewInt(50),
		HomesteadBlock:      big.NewInt(1),
		DAOForkBlock:        nil,
		DAOForkSupport:      false,
		EIP150Block:         big.NewInt(2),
		EIP155Block:         big.NewInt(3),
		EIP158Block:         big.NewInt(3),
		ByzantiumBlock:      big.NewInt(4),
		ConstantinopleBlock: big.NewInt(76321000), // align with Berlin; effective Istanbul activation via TIPXDCXCancellationFee=38383838
		PetersburgBlock:     big.NewInt(76321000),
		IstanbulBlock:       big.NewInt(76321000),
		MuirGlacierBlock:    nil,
		BerlinBlock:         big.NewInt(76321000),   // XDPoSChain MainnetConstant.berlinBlock — Target 19th June 2024
		LondonBlock:         big.NewInt(76321000),   // XDPoSChain MainnetConstant.londonBlock — Target 19th June 2024
		Eip1559Block:        big.NewInt(98_800_200), // XDPoSChain MainnetConstant.eip1559Block — Target 28th Jan 2026
		CancunBlock:         big.NewInt(98_802_000), // XDPoSChain MainnetConstant.cancunBlock — Target 28th Jan 2026
		XDPoS: &XDPoSConfig{
			Period:              2,                                                                 // 2 second block time
			Epoch:               900,                                                               // 900 blocks per epoch (~30 minutes)
			Reward:              5000,                                                              // Block reward in XDC (before division)
			RewardCheckpoint:    900,                                                               // Checkpoint for rewards
			Gap:                 450,                                                               // Gap blocks before epoch end
			FoudationWalletAddr: common.HexToAddress("0x92a289fe95a85c53b8d0d113cbaef0c1ec98ac65"), // Mainnet foundation wallet — XinFinOrg/XinFin-Node/mainnet/genesis.json:16
			V2: &V2{
				SwitchBlock:   big.NewInt(80370000), // XDC mainnet V2 switch block
				SwitchEpoch:   89300,                // Epoch number at V2 switch (80370000/900)
				AllConfigs:    MainnetV2Configs,
				CurrentConfig: MainnetV2Configs[0], // Initial config active at round 0
			},
		},
		// TrustedSyncCheckpoints: mainnet checkpoints for near-instant sync.
		// Verified against https://rpc.xdcrpc.com at 2026-05-11 (chainId 50).
		// Current mainnet head: ~102,445,681.
		//
		// Coverage targets fork boundaries:
		//   75M             — pre-Berlin/London/Merge/Shanghai (76,321,000)
		//   80,370,000      — V2 switch (TIPV2SwitchBlock, Source-1 pre-seed)
		//   80,999,550      — V2-era gap block (Path B), post-V2-switch
		//   97,999,650      — V2-era gap block (Path B), pre-EIP-1559 (98,800,200)
		//   101,999,250     — V2-era gap block (Path B), recent post-Cancun
		// V2-era anchors (post-80,370,000) are gap blocks with `Number % 900 == 450`
		// and carry embedded Masternodes/Penalties so InsertHeadersBeforeCutoff can
		// pre-seed the V2 snapshot store without contract state. Non-gap entries
		// (50M–80M, 85M–100M) provide intermediate coverage but rely on PR #569's
		// bounded-catchup window for the first 2*Epoch blocks past anchor.
		TrustedSyncCheckpoints: []*TrustedSyncCheckpoint{
			{Number: 50000000, Hash: common.HexToHash("0x6897dbf3015d7b9e41ffb42a1339fdbbbf10ed7c7571ab16861e6a9ee7a13a36"), Root: common.HexToHash("0x808cd34093ffebfe37b9a99e38240a5857ec30a442b54bcc80133ae85e71e3c0")},
			{Number: 55000000, Hash: common.HexToHash("0xe081d7fe9fa8285282b7f48ace56a925a6dcd53a954a4b588c3589d94e7f1f45"), Root: common.HexToHash("0x8af89d783698ab3061e99dcffc21ad8b002e331968c37c7b4d90a4e7bb6f892e")},
			{Number: 60000000, Hash: common.HexToHash("0x86635b0445315c63e898a75162d3f0f265b72bd68e3d4f56202029f885cc27e2"), Root: common.HexToHash("0xc2895d9bcca3e136999d6eca4c52010fca287d512f4f88248e65bd57e5e49fa6")},
			{Number: 65000000, Hash: common.HexToHash("0xb46754db348cbf1a82abc0e7ad9d26aa5ad0a32979e87d99d319c1183c720a65"), Root: common.HexToHash("0x2aad852f65a9b1e77a410c5ff74fd84a1d17f8802ed3e87c60d053b56d2b50bd")},
			{Number: 70000000, Hash: common.HexToHash("0x06bf58bb64ca9924986caf798ee090d0b5fa13598c0adcfa5c21c2d91d8f1662"), Root: common.HexToHash("0x5a8db082c58ac5ce7dd7f59b20a06dfbbb13db43cd98dbfdac4bcdbeb6e50673")},
			{Number: 75000000, Hash: common.HexToHash("0x817d34ac145fba3b5c2c985e0f803e7a90579f1170a0d247b2a618ec21be7d70"), Root: common.HexToHash("0x38885e5b7df454f00d2394f329a831bcd762b4dc964474ead9b01ae73a4da8fc")},
			// Pre-Constantinople gap-block anchor at 76,320,450 (450 blocks before
			// fork at 76,321,000). Mainnet V2 switch is at 80,370,000, so this is a
			// V1-era anchor — hash + root only. Use for fast fork-upgrade testing
			// of Constantinople/Petersburg/Istanbul/Berlin/London.
			// Source: rpc.ankr.com/xdc, XDPoS_getMasternodesByNumber, 2026-05-12.
			{Number: 76320450, Hash: common.HexToHash("0x9aa6187f8d217e758bcf92d223013e9284378b214d7900ac993e5fa2a1a88a88"), Root: common.HexToHash("0xa9ee9f835982235b19c9264e4887861a2f12386e1604bb0b2316c97b78417985")},
			{Number: 80000000, Hash: common.HexToHash("0x5f64e43e7e542ad51d9937f72e0e049217d478a024b7cab7df9589337d29f950"), Root: common.HexToHash("0xfdbfee3a3d7afa506c0e605933b3cde2ce665c4011a42132dbcab054107ce21f")},
			// V2 switch (TIPV2SwitchBlock). InsertHeadersBeforeCutoff
			// special-cases this via Source 1 (header.Validators / V1 Extra) and
			// falls back to Source 2 (the embedded list below) if header decoding
			// returns empty.
			// Source: rpc.xdcrpc.com, XDPoS_getMasternodesByNumber, 2026-05-11. Round 0.
			{
				Number: 80370000,
				Hash:   common.HexToHash("0x83b8e385682ca0faa29e0cc4dbf7de08512ec36bc7d4f0cf173ca5a6dbf034dc"),
				Root:   common.HexToHash("0x3cf97cbeab58e52531360143cc1c262e3b3deb0d610193be1dba4481f2e50b77"),
				Masternodes: []common.Address{
					common.HexToAddress("0x03d9e17ae3ff2c6712e44e25b09ac5ee91f6c9ff"),
					common.HexToAddress("0x047ffe1fc7f6d0b7168c4ccc312221089629f470"),
					common.HexToAddress("0x065551f0dcac6f00cae11192d462db709be3758c"),
					common.HexToAddress("0x09bae325e54edf4dc8b79a8bb29f90deb90e8fe7"),
					common.HexToAddress("0x0b0afb41c14dd921a9a4511c226dc29254ba0d8f"),
					common.HexToAddress("0x18d31511b8efbf4215c48c026c56ad469ce90374"),
					common.HexToAddress("0x1a7c3d7481adc7e067f2f73f35f44143d7bf02d4"),
					common.HexToAddress("0x1aff171caa8c1ea93bac4c27676f356d054412b4"),
					common.HexToAddress("0x1d25a7076993cfcd676237daea90d8edc99c7f46"),
					common.HexToAddress("0x1d393817ab218ebade3e8ad591593ec3b132b1f6"),
					common.HexToAddress("0x1e0103ba7665d15328b3886927d4f0a85f8b2299"),
					common.HexToAddress("0x21396ca79a433a20b5904c9a77aa9a4f110ef80e"),
					common.HexToAddress("0x241ff0d3096e2e0b477780f9f551918a06827c05"),
					common.HexToAddress("0x24c0832d9df8189166d8e4e2cedc40ad69077b17"),
					common.HexToAddress("0x25c65b4b379ac37cf78357c4915f73677022eaff"),
					common.HexToAddress("0x2a591f3d64f3ce6b1d2afeead839ad76aab9feb2"),
					common.HexToAddress("0x2d74d0125982bdc3a9f54a10216d82509379e821"),
					common.HexToAddress("0x2d881b373edf297b495e8deedd9108e3d6870dee"),
					common.HexToAddress("0x2f86476faa31c3f5a3d5b9376282e1b02b4dfa00"),
					common.HexToAddress("0x3056a8bff9a17b12d08f1837d0b44cf1e2018fbe"),
					common.HexToAddress("0x346ada489c70c85ca665428389f1a971abbee960"),
					common.HexToAddress("0x35898873c021f9f4fa01a76c7fa595159f5523e7"),
					common.HexToAddress("0x35943387085224cd07efab4264e850ce6cdc99ac"),
					common.HexToAddress("0x360b9e5870fc91e375f902fc134f91739f4a99c7"),
					common.HexToAddress("0x391f3d21d9062ebbdd958e436b26d4b40928658c"),
					common.HexToAddress("0x39ee018a85e4469a1b335efe014067e315bd6594"),
					common.HexToAddress("0x4398241671b3dd484fe3213a4fb7511f30e7d7c0"),
					common.HexToAddress("0x450d714e65f4de007937c56fb1c4686efd4fb4ec"),
					common.HexToAddress("0x48570e5de69db5203d259bbde6722bb1d3c3ee5a"),
					common.HexToAddress("0x497c44f4a22099109ad7d194aad4fbe78dceb788"),
					common.HexToAddress("0x49d3fa92eec838f644e8cacf2c93533d29b6c713"),
					common.HexToAddress("0x4b7076c988da8a0ef87f1af137f7abc39557b746"),
					common.HexToAddress("0x4e111142fbf2edacc4ab122feb54b031dc3d95d9"),
					common.HexToAddress("0x52825e085ae7785ad9b42aaa98a630560593b7e2"),
					common.HexToAddress("0x555ff7828a0b435432308a4721e4d9f110324025"),
					common.HexToAddress("0x5651290bdd3a952357066b324f9334b544100140"),
					common.HexToAddress("0x58f25975086b8d23c028ebb651be064da0360367"),
					common.HexToAddress("0x595b8170eaf2e53e47cc20db47ad063a1e6e2c0f"),
					common.HexToAddress("0x609cc32e7513135349fbe9ebd78ea8cdcfd9f819"),
					common.HexToAddress("0x618e706c531e57f44a739cef129bf08cbd912d6a"),
					common.HexToAddress("0x619f838ea2a12cdb508e759c3e0697e021d52ceb"),
					common.HexToAddress("0x63443ffdb5c139c3bbab97d3b06ee0674d75ab7f"),
					common.HexToAddress("0x65c90c2d3e99d8366f90db7f4d25f23a0a569d49"),
					common.HexToAddress("0x664c4a7b15d91b07c468162f535909114c038b91"),
					common.HexToAddress("0x70916660766043c23443479658008eeedad8cb94"),
					common.HexToAddress("0x72a0224245992792c75565bd3ab6caa6c8b95218"),
					common.HexToAddress("0x72fb467ef6da285b6b0d8f7a25abd6049385d5fd"),
					common.HexToAddress("0x74d3ac0efc4c22ea05150d7501c95c610b130c4b"),
					common.HexToAddress("0x7525f63e5f739ef952fbea50c1dc97ef5d5bd984"),
					common.HexToAddress("0x7aa125338be075260e77c6a66a56c90a5dec4c58"),
					common.HexToAddress("0x7af6aedf3382bb3de2dba61769d96444bf660494"),
					common.HexToAddress("0x82c85801a8b18c4b2701e552727cea8494bbe9ea"),
					common.HexToAddress("0x8e455bb521212bdcf8cb326e32dc1183cb3fd887"),
					common.HexToAddress("0x8eeeeafaca49e507bc9bba121dac97ec75774ff2"),
					common.HexToAddress("0x8f2fb5da850042b7da5097061f098493f8ec6dd8"),
					common.HexToAddress("0x9043fafbe8833adafb449b559cef300a9632763f"),
					common.HexToAddress("0x90c60bd5a20bd2a3142e2c491b9a59c2c1e83e4d"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0x9200e4fe8959f0268eb9daf06aba4756e595b99f"),
					common.HexToAddress("0x92d32364313c376dcae272e113fd04cea194d2c8"),
					common.HexToAddress("0x9a3787688fd210ec8f8d0224c6c50b8178d75bc0"),
					common.HexToAddress("0x9c54bc764c2e00717fbbf31b4dc962a72c47bdf6"),
					common.HexToAddress("0x9fce52c5c451599235c17bc37e99f846d25ee6ec"),
					common.HexToAddress("0xa26be303e8378e427669650a4f53506d6dd2d55f"),
					common.HexToAddress("0xa4657c02208797985adedcbd048efc82291dbdb2"),
					common.HexToAddress("0xa65010026b83368ca05df6e8b467985d6de3eac5"),
					common.HexToAddress("0xa70b87c39a1237ba53953a1da04b23d4db28eace"),
					common.HexToAddress("0xa72ce94a09db26dce57a4852409abc2fff07a962"),
					common.HexToAddress("0xaf3db8ad8154820303adc6be0d9b10ef8e33024f"),
					common.HexToAddress("0xb0a48f9087ecb85390abf23ec1b1d591ddc757bd"),
					common.HexToAddress("0xb0cc3fd7fe1df0f3d2d962746725f01693c49b31"),
					common.HexToAddress("0xb1693d224d4fd70ad6c9c9bdc44faa3ce21fb40d"),
					common.HexToAddress("0xb38aba47a5563fa4aedc2a649ef819b9fb160b6a"),
					common.HexToAddress("0xb570b13fa9ca093347448dc600ed0d09333ac9fa"),
					common.HexToAddress("0xb9a3a97f6a02a86483bf02cb33f8b33d2d117708"),
					common.HexToAddress("0xbbd2d417a8b6f1b1d7a267cd1d7402b443f35cfe"),
					common.HexToAddress("0xc02aed857b01b4d60b378096221db3b60afadc37"),
					common.HexToAddress("0xc3e2a9a73881fcce6fc9367a0a3ddbd658d20e37"),
					common.HexToAddress("0xc67c2dec79da735d6587d8db3c23271d557196ab"),
					common.HexToAddress("0xc7bf1cd426e6f47d879fbaba789d7c5740ce9b4b"),
					common.HexToAddress("0xc7d49d0a2cf198deebd6ce581af465944ec8b2bb"),
					common.HexToAddress("0xcaeb8bef9689e70135023d4dfb85864832f968bf"),
					common.HexToAddress("0xccab2f5267bc66b69f1688560c2e075216908a2c"),
					common.HexToAddress("0xcfccdea1006a5cfa7d9484b5b293b46964c265c0"),
					common.HexToAddress("0xd22fdac1459760f698618d927bbe22249e2b29b9"),
					common.HexToAddress("0xd2fefdd118aa2bea5991dc079fd341d3e7a92caf"),
					common.HexToAddress("0xd5bb37763625bc16f2ad0791d87e2726004241e4"),
					common.HexToAddress("0xd6e9161fad50d2e697cda2b960fd26bf52a5d169"),
					common.HexToAddress("0xdb2e141595d8edf6b1ce40b10d57ca5b83855ec5"),
					common.HexToAddress("0xdccd99da1c942a36c5dcaf26d19b98c815dfcb73"),
					common.HexToAddress("0xdef4bd67f9e2627ca495b5f71794fab1bab40619"),
					common.HexToAddress("0xe230905c99aaa7b68402af8611b89ceda743191e"),
					common.HexToAddress("0xe2bc9a03d5ae35e130c8bf99ea50c022de375db7"),
					common.HexToAddress("0xe4710a854b24062ff37ab6636bd9a456e24c1635"),
					common.HexToAddress("0xe494fe5a38b7212ab999152d1d45adab8d84a8a7"),
					common.HexToAddress("0xe865a5b2bf699a4b498de8a8c55da14bb0d94b21"),
					common.HexToAddress("0xe8bc0e78114ad8dc4290eaed78bcb9e3f5b91e32"),
					common.HexToAddress("0xe8e8194c0a8e5a32306c7a86052a4e8ca4b8729d"),
					common.HexToAddress("0xeafdcce538785f97c0863288bfb3235e759b5d55"),
					common.HexToAddress("0xebf8e4904fe2bd561475e9e0e65a3336c56f83d3"),
					common.HexToAddress("0xec4a5fbd2e46e97be98c212e668ef1d08d695440"),
					common.HexToAddress("0xef3c018667aa871c02d3d6be10a9a8ccdd351294"),
					common.HexToAddress("0xf04f32c46f1a16663bc7f6409b35b33f3daa9a03"),
					common.HexToAddress("0xf48aa29de23c45c54a96c2a7b8ce5218abf46874"),
					common.HexToAddress("0xfca96ff494f38a9c33a558caf8d9d628c819c2ca"),
				},
				// PenaltyLen=0 at the V2 switch block (clean start). Omit Penalties.
			},
			// V2-era gap-block anchor at 80,999,550 (round 639102).
			// Post-V2-switch (80,370,000). Path B with embedded masternodes/penalties:
			// header.Validators is empty on V2-era headers, so the pre-seed path in
			// InsertHeadersBeforeCutoff falls back to this list to seed the V2 snapshot.
			// Source: rpc.xdcrpc.com, XDPoS_getMasternodesByNumber, 2026-05-11.
			{
				Number: 80999550,
				Hash:   common.HexToHash("0x42f104168ac30a90e32b16a9e957b20848efab7ebe404e0f70b1e4d0a7a660d6"),
				Root:   common.HexToHash("0x58299510b40cc6c9906460be36753a479f8694ca6aa297d42a4a6bae2c383722"),
				Masternodes: []common.Address{
					common.HexToAddress("0x047ffe1fc7f6d0b7168c4ccc312221089629f470"),
					common.HexToAddress("0xb1693d224d4fd70ad6c9c9bdc44faa3ce21fb40d"),
					common.HexToAddress("0x5651290bdd3a952357066b324f9334b544100140"),
					common.HexToAddress("0x2a591f3d64f3ce6b1d2afeead839ad76aab9feb2"),
					common.HexToAddress("0x49d3fa92eec838f644e8cacf2c93533d29b6c713"),
					common.HexToAddress("0x74d3ac0efc4c22ea05150d7501c95c610b130c4b"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0xa26be303e8378e427669650a4f53506d6dd2d55f"),
					common.HexToAddress("0xdef4bd67f9e2627ca495b5f71794fab1bab40619"),
					common.HexToAddress("0x9043fafbe8833adafb449b559cef300a9632763f"),
					common.HexToAddress("0x90c60bd5a20bd2a3142e2c491b9a59c2c1e83e4d"),
					common.HexToAddress("0x4398241671b3dd484fe3213a4fb7511f30e7d7c0"),
					common.HexToAddress("0x65c90c2d3e99d8366f90db7f4d25f23a0a569d49"),
					common.HexToAddress("0x3056a8bff9a17b12d08f1837d0b44cf1e2018fbe"),
					common.HexToAddress("0x35943387085224cd07efab4264e850ce6cdc99ac"),
					common.HexToAddress("0xe494fe5a38b7212ab999152d1d45adab8d84a8a7"),
					common.HexToAddress("0xd2fefdd118aa2bea5991dc079fd341d3e7a92caf"),
					common.HexToAddress("0x0b0afb41c14dd921a9a4511c226dc29254ba0d8f"),
					common.HexToAddress("0xa65010026b83368ca05df6e8b467985d6de3eac5"),
					common.HexToAddress("0xc02aed857b01b4d60b378096221db3b60afadc37"),
					common.HexToAddress("0x609cc32e7513135349fbe9ebd78ea8cdcfd9f819"),
					common.HexToAddress("0xb0cc3fd7fe1df0f3d2d962746725f01693c49b31"),
					common.HexToAddress("0x595b8170eaf2e53e47cc20db47ad063a1e6e2c0f"),
					common.HexToAddress("0x1d25a7076993cfcd676237daea90d8edc99c7f46"),
					common.HexToAddress("0xdccd99da1c942a36c5dcaf26d19b98c815dfcb73"),
					common.HexToAddress("0x241ff0d3096e2e0b477780f9f551918a06827c05"),
					common.HexToAddress("0xe865a5b2bf699a4b498de8a8c55da14bb0d94b21"),
					common.HexToAddress("0x065551f0dcac6f00cae11192d462db709be3758c"),
					common.HexToAddress("0x1d393817ab218ebade3e8ad591593ec3b132b1f6"),
					common.HexToAddress("0x9a3787688fd210ec8f8d0224c6c50b8178d75bc0"),
					common.HexToAddress("0x2d74d0125982bdc3a9f54a10216d82509379e821"),
					common.HexToAddress("0x03d9e17ae3ff2c6712e44e25b09ac5ee91f6c9ff"),
					common.HexToAddress("0x18d31511b8efbf4215c48c026c56ad469ce90374"),
					common.HexToAddress("0xa4657c02208797985adedcbd048efc82291dbdb2"),
					common.HexToAddress("0xd5bb37763625bc16f2ad0791d87e2726004241e4"),
					common.HexToAddress("0x52825e085ae7785ad9b42aaa98a630560593b7e2"),
					common.HexToAddress("0xd22fdac1459760f698618d927bbe22249e2b29b9"),
					common.HexToAddress("0x8f2fb5da850042b7da5097061f098493f8ec6dd8"),
					common.HexToAddress("0xcaeb8bef9689e70135023d4dfb85864832f968bf"),
					common.HexToAddress("0x7525f63e5f739ef952fbea50c1dc97ef5d5bd984"),
					common.HexToAddress("0x25c65b4b379ac37cf78357c4915f73677022eaff"),
					common.HexToAddress("0xe2bc9a03d5ae35e130c8bf99ea50c022de375db7"),
					common.HexToAddress("0x1aff171caa8c1ea93bac4c27676f356d054412b4"),
					common.HexToAddress("0x8e455bb521212bdcf8cb326e32dc1183cb3fd887"),
					common.HexToAddress("0xc67c2dec79da735d6587d8db3c23271d557196ab"),
					common.HexToAddress("0x70916660766043c23443479658008eeedad8cb94"),
					common.HexToAddress("0x360b9e5870fc91e375f902fc134f91739f4a99c7"),
					common.HexToAddress("0xc7d49d0a2cf198deebd6ce581af465944ec8b2bb"),
					common.HexToAddress("0xb9a3a97f6a02a86483bf02cb33f8b33d2d117708"),
					common.HexToAddress("0xc3e2a9a73881fcce6fc9367a0a3ddbd658d20e37"),
					common.HexToAddress("0x4e111142fbf2edacc4ab122feb54b031dc3d95d9"),
					common.HexToAddress("0x1a7c3d7481adc7e067f2f73f35f44143d7bf02d4"),
					common.HexToAddress("0x48570e5de69db5203d259bbde6722bb1d3c3ee5a"),
					common.HexToAddress("0x7aa125338be075260e77c6a66a56c90a5dec4c58"),
					common.HexToAddress("0xaf3db8ad8154820303adc6be0d9b10ef8e33024f"),
					common.HexToAddress("0xbbd2d417a8b6f1b1d7a267cd1d7402b443f35cfe"),
					common.HexToAddress("0x1e0103ba7665d15328b3886927d4f0a85f8b2299"),
					common.HexToAddress("0x72fb467ef6da285b6b0d8f7a25abd6049385d5fd"),
					common.HexToAddress("0x24c0832d9df8189166d8e4e2cedc40ad69077b17"),
					common.HexToAddress("0x35898873c021f9f4fa01a76c7fa595159f5523e7"),
					common.HexToAddress("0x9c54bc764c2e00717fbbf31b4dc962a72c47bdf6"),
					common.HexToAddress("0xe8e8194c0a8e5a32306c7a86052a4e8ca4b8729d"),
					common.HexToAddress("0x72a0224245992792c75565bd3ab6caa6c8b95218"),
					common.HexToAddress("0x2f86476faa31c3f5a3d5b9376282e1b02b4dfa00"),
					common.HexToAddress("0xef3c018667aa871c02d3d6be10a9a8ccdd351294"),
					common.HexToAddress("0x4b7076c988da8a0ef87f1af137f7abc39557b746"),
					common.HexToAddress("0xb38aba47a5563fa4aedc2a649ef819b9fb160b6a"),
					common.HexToAddress("0xec4a5fbd2e46e97be98c212e668ef1d08d695440"),
					common.HexToAddress("0x450d714e65f4de007937c56fb1c4686efd4fb4ec"),
					common.HexToAddress("0xe4710a854b24062ff37ab6636bd9a456e24c1635"),
					common.HexToAddress("0xe230905c99aaa7b68402af8611b89ceda743191e"),
					common.HexToAddress("0x9fce52c5c451599235c17bc37e99f846d25ee6ec"),
					common.HexToAddress("0x664c4a7b15d91b07c468162f535909114c038b91"),
					common.HexToAddress("0x39ee018a85e4469a1b335efe014067e315bd6594"),
					common.HexToAddress("0xa72ce94a09db26dce57a4852409abc2fff07a962"),
					common.HexToAddress("0xcfccdea1006a5cfa7d9484b5b293b46964c265c0"),
					common.HexToAddress("0x497c44f4a22099109ad7d194aad4fbe78dceb788"),
					common.HexToAddress("0xa70b87c39a1237ba53953a1da04b23d4db28eace"),
					common.HexToAddress("0xdb2e141595d8edf6b1ce40b10d57ca5b83855ec5"),
					common.HexToAddress("0xf04f32c46f1a16663bc7f6409b35b33f3daa9a03"),
					common.HexToAddress("0xccab2f5267bc66b69f1688560c2e075216908a2c"),
					common.HexToAddress("0x92d32364313c376dcae272e113fd04cea194d2c8"),
					common.HexToAddress("0x619f838ea2a12cdb508e759c3e0697e021d52ceb"),
					common.HexToAddress("0x63443ffdb5c139c3bbab97d3b06ee0674d75ab7f"),
					common.HexToAddress("0x1a1a8229e4a2fa06f73a564092976ba2dfe6aab8"),
					common.HexToAddress("0x346ada489c70c85ca665428389f1a971abbee960"),
					common.HexToAddress("0x555d4cd195bcb7d4196f2005db46a4b71c36c5a4"),
					common.HexToAddress("0x7af6aedf3382bb3de2dba61769d96444bf660494"),
					common.HexToAddress("0x3197b8ed3bcd7eea2c695951d9d57e833457072b"),
					common.HexToAddress("0xd6e9161fad50d2e697cda2b960fd26bf52a5d169"),
					common.HexToAddress("0x8eeeeafaca49e507bc9bba121dac97ec75774ff2"),
					common.HexToAddress("0xa828c2381bb91fc96cc269de73b99a4314ac4b5b"),
					common.HexToAddress("0x7fca0e918c06ff0b4e51ecf76670e07714e44a9c"),
					common.HexToAddress("0x9e057cebf2101a5e3e57906b834a2a82893b7739"),
					common.HexToAddress("0x58f25975086b8d23c028ebb651be064da0360367"),
					common.HexToAddress("0xe8bc0e78114ad8dc4290eaed78bcb9e3f5b91e32"),
					common.HexToAddress("0x695ce237df312f9a6c6a5386b91b37ae249d07dd"),
					common.HexToAddress("0xe79ef2d92a8e4d758d78dfcc8e61b2fa377ee78d"),
					common.HexToAddress("0x2a4559e84ca53e00b05d9d53086005432926a992"),
					common.HexToAddress("0x249f443d5c8400d7bc638a199d1f458b47a41a47"),
					common.HexToAddress("0x21396ca79a433a20b5904c9a77aa9a4f110ef80e"),
					common.HexToAddress("0x2d302db4b8182c6558b3ec9c2f1d69830dd5d6d3"),
					common.HexToAddress("0xeafdcce538785f97c0863288bfb3235e759b5d55"),
					common.HexToAddress("0xb0a48f9087ecb85390abf23ec1b1d591ddc757bd"),
					common.HexToAddress("0xfca96ff494f38a9c33a558caf8d9d628c819c2ca"),
					common.HexToAddress("0xb04891dc6e5ee5729bf41a08e5c51f8883498bfb"),
					common.HexToAddress("0x18fb21508a2983d9b8368d8cab95f563402612bf"),
					common.HexToAddress("0x220f59f7c6e19f374ef9f49a26382515b74ace7c"),
				},
				Penalties: []common.Address{
					common.HexToAddress("0x6f356f6a7ff84c46f59fee691a2a161494871eec"),
					common.HexToAddress("0x00021c85d8cf9ef6c73e8f95740f8e874e4c9d1f"),
					common.HexToAddress("0x20d6826ef6a151e327f5b5fc41e42fff08c07311"),
					common.HexToAddress("0xb1847452a58a2e2a4ee658a192f0d5d511c6f3f2"),
					common.HexToAddress("0xd9d474b83c514920f44c519f83e23e7b6927d552"),
					common.HexToAddress("0x0b5ba833d689a2ec8a3f5275f2b033bdd2de337b"),
				},
			},
			{Number: 85000000, Hash: common.HexToHash("0xe9a7cd7fdd4511de0d5cc85a694f8e3b436715928bb0c363b8d7449365353699"), Root: common.HexToHash("0x91a5296022a332ba10a38395f42eda33c4a66809bbc9daccf964ecf8eab8d67c")},
			{Number: 90000000, Hash: common.HexToHash("0x8d83a00b7134f4dcb68834ccc4b076ba3521dffd32ceb426fe95dc20fbc29508"), Root: common.HexToHash("0x345ce1be4edec079844299cfe84822c1f6a032b00afe86d72242856befbc970e")},
			{Number: 95000000, Hash: common.HexToHash("0x3fe0d509b753ba5bbb9e8bd10e90599cab6542d3aad53a5842a24b53d09864c7"), Root: common.HexToHash("0x6f6853c31b489fab75a9b92276fa5b734b7bb2f095f7870034f45dfff61df5c2")},
			// V2-era gap-block anchor at 97,999,650 (round 17888509).
			// ~800k blocks before EIP-1559 (98,800,200) and Cancun (98,802,000) — anchor
			// for short-path sync to test EIP-1559 + Cancun activation.
			// Source: rpc.xdcrpc.com, XDPoS_getMasternodesByNumber, 2026-05-11.
			{
				Number: 97999650,
				Hash:   common.HexToHash("0xe4871c5eab51fe52f23cfddba567f8f9b9504ab3764ecaec487093b69aa408b1"),
				Root:   common.HexToHash("0x80dee69905db26ccb365d784d31a32ffb397671024954f9eab7f6c06c4b90aa4"),
				Masternodes: []common.Address{
					common.HexToAddress("0x5651290bdd3a952357066b324f9334b544100140"),
					common.HexToAddress("0x2a591f3d64f3ce6b1d2afeead839ad76aab9feb2"),
					common.HexToAddress("0x74d3ac0efc4c22ea05150d7501c95c610b130c4b"),
					common.HexToAddress("0xcc8247cfaed1950dfd6dd4bc23a0ecab014c3b6c"),
					common.HexToAddress("0xb1693d224d4fd70ad6c9c9bdc44faa3ce21fb40d"),
					common.HexToAddress("0x047ffe1fc7f6d0b7168c4ccc312221089629f470"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0x49d3fa92eec838f644e8cacf2c93533d29b6c713"),
					common.HexToAddress("0xb9a3a97f6a02a86483bf02cb33f8b33d2d117708"),
					common.HexToAddress("0xb38aba47a5563fa4aedc2a649ef819b9fb160b6a"),
					common.HexToAddress("0xe230905c99aaa7b68402af8611b89ceda743191e"),
					common.HexToAddress("0xdb2e141595d8edf6b1ce40b10d57ca5b83855ec5"),
					common.HexToAddress("0x7525f63e5f739ef952fbea50c1dc97ef5d5bd984"),
					common.HexToAddress("0x9043fafbe8833adafb449b559cef300a9632763f"),
					common.HexToAddress("0x35898873c021f9f4fa01a76c7fa595159f5523e7"),
					common.HexToAddress("0x497c44f4a22099109ad7d194aad4fbe78dceb788"),
					common.HexToAddress("0x1aff171caa8c1ea93bac4c27676f356d054412b4"),
					common.HexToAddress("0x4b7076c988da8a0ef87f1af137f7abc39557b746"),
					common.HexToAddress("0x360b9e5870fc91e375f902fc134f91739f4a99c7"),
					common.HexToAddress("0x3056a8bff9a17b12d08f1837d0b44cf1e2018fbe"),
					common.HexToAddress("0x9fce52c5c451599235c17bc37e99f846d25ee6ec"),
					common.HexToAddress("0xa4657c02208797985adedcbd048efc82291dbdb2"),
					common.HexToAddress("0x2d74d0125982bdc3a9f54a10216d82509379e821"),
					common.HexToAddress("0xa70b87c39a1237ba53953a1da04b23d4db28eace"),
					common.HexToAddress("0x92d32364313c376dcae272e113fd04cea194d2c8"),
					common.HexToAddress("0xdef4bd67f9e2627ca495b5f71794fab1bab40619"),
					common.HexToAddress("0xd5bb37763625bc16f2ad0791d87e2726004241e4"),
					common.HexToAddress("0x39ee018a85e4469a1b335efe014067e315bd6594"),
					common.HexToAddress("0xcfccdea1006a5cfa7d9484b5b293b46964c265c0"),
					common.HexToAddress("0xd22fdac1459760f698618d927bbe22249e2b29b9"),
					common.HexToAddress("0xe4710a854b24062ff37ab6636bd9a456e24c1635"),
					common.HexToAddress("0xccab2f5267bc66b69f1688560c2e075216908a2c"),
					common.HexToAddress("0x8f2fb5da850042b7da5097061f098493f8ec6dd8"),
					common.HexToAddress("0xbbd2d417a8b6f1b1d7a267cd1d7402b443f35cfe"),
					common.HexToAddress("0x65c90c2d3e99d8366f90db7f4d25f23a0a569d49"),
					common.HexToAddress("0xe494fe5a38b7212ab999152d1d45adab8d84a8a7"),
					common.HexToAddress("0x70916660766043c23443479658008eeedad8cb94"),
					common.HexToAddress("0xe2bc9a03d5ae35e130c8bf99ea50c022de375db7"),
					common.HexToAddress("0x619f838ea2a12cdb508e759c3e0697e021d52ceb"),
					common.HexToAddress("0xdccd99da1c942a36c5dcaf26d19b98c815dfcb73"),
					common.HexToAddress("0x03d9e17ae3ff2c6712e44e25b09ac5ee91f6c9ff"),
					common.HexToAddress("0x1e0103ba7665d15328b3886927d4f0a85f8b2299"),
					common.HexToAddress("0x595b8170eaf2e53e47cc20db47ad063a1e6e2c0f"),
					common.HexToAddress("0x8e455bb521212bdcf8cb326e32dc1183cb3fd887"),
					common.HexToAddress("0xaf3db8ad8154820303adc6be0d9b10ef8e33024f"),
					common.HexToAddress("0xc67c2dec79da735d6587d8db3c23271d557196ab"),
					common.HexToAddress("0x24c0832d9df8189166d8e4e2cedc40ad69077b17"),
					common.HexToAddress("0xe865a5b2bf699a4b498de8a8c55da14bb0d94b21"),
					common.HexToAddress("0xf04f32c46f1a16663bc7f6409b35b33f3daa9a03"),
					common.HexToAddress("0xe8e8194c0a8e5a32306c7a86052a4e8ca4b8729d"),
					common.HexToAddress("0x450d714e65f4de007937c56fb1c4686efd4fb4ec"),
					common.HexToAddress("0xa72ce94a09db26dce57a4852409abc2fff07a962"),
					common.HexToAddress("0x63443ffdb5c139c3bbab97d3b06ee0674d75ab7f"),
					common.HexToAddress("0x1a7c3d7481adc7e067f2f73f35f44143d7bf02d4"),
					common.HexToAddress("0x2f86476faa31c3f5a3d5b9376282e1b02b4dfa00"),
					common.HexToAddress("0xec4a5fbd2e46e97be98c212e668ef1d08d695440"),
					common.HexToAddress("0xd2fefdd118aa2bea5991dc079fd341d3e7a92caf"),
					common.HexToAddress("0x609cc32e7513135349fbe9ebd78ea8cdcfd9f819"),
					common.HexToAddress("0xc02aed857b01b4d60b378096221db3b60afadc37"),
					common.HexToAddress("0x0b0afb41c14dd921a9a4511c226dc29254ba0d8f"),
					common.HexToAddress("0xc7d49d0a2cf198deebd6ce581af465944ec8b2bb"),
					common.HexToAddress("0x72fb467ef6da285b6b0d8f7a25abd6049385d5fd"),
					common.HexToAddress("0x241ff0d3096e2e0b477780f9f551918a06827c05"),
					common.HexToAddress("0x4e111142fbf2edacc4ab122feb54b031dc3d95d9"),
					common.HexToAddress("0x1d393817ab218ebade3e8ad591593ec3b132b1f6"),
					common.HexToAddress("0x25c65b4b379ac37cf78357c4915f73677022eaff"),
					common.HexToAddress("0x1a1a8229e4a2fa06f73a564092976ba2dfe6aab8"),
					common.HexToAddress("0x19a1e02fec5d52be689f59b22d9c0f1765bd7052"),
					common.HexToAddress("0x1bc85db77617515381cbbb28fdd2b1a10264de11"),
					common.HexToAddress("0xfce02e190f722e790be06b3a6ec43e2f606dba65"),
					common.HexToAddress("0x051572edba4a8290bf45dd2d7ab80eb6cd56ccc6"),
					common.HexToAddress("0x39dae44e488ad467b5fa48889053758fb4e15acb"),
					common.HexToAddress("0x239b8e6cfe09d9324cf99412dd069788446385bc"),
					common.HexToAddress("0x33e45ae78f3bee669e97e13a14619f6cb51bde3a"),
					common.HexToAddress("0x89e07253f5eb733fc3aefe983b53189cfeafa141"),
					common.HexToAddress("0x346ada489c70c85ca665428389f1a971abbee960"),
					common.HexToAddress("0x621996eb1d03a6e9614ddf150f6123c5602c8418"),
					common.HexToAddress("0x7bda7752b3533b3b71346ff02f6314b8fe77ec43"),
					common.HexToAddress("0x7c0f72d80d9d8b822e2fb217e56be732a12fc8c9"),
					common.HexToAddress("0xfcbddd58be4616042543637a84ad18cb065adba4"),
					common.HexToAddress("0x3bddd35ddf0945c0151a4ccd547d9e7a0b1fa4cd"),
					common.HexToAddress("0x251aca934009f4dda1d904e28ad7f20b3da4d888"),
					common.HexToAddress("0x785076b971f2a90b029b680f90d4d609060c01d5"),
					common.HexToAddress("0x78fb8980d122c902ad1abeac523a92e9c24e75c4"),
					common.HexToAddress("0x82183d37848f38c807e274b15b86d16e9ae60fd3"),
					common.HexToAddress("0xa43a99c9752166ec30c8369ce1e84de43be1e617"),
					common.HexToAddress("0xd5384163e03481b8b1c13e8da611e05e2612586c"),
					common.HexToAddress("0x3396803b0cb3b5790911bb51b6c5193e9940793f"),
					common.HexToAddress("0x417b06236ecc5bf200a59152e92cd4923867409c"),
					common.HexToAddress("0xe495a6242b78fe35211116839ad1882e7c4fc564"),
					common.HexToAddress("0x9682520376f26a733a75588c0bdede7645bdfc4a"),
					common.HexToAddress("0xd97d7434af4ad873585c71df55fce07996e27a82"),
					common.HexToAddress("0x200f1c0b9411dd0f1fad9a76cc47cf8d56e0a19d"),
					common.HexToAddress("0x4e52755f091c4fb826b994666a3e207fdf3a0cc5"),
					common.HexToAddress("0x51aa6a6b6a738d44e6a4e00d6e02faa991cf44be"),
					common.HexToAddress("0xa6d916b338291ae14402d67af2b9d9e19bf72fd5"),
					common.HexToAddress("0xc7f52a1c275d470ff92718dfe27be7800f7bb697"),
					common.HexToAddress("0x4cfd9048cfe93e02e30a84c7538c726e980c1d78"),
					common.HexToAddress("0x844a6c40b34e2335fc6887db2975d55183082c0d"),
					common.HexToAddress("0x29a66147543707ef83d5d15e0a1d9f65cbe90e7c"),
					common.HexToAddress("0xcac04ac16876a65d3bf797679f34fc8272a1f6b4"),
					common.HexToAddress("0xab5d74a461bb0f2231abcc5341ba7d89b24f0926"),
					common.HexToAddress("0x67a24b5821724419bbc0710cbbb3122d84703318"),
					common.HexToAddress("0xb2e8a55ea7fccdd8cdfb1af8e497a6f793ddf63e"),
					common.HexToAddress("0x09bae325e54edf4dc8b79a8bb29f90deb90e8fe7"),
					common.HexToAddress("0x3b8a906602422fe9f316e6fa0c1728cfaa238766"),
					common.HexToAddress("0xa828c2381bb91fc96cc269de73b99a4314ac4b5b"),
					common.HexToAddress("0x7fca0e918c06ff0b4e51ecf76670e07714e44a9c"),
				},
				Penalties: []common.Address{
					common.HexToAddress("0x8e9976680f84fab8b1dff91716762855c1a975e1"),
					common.HexToAddress("0x4d21849446a60c9ecbcf6155d1152676b8a76b44"),
					common.HexToAddress("0x95e58330cc798c8f079b8c91ba4d960d114cd785"),
					common.HexToAddress("0x69a809f4d6e65792158c1bef35b316f6292eefb1"),
				},
			},
			{Number: 100000000, Hash: common.HexToHash("0x20fe76263ff361bc17f311ab7bc3228941a78264489c25e33bb7651503230cca"), Root: common.HexToHash("0xefb7729414071a00f29e72412d7257201010687639ce1815bb3f4a3dd84f2fcf")},
			// V2-era gap-block anchor at 101,999,250 (round 21912064).
			// Recent post-Cancun anchor.
			// Source: rpc.xdcrpc.com, XDPoS_getMasternodesByNumber, 2026-05-11.
			{
				Number: 101999250,
				Hash:   common.HexToHash("0xb8972e89505ac154e1185caa9d3ff300b83e5553c7bf70acb6503c1cd2dbb8e8"),
				Root:   common.HexToHash("0x12e097b5078c30468be7b5da0ca137f86a76c33aff823eaf952b5e1f85aef4b5"),
				Masternodes: []common.Address{
					common.HexToAddress("0xcc8247cfaed1950dfd6dd4bc23a0ecab014c3b6c"),
					common.HexToAddress("0x047ffe1fc7f6d0b7168c4ccc312221089629f470"),
					common.HexToAddress("0x2a591f3d64f3ce6b1d2afeead839ad76aab9feb2"),
					common.HexToAddress("0x74d3ac0efc4c22ea05150d7501c95c610b130c4b"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0x49d3fa92eec838f644e8cacf2c93533d29b6c713"),
					common.HexToAddress("0x785076b971f2a90b029b680f90d4d609060c01d5"),
					common.HexToAddress("0xb1693d224d4fd70ad6c9c9bdc44faa3ce21fb40d"),
					common.HexToAddress("0x5651290bdd3a952357066b324f9334b544100140"),
					common.HexToAddress("0xa43a99c9752166ec30c8369ce1e84de43be1e617"),
					common.HexToAddress("0xa70b87c39a1237ba53953a1da04b23d4db28eace"),
					common.HexToAddress("0x4b7076c988da8a0ef87f1af137f7abc39557b746"),
					common.HexToAddress("0xdccd99da1c942a36c5dcaf26d19b98c815dfcb73"),
					common.HexToAddress("0x1a7c3d7481adc7e067f2f73f35f44143d7bf02d4"),
					common.HexToAddress("0x450d714e65f4de007937c56fb1c4686efd4fb4ec"),
					common.HexToAddress("0xa4657c02208797985adedcbd048efc82291dbdb2"),
					common.HexToAddress("0xd2fefdd118aa2bea5991dc079fd341d3e7a92caf"),
					common.HexToAddress("0xaf3db8ad8154820303adc6be0d9b10ef8e33024f"),
					common.HexToAddress("0x3056a8bff9a17b12d08f1837d0b44cf1e2018fbe"),
					common.HexToAddress("0x35898873c021f9f4fa01a76c7fa595159f5523e7"),
					common.HexToAddress("0xd22fdac1459760f698618d927bbe22249e2b29b9"),
					common.HexToAddress("0xd5bb37763625bc16f2ad0791d87e2726004241e4"),
					common.HexToAddress("0x2f86476faa31c3f5a3d5b9376282e1b02b4dfa00"),
					common.HexToAddress("0x9043fafbe8833adafb449b559cef300a9632763f"),
					common.HexToAddress("0x619f838ea2a12cdb508e759c3e0697e021d52ceb"),
					common.HexToAddress("0xb38aba47a5563fa4aedc2a649ef819b9fb160b6a"),
					common.HexToAddress("0x7525f63e5f739ef952fbea50c1dc97ef5d5bd984"),
					common.HexToAddress("0x360b9e5870fc91e375f902fc134f91739f4a99c7"),
					common.HexToAddress("0xdef4bd67f9e2627ca495b5f71794fab1bab40619"),
					common.HexToAddress("0x39ee018a85e4469a1b335efe014067e315bd6594"),
					common.HexToAddress("0x9fce52c5c451599235c17bc37e99f846d25ee6ec"),
					common.HexToAddress("0x241ff0d3096e2e0b477780f9f551918a06827c05"),
					common.HexToAddress("0xe4710a854b24062ff37ab6636bd9a456e24c1635"),
					common.HexToAddress("0x497c44f4a22099109ad7d194aad4fbe78dceb788"),
					common.HexToAddress("0x72fb467ef6da285b6b0d8f7a25abd6049385d5fd"),
					common.HexToAddress("0x65c90c2d3e99d8366f90db7f4d25f23a0a569d49"),
					common.HexToAddress("0xc02aed857b01b4d60b378096221db3b60afadc37"),
					common.HexToAddress("0xa72ce94a09db26dce57a4852409abc2fff07a962"),
					common.HexToAddress("0x63443ffdb5c139c3bbab97d3b06ee0674d75ab7f"),
					common.HexToAddress("0xf04f32c46f1a16663bc7f6409b35b33f3daa9a03"),
					common.HexToAddress("0x8e455bb521212bdcf8cb326e32dc1183cb3fd887"),
					common.HexToAddress("0x609cc32e7513135349fbe9ebd78ea8cdcfd9f819"),
					common.HexToAddress("0xe2bc9a03d5ae35e130c8bf99ea50c022de375db7"),
					common.HexToAddress("0xc67c2dec79da735d6587d8db3c23271d557196ab"),
					common.HexToAddress("0xcfccdea1006a5cfa7d9484b5b293b46964c265c0"),
					common.HexToAddress("0xdb2e141595d8edf6b1ce40b10d57ca5b83855ec5"),
					common.HexToAddress("0xbbd2d417a8b6f1b1d7a267cd1d7402b443f35cfe"),
					common.HexToAddress("0x8f2fb5da850042b7da5097061f098493f8ec6dd8"),
					common.HexToAddress("0xe865a5b2bf699a4b498de8a8c55da14bb0d94b21"),
					common.HexToAddress("0x92d32364313c376dcae272e113fd04cea194d2c8"),
					common.HexToAddress("0xec4a5fbd2e46e97be98c212e668ef1d08d695440"),
					common.HexToAddress("0xe8e8194c0a8e5a32306c7a86052a4e8ca4b8729d"),
					common.HexToAddress("0x1aff171caa8c1ea93bac4c27676f356d054412b4"),
					common.HexToAddress("0x1d393817ab218ebade3e8ad591593ec3b132b1f6"),
					common.HexToAddress("0x1e0103ba7665d15328b3886927d4f0a85f8b2299"),
					common.HexToAddress("0x0b0afb41c14dd921a9a4511c226dc29254ba0d8f"),
					common.HexToAddress("0x2d74d0125982bdc3a9f54a10216d82509379e821"),
					common.HexToAddress("0xe230905c99aaa7b68402af8611b89ceda743191e"),
					common.HexToAddress("0xe494fe5a38b7212ab999152d1d45adab8d84a8a7"),
					common.HexToAddress("0x25c65b4b379ac37cf78357c4915f73677022eaff"),
					common.HexToAddress("0x03d9e17ae3ff2c6712e44e25b09ac5ee91f6c9ff"),
					common.HexToAddress("0x24c0832d9df8189166d8e4e2cedc40ad69077b17"),
					common.HexToAddress("0xc7d49d0a2cf198deebd6ce581af465944ec8b2bb"),
					common.HexToAddress("0xb9a3a97f6a02a86483bf02cb33f8b33d2d117708"),
					common.HexToAddress("0xccab2f5267bc66b69f1688560c2e075216908a2c"),
					common.HexToAddress("0x4e111142fbf2edacc4ab122feb54b031dc3d95d9"),
					common.HexToAddress("0x1a1a8229e4a2fa06f73a564092976ba2dfe6aab8"),
					common.HexToAddress("0x051572edba4a8290bf45dd2d7ab80eb6cd56ccc6"),
					common.HexToAddress("0x239b8e6cfe09d9324cf99412dd069788446385bc"),
					common.HexToAddress("0x04a76d9f7ae68f1e3771f5d1c8bd319bb0b09e13"),
					common.HexToAddress("0x89e07253f5eb733fc3aefe983b53189cfeafa141"),
					common.HexToAddress("0x53fca59ae84841ba3c57fd709e57a01fe18801ab"),
					common.HexToAddress("0x205720bb184a61d69c270a77789ae94b7d2c5e88"),
					common.HexToAddress("0x39dae44e488ad467b5fa48889053758fb4e15acb"),
					common.HexToAddress("0x0b80bf9615e7fb34d48504dc51386da3cabf20ef"),
					common.HexToAddress("0x19a1e02fec5d52be689f59b22d9c0f1765bd7052"),
					common.HexToAddress("0x24eaf6eda6b6bdde516c71bb3445712ce57a3ea0"),
					common.HexToAddress("0x1bc85db77617515381cbbb28fdd2b1a10264de11"),
					common.HexToAddress("0xfce02e190f722e790be06b3a6ec43e2f606dba65"),
					common.HexToAddress("0x33e45ae78f3bee669e97e13a14619f6cb51bde3a"),
					common.HexToAddress("0x59c4aa10ab424cb33868c05af2626e72c1d41a6d"),
					common.HexToAddress("0xfd65b556175f32d98673ec32a2046b50dc39e12d"),
					common.HexToAddress("0xee68d8bf300b427f6bfefdb27972abb7e7f97c81"),
					common.HexToAddress("0x346ada489c70c85ca665428389f1a971abbee960"),
					common.HexToAddress("0x249f443d5c8400d7bc638a199d1f458b47a41a47"),
					common.HexToAddress("0xb95d3439a7d3654e7871e72213caaad472ec8325"),
					common.HexToAddress("0xb495b026cbf87664d68f279e55524aa61e6e9d5e"),
					common.HexToAddress("0x823a47d0a1f4c5781ead9f0d5b361557a45355bd"),
					common.HexToAddress("0xa6d916b338291ae14402d67af2b9d9e19bf72fd5"),
					common.HexToAddress("0x8f5fdc5f5f5f8c9832d4df256414f2a982404830"),
					common.HexToAddress("0xc1c9152c47ddb5002ed2501df812061ae6f75398"),
					common.HexToAddress("0xebf8e4904fe2bd561475e9e0e65a3336c56f83d3"),
					common.HexToAddress("0xc533d1fdd6f4728d37fbed50caaecfce477f784c"),
					common.HexToAddress("0xd64c15787bb52bbfe0d195df0d954725469a318e"),
					common.HexToAddress("0x09bae325e54edf4dc8b79a8bb29f90deb90e8fe7"),
					common.HexToAddress("0xbd46f94ca626a3ac72e60ca7efde379e42603b98"),
					common.HexToAddress("0x64e2e07bb17d978108824219741b9cc9e52b4443"),
					common.HexToAddress("0x200f1c0b9411dd0f1fad9a76cc47cf8d56e0a19d"),
					common.HexToAddress("0xc7f52a1c275d470ff92718dfe27be7800f7bb697"),
					common.HexToAddress("0xc7bf1cd426e6f47d879fbaba789d7c5740ce9b4b"),
					common.HexToAddress("0xfcbddd58be4616042543637a84ad18cb065adba4"),
					common.HexToAddress("0x13afe4210b6340723883be07618d3a4f019c2adc"),
					common.HexToAddress("0x83e12760c1e324b16fe68bc23ffc69b37d17ee23"),
					common.HexToAddress("0x5a39debded5481a5e5b73a1551fd31208b88da4e"),
					common.HexToAddress("0x0afe5a6890cf357022dfdaac7e2d6e248755cdfd"),
					common.HexToAddress("0xc6b903af2816a2423a3300ed853e5e7d26ea0cf0"),
					common.HexToAddress("0x3b8a906602422fe9f316e6fa0c1728cfaa238766"),
					common.HexToAddress("0x66bb8c2724ed2dc09ece6024045e90e65c29eaff"),
				},
				Penalties: []common.Address{
					common.HexToAddress("0x349563f9b0e3167f816cc39b272e3f888e23d3f3"),
					common.HexToAddress("0x70916660766043c23443479658008eeedad8cb94"),
					common.HexToAddress("0x4d21849446a60c9ecbcf6155d1152676b8a76b44"),
					common.HexToAddress("0x95e58330cc798c8f079b8c91ba4d960d114cd785"),
					common.HexToAddress("0x69a809f4d6e65792158c1bef35b316f6292eefb1"),
				},
			},
			// Pre-EIP1559 gap-block anchor at 98,799,750 (450 blocks before
			// Eip1559Block = 98,800,200). Use for fast fork-upgrade testing of
			// EIP-1559 activation on mainnet without syncing 98M blocks first.
			// Source: rpc.ankr.com/xdc, XDPoS_getMasternodesByNumber, 2026-05-12.
			{
				Number: 98799750,
				Hash:   common.HexToHash("0xfcda328e09a006cfe14dbd33dcdfa2e23d10dc0798a0ad6f03aa32e04a0f0336"),
				Root:   common.HexToHash("0x54bb5bd66756824bb040e8d1fd76414e3f6d309d7044d3c9c388d433ed98b3cc"),
				Masternodes: []common.Address{
					common.HexToAddress("0xb1693d224d4fd70ad6c9c9bdc44faa3ce21fb40d"),
					common.HexToAddress("0xcc8247cfaed1950dfd6dd4bc23a0ecab014c3b6c"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0x5651290bdd3a952357066b324f9334b544100140"),
					common.HexToAddress("0x2a591f3d64f3ce6b1d2afeead839ad76aab9feb2"),
					common.HexToAddress("0x047ffe1fc7f6d0b7168c4ccc312221089629f470"),
					common.HexToAddress("0x74d3ac0efc4c22ea05150d7501c95c610b130c4b"),
					common.HexToAddress("0x49d3fa92eec838f644e8cacf2c93533d29b6c713"),
					common.HexToAddress("0xb9a3a97f6a02a86483bf02cb33f8b33d2d117708"),
					common.HexToAddress("0x595b8170eaf2e53e47cc20db47ad063a1e6e2c0f"),
					common.HexToAddress("0xe230905c99aaa7b68402af8611b89ceda743191e"),
					common.HexToAddress("0xdb2e141595d8edf6b1ce40b10d57ca5b83855ec5"),
					common.HexToAddress("0xd22fdac1459760f698618d927bbe22249e2b29b9"),
					common.HexToAddress("0x24c0832d9df8189166d8e4e2cedc40ad69077b17"),
					common.HexToAddress("0x35898873c021f9f4fa01a76c7fa595159f5523e7"),
					common.HexToAddress("0xdef4bd67f9e2627ca495b5f71794fab1bab40619"),
					common.HexToAddress("0x1aff171caa8c1ea93bac4c27676f356d054412b4"),
					common.HexToAddress("0x4b7076c988da8a0ef87f1af137f7abc39557b746"),
					common.HexToAddress("0x360b9e5870fc91e375f902fc134f91739f4a99c7"),
					common.HexToAddress("0xc02aed857b01b4d60b378096221db3b60afadc37"),
					common.HexToAddress("0xa4657c02208797985adedcbd048efc82291dbdb2"),
					common.HexToAddress("0x2d74d0125982bdc3a9f54a10216d82509379e821"),
					common.HexToAddress("0x609cc32e7513135349fbe9ebd78ea8cdcfd9f819"),
					common.HexToAddress("0x92d32364313c376dcae272e113fd04cea194d2c8"),
					common.HexToAddress("0x450d714e65f4de007937c56fb1c4686efd4fb4ec"),
					common.HexToAddress("0x9043fafbe8833adafb449b559cef300a9632763f"),
					common.HexToAddress("0xc7d49d0a2cf198deebd6ce581af465944ec8b2bb"),
					common.HexToAddress("0x9fce52c5c451599235c17bc37e99f846d25ee6ec"),
					common.HexToAddress("0xcfccdea1006a5cfa7d9484b5b293b46964c265c0"),
					common.HexToAddress("0xd5bb37763625bc16f2ad0791d87e2726004241e4"),
					common.HexToAddress("0xe4710a854b24062ff37ab6636bd9a456e24c1635"),
					common.HexToAddress("0xccab2f5267bc66b69f1688560c2e075216908a2c"),
					common.HexToAddress("0xec4a5fbd2e46e97be98c212e668ef1d08d695440"),
					common.HexToAddress("0x8f2fb5da850042b7da5097061f098493f8ec6dd8"),
					common.HexToAddress("0x65c90c2d3e99d8366f90db7f4d25f23a0a569d49"),
					common.HexToAddress("0xa72ce94a09db26dce57a4852409abc2fff07a962"),
					common.HexToAddress("0xe2bc9a03d5ae35e130c8bf99ea50c022de375db7"),
					common.HexToAddress("0x39ee018a85e4469a1b335efe014067e315bd6594"),
					common.HexToAddress("0xdccd99da1c942a36c5dcaf26d19b98c815dfcb73"),
					common.HexToAddress("0x03d9e17ae3ff2c6712e44e25b09ac5ee91f6c9ff"),
					common.HexToAddress("0x63443ffdb5c139c3bbab97d3b06ee0674d75ab7f"),
					common.HexToAddress("0xaf3db8ad8154820303adc6be0d9b10ef8e33024f"),
					common.HexToAddress("0xc67c2dec79da735d6587d8db3c23271d557196ab"),
					common.HexToAddress("0xb38aba47a5563fa4aedc2a649ef819b9fb160b6a"),
					common.HexToAddress("0x241ff0d3096e2e0b477780f9f551918a06827c05"),
					common.HexToAddress("0xbbd2d417a8b6f1b1d7a267cd1d7402b443f35cfe"),
					common.HexToAddress("0x1e0103ba7665d15328b3886927d4f0a85f8b2299"),
					common.HexToAddress("0xf04f32c46f1a16663bc7f6409b35b33f3daa9a03"),
					common.HexToAddress("0x1a7c3d7481adc7e067f2f73f35f44143d7bf02d4"),
					common.HexToAddress("0x8e455bb521212bdcf8cb326e32dc1183cb3fd887"),
					common.HexToAddress("0xa70b87c39a1237ba53953a1da04b23d4db28eace"),
					common.HexToAddress("0xe865a5b2bf699a4b498de8a8c55da14bb0d94b21"),
					common.HexToAddress("0xe8e8194c0a8e5a32306c7a86052a4e8ca4b8729d"),
					common.HexToAddress("0x2f86476faa31c3f5a3d5b9376282e1b02b4dfa00"),
					common.HexToAddress("0x4e111142fbf2edacc4ab122feb54b031dc3d95d9"),
					common.HexToAddress("0x619f838ea2a12cdb508e759c3e0697e021d52ceb"),
					common.HexToAddress("0xe494fe5a38b7212ab999152d1d45adab8d84a8a7"),
					common.HexToAddress("0x497c44f4a22099109ad7d194aad4fbe78dceb788"),
					common.HexToAddress("0xd2fefdd118aa2bea5991dc079fd341d3e7a92caf"),
					common.HexToAddress("0x0b0afb41c14dd921a9a4511c226dc29254ba0d8f"),
					common.HexToAddress("0x72fb467ef6da285b6b0d8f7a25abd6049385d5fd"),
					common.HexToAddress("0x3056a8bff9a17b12d08f1837d0b44cf1e2018fbe"),
					common.HexToAddress("0x7525f63e5f739ef952fbea50c1dc97ef5d5bd984"),
					common.HexToAddress("0x1d393817ab218ebade3e8ad591593ec3b132b1f6"),
					common.HexToAddress("0x25c65b4b379ac37cf78357c4915f73677022eaff"),
					common.HexToAddress("0x1a1a8229e4a2fa06f73a564092976ba2dfe6aab8"),
					common.HexToAddress("0x39dae44e488ad467b5fa48889053758fb4e15acb"),
					common.HexToAddress("0x19a1e02fec5d52be689f59b22d9c0f1765bd7052"),
					common.HexToAddress("0xfce02e190f722e790be06b3a6ec43e2f606dba65"),
					common.HexToAddress("0x051572edba4a8290bf45dd2d7ab80eb6cd56ccc6"),
					common.HexToAddress("0x1bc85db77617515381cbbb28fdd2b1a10264de11"),
					common.HexToAddress("0x33e45ae78f3bee669e97e13a14619f6cb51bde3a"),
					common.HexToAddress("0x89e07253f5eb733fc3aefe983b53189cfeafa141"),
					common.HexToAddress("0x239b8e6cfe09d9324cf99412dd069788446385bc"),
					common.HexToAddress("0x346ada489c70c85ca665428389f1a971abbee960"),
					common.HexToAddress("0x7c0f72d80d9d8b822e2fb217e56be732a12fc8c9"),
					common.HexToAddress("0x7bda7752b3533b3b71346ff02f6314b8fe77ec43"),
					common.HexToAddress("0x3b8a906602422fe9f316e6fa0c1728cfaa238766"),
					common.HexToAddress("0x251aca934009f4dda1d904e28ad7f20b3da4d888"),
					common.HexToAddress("0xa59318ba345b293f4ac5acb9f59a47365987b7da"),
					common.HexToAddress("0x935a34962ed8237d9700191320e3e0b66741133d"),
					common.HexToAddress("0x785076b971f2a90b029b680f90d4d609060c01d5"),
					common.HexToAddress("0x64e2e07bb17d978108824219741b9cc9e52b4443"),
					common.HexToAddress("0x3cc8e30f8be48e57dbac01d8c7b05fb18ef1f7c8"),
					common.HexToAddress("0xa43a99c9752166ec30c8369ce1e84de43be1e617"),
					common.HexToAddress("0xd5384163e03481b8b1c13e8da611e05e2612586c"),
					common.HexToAddress("0x3396803b0cb3b5790911bb51b6c5193e9940793f"),
					common.HexToAddress("0x417b06236ecc5bf200a59152e92cd4923867409c"),
					common.HexToAddress("0xfc5fea016be9ac2d23dfe18e16d3be79547e5466"),
					common.HexToAddress("0x9682520376f26a733a75588c0bdede7645bdfc4a"),
					common.HexToAddress("0xd97d7434af4ad873585c71df55fce07996e27a82"),
					common.HexToAddress("0xc7f52a1c275d470ff92718dfe27be7800f7bb697"),
					common.HexToAddress("0xa478633e8aba4188c25159e1103206eeca98bced"),
					common.HexToAddress("0x51aa6a6b6a738d44e6a4e00d6e02faa991cf44be"),
					common.HexToAddress("0xa6d916b338291ae14402d67af2b9d9e19bf72fd5"),
					common.HexToAddress("0x944dd93e0f6d213b0dce27590bd5a9a4351fafd6"),
					common.HexToAddress("0xac95f4af1e9efbc914895695e232fb8dbaa66275"),
					common.HexToAddress("0xcac04ac16876a65d3bf797679f34fc8272a1f6b4"),
					common.HexToAddress("0x29a66147543707ef83d5d15e0a1d9f65cbe90e7c"),
					common.HexToAddress("0xb2e8a55ea7fccdd8cdfb1af8e497a6f793ddf63e"),
					common.HexToAddress("0x76e9285b4a804033a1d87b21c4e9d4e7028ce944"),
					common.HexToAddress("0x67a24b5821724419bbc0710cbbb3122d84703318"),
					common.HexToAddress("0x2759e5176992c834e7c0da762ae6178de6e7e711"),
					common.HexToAddress("0x966f1f7e10f9bd531e31ab6bba0936944e00ebf9"),
					common.HexToAddress("0xfcbddd58be4616042543637a84ad18cb065adba4"),
					common.HexToAddress("0x2e32b4db98ae68ea725212040f5f29abc61ce18f"),
					common.HexToAddress("0x76df51309c6367678635a3ea76d1482666f55a05"),
					common.HexToAddress("0x391f3d21d9062ebbdd958e436b26d4b40928658c"),
				},
				Penalties: []common.Address{
					common.HexToAddress("0x70916660766043c23443479658008eeedad8cb94"),
					common.HexToAddress("0x8e9976680f84fab8b1dff91716762855c1a975e1"),
					common.HexToAddress("0x4d21849446a60c9ecbcf6155d1152676b8a76b44"),
					common.HexToAddress("0x95e58330cc798c8f079b8c91ba4d960d114cd785"),
					common.HexToAddress("0x69a809f4d6e65792158c1bef35b316f6292eefb1"),
				},
			},
			// Pre-Cancun gap-block anchor at 98,801,550 (450 blocks before
			// CancunBlock = 98,802,000, 1,350 blocks past Eip1559Block).
			// Same epoch group as Cancun fork; anchor here to test Cancun
			// activation independently of EIP-1559.
			// Source: rpc.ankr.com/xdc, XDPoS_getMasternodesByNumber, 2026-05-12.
			{
				Number: 98801550,
				Hash:   common.HexToHash("0x000c78a1b4a1e136e4486c3e8ad8726c21d7446d4637c1c0796e4e10f256f0f7"),
				Root:   common.HexToHash("0x119d6567fe8907d6f39251ea61bf87eb91bfae6a2517e7f14a014b8261934747"),
				Masternodes: []common.Address{
					common.HexToAddress("0xb1693d224d4fd70ad6c9c9bdc44faa3ce21fb40d"),
					common.HexToAddress("0xcc8247cfaed1950dfd6dd4bc23a0ecab014c3b6c"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0x5651290bdd3a952357066b324f9334b544100140"),
					common.HexToAddress("0x2a591f3d64f3ce6b1d2afeead839ad76aab9feb2"),
					common.HexToAddress("0x047ffe1fc7f6d0b7168c4ccc312221089629f470"),
					common.HexToAddress("0x74d3ac0efc4c22ea05150d7501c95c610b130c4b"),
					common.HexToAddress("0x49d3fa92eec838f644e8cacf2c93533d29b6c713"),
					common.HexToAddress("0xb9a3a97f6a02a86483bf02cb33f8b33d2d117708"),
					common.HexToAddress("0x595b8170eaf2e53e47cc20db47ad063a1e6e2c0f"),
					common.HexToAddress("0xe230905c99aaa7b68402af8611b89ceda743191e"),
					common.HexToAddress("0xdb2e141595d8edf6b1ce40b10d57ca5b83855ec5"),
					common.HexToAddress("0xd22fdac1459760f698618d927bbe22249e2b29b9"),
					common.HexToAddress("0x24c0832d9df8189166d8e4e2cedc40ad69077b17"),
					common.HexToAddress("0x35898873c021f9f4fa01a76c7fa595159f5523e7"),
					common.HexToAddress("0xdef4bd67f9e2627ca495b5f71794fab1bab40619"),
					common.HexToAddress("0x1aff171caa8c1ea93bac4c27676f356d054412b4"),
					common.HexToAddress("0x4b7076c988da8a0ef87f1af137f7abc39557b746"),
					common.HexToAddress("0x360b9e5870fc91e375f902fc134f91739f4a99c7"),
					common.HexToAddress("0xc02aed857b01b4d60b378096221db3b60afadc37"),
					common.HexToAddress("0xa4657c02208797985adedcbd048efc82291dbdb2"),
					common.HexToAddress("0x2d74d0125982bdc3a9f54a10216d82509379e821"),
					common.HexToAddress("0x609cc32e7513135349fbe9ebd78ea8cdcfd9f819"),
					common.HexToAddress("0x92d32364313c376dcae272e113fd04cea194d2c8"),
					common.HexToAddress("0x450d714e65f4de007937c56fb1c4686efd4fb4ec"),
					common.HexToAddress("0x9043fafbe8833adafb449b559cef300a9632763f"),
					common.HexToAddress("0xc7d49d0a2cf198deebd6ce581af465944ec8b2bb"),
					common.HexToAddress("0x9fce52c5c451599235c17bc37e99f846d25ee6ec"),
					common.HexToAddress("0xcfccdea1006a5cfa7d9484b5b293b46964c265c0"),
					common.HexToAddress("0xd5bb37763625bc16f2ad0791d87e2726004241e4"),
					common.HexToAddress("0xe4710a854b24062ff37ab6636bd9a456e24c1635"),
					common.HexToAddress("0xccab2f5267bc66b69f1688560c2e075216908a2c"),
					common.HexToAddress("0xec4a5fbd2e46e97be98c212e668ef1d08d695440"),
					common.HexToAddress("0x8f2fb5da850042b7da5097061f098493f8ec6dd8"),
					common.HexToAddress("0x65c90c2d3e99d8366f90db7f4d25f23a0a569d49"),
					common.HexToAddress("0xa72ce94a09db26dce57a4852409abc2fff07a962"),
					common.HexToAddress("0xe2bc9a03d5ae35e130c8bf99ea50c022de375db7"),
					common.HexToAddress("0x39ee018a85e4469a1b335efe014067e315bd6594"),
					common.HexToAddress("0xdccd99da1c942a36c5dcaf26d19b98c815dfcb73"),
					common.HexToAddress("0x03d9e17ae3ff2c6712e44e25b09ac5ee91f6c9ff"),
					common.HexToAddress("0x63443ffdb5c139c3bbab97d3b06ee0674d75ab7f"),
					common.HexToAddress("0xaf3db8ad8154820303adc6be0d9b10ef8e33024f"),
					common.HexToAddress("0xc67c2dec79da735d6587d8db3c23271d557196ab"),
					common.HexToAddress("0xb38aba47a5563fa4aedc2a649ef819b9fb160b6a"),
					common.HexToAddress("0x241ff0d3096e2e0b477780f9f551918a06827c05"),
					common.HexToAddress("0xbbd2d417a8b6f1b1d7a267cd1d7402b443f35cfe"),
					common.HexToAddress("0x1e0103ba7665d15328b3886927d4f0a85f8b2299"),
					common.HexToAddress("0xf04f32c46f1a16663bc7f6409b35b33f3daa9a03"),
					common.HexToAddress("0x1a7c3d7481adc7e067f2f73f35f44143d7bf02d4"),
					common.HexToAddress("0x8e455bb521212bdcf8cb326e32dc1183cb3fd887"),
					common.HexToAddress("0xa70b87c39a1237ba53953a1da04b23d4db28eace"),
					common.HexToAddress("0xe865a5b2bf699a4b498de8a8c55da14bb0d94b21"),
					common.HexToAddress("0xe8e8194c0a8e5a32306c7a86052a4e8ca4b8729d"),
					common.HexToAddress("0x2f86476faa31c3f5a3d5b9376282e1b02b4dfa00"),
					common.HexToAddress("0x4e111142fbf2edacc4ab122feb54b031dc3d95d9"),
					common.HexToAddress("0x619f838ea2a12cdb508e759c3e0697e021d52ceb"),
					common.HexToAddress("0xe494fe5a38b7212ab999152d1d45adab8d84a8a7"),
					common.HexToAddress("0x497c44f4a22099109ad7d194aad4fbe78dceb788"),
					common.HexToAddress("0xd2fefdd118aa2bea5991dc079fd341d3e7a92caf"),
					common.HexToAddress("0x0b0afb41c14dd921a9a4511c226dc29254ba0d8f"),
					common.HexToAddress("0x72fb467ef6da285b6b0d8f7a25abd6049385d5fd"),
					common.HexToAddress("0x3056a8bff9a17b12d08f1837d0b44cf1e2018fbe"),
					common.HexToAddress("0x7525f63e5f739ef952fbea50c1dc97ef5d5bd984"),
					common.HexToAddress("0x1d393817ab218ebade3e8ad591593ec3b132b1f6"),
					common.HexToAddress("0x25c65b4b379ac37cf78357c4915f73677022eaff"),
					common.HexToAddress("0x39dae44e488ad467b5fa48889053758fb4e15acb"),
					common.HexToAddress("0x19a1e02fec5d52be689f59b22d9c0f1765bd7052"),
					common.HexToAddress("0xfce02e190f722e790be06b3a6ec43e2f606dba65"),
					common.HexToAddress("0x051572edba4a8290bf45dd2d7ab80eb6cd56ccc6"),
					common.HexToAddress("0x1bc85db77617515381cbbb28fdd2b1a10264de11"),
					common.HexToAddress("0x33e45ae78f3bee669e97e13a14619f6cb51bde3a"),
					common.HexToAddress("0x89e07253f5eb733fc3aefe983b53189cfeafa141"),
					common.HexToAddress("0x239b8e6cfe09d9324cf99412dd069788446385bc"),
					common.HexToAddress("0x346ada489c70c85ca665428389f1a971abbee960"),
					common.HexToAddress("0x7c0f72d80d9d8b822e2fb217e56be732a12fc8c9"),
					common.HexToAddress("0x7bda7752b3533b3b71346ff02f6314b8fe77ec43"),
					common.HexToAddress("0x3b8a906602422fe9f316e6fa0c1728cfaa238766"),
					common.HexToAddress("0x251aca934009f4dda1d904e28ad7f20b3da4d888"),
					common.HexToAddress("0xa59318ba345b293f4ac5acb9f59a47365987b7da"),
					common.HexToAddress("0x935a34962ed8237d9700191320e3e0b66741133d"),
					common.HexToAddress("0x785076b971f2a90b029b680f90d4d609060c01d5"),
					common.HexToAddress("0x64e2e07bb17d978108824219741b9cc9e52b4443"),
					common.HexToAddress("0x3cc8e30f8be48e57dbac01d8c7b05fb18ef1f7c8"),
					common.HexToAddress("0xa43a99c9752166ec30c8369ce1e84de43be1e617"),
					common.HexToAddress("0xd5384163e03481b8b1c13e8da611e05e2612586c"),
					common.HexToAddress("0x3396803b0cb3b5790911bb51b6c5193e9940793f"),
					common.HexToAddress("0x417b06236ecc5bf200a59152e92cd4923867409c"),
					common.HexToAddress("0xfc5fea016be9ac2d23dfe18e16d3be79547e5466"),
					common.HexToAddress("0x9682520376f26a733a75588c0bdede7645bdfc4a"),
					common.HexToAddress("0xd97d7434af4ad873585c71df55fce07996e27a82"),
					common.HexToAddress("0xc7f52a1c275d470ff92718dfe27be7800f7bb697"),
					common.HexToAddress("0xa478633e8aba4188c25159e1103206eeca98bced"),
					common.HexToAddress("0x51aa6a6b6a738d44e6a4e00d6e02faa991cf44be"),
					common.HexToAddress("0xa6d916b338291ae14402d67af2b9d9e19bf72fd5"),
					common.HexToAddress("0x944dd93e0f6d213b0dce27590bd5a9a4351fafd6"),
					common.HexToAddress("0xac95f4af1e9efbc914895695e232fb8dbaa66275"),
					common.HexToAddress("0xcac04ac16876a65d3bf797679f34fc8272a1f6b4"),
					common.HexToAddress("0xb2e8a55ea7fccdd8cdfb1af8e497a6f793ddf63e"),
					common.HexToAddress("0x76e9285b4a804033a1d87b21c4e9d4e7028ce944"),
					common.HexToAddress("0x67a24b5821724419bbc0710cbbb3122d84703318"),
					common.HexToAddress("0x2759e5176992c834e7c0da762ae6178de6e7e711"),
					common.HexToAddress("0x966f1f7e10f9bd531e31ab6bba0936944e00ebf9"),
					common.HexToAddress("0xfcbddd58be4616042543637a84ad18cb065adba4"),
					common.HexToAddress("0x2e32b4db98ae68ea725212040f5f29abc61ce18f"),
					common.HexToAddress("0x76df51309c6367678635a3ea76d1482666f55a05"),
					common.HexToAddress("0x391f3d21d9062ebbdd958e436b26d4b40928658c"),
					common.HexToAddress("0x5f4ff7948061a605e9d64b4d5fde927b70bc3fa5"),
					common.HexToAddress("0x66bb8c2724ed2dc09ece6024045e90e65c29eaff"),
				},
				Penalties: []common.Address{
					common.HexToAddress("0x1a1a8229e4a2fa06f73a564092976ba2dfe6aab8"),
					common.HexToAddress("0x29a66147543707ef83d5d15e0a1d9f65cbe90e7c"),
					common.HexToAddress("0x70916660766043c23443479658008eeedad8cb94"),
					common.HexToAddress("0x8e9976680f84fab8b1dff91716762855c1a975e1"),
					common.HexToAddress("0x4d21849446a60c9ecbcf6155d1152676b8a76b44"),
					common.HexToAddress("0x95e58330cc798c8f079b8c91ba4d960d114cd785"),
					common.HexToAddress("0x69a809f4d6e65792158c1bef35b316f6292eefb1"),
				},
			},
			// Near-tip V2-era gap-block anchor at 102,513,150.
			// ~7k blocks behind current mainnet head — for near-instant sync to
			// current mainnet state. Mirrors the Apothem near-tip anchor at
			// 81,856,350 (PR #575).
			// Source: rpc.ankr.com/xdc, XDPoS_getMasternodesByNumber, 2026-05-13.
			{
				Number: 102513150,
				Hash:   common.HexToHash("0x835802fcea7d869bf6b5cae1811ae1f53afdf1201af119773f1f602fd2dc7aad"),
				Root:   common.HexToHash("0x53747cd6c1313475417abe6444bc29438ae8b717c095e8550470c74a6d425468"),
				Masternodes: []common.Address{
					common.HexToAddress("0xcc8247cfaed1950dfd6dd4bc23a0ecab014c3b6c"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0xb1693d224d4fd70ad6c9c9bdc44faa3ce21fb40d"),
					common.HexToAddress("0x5651290bdd3a952357066b324f9334b544100140"),
					common.HexToAddress("0xa43a99c9752166ec30c8369ce1e84de43be1e617"),
					common.HexToAddress("0x2a591f3d64f3ce6b1d2afeead839ad76aab9feb2"),
					common.HexToAddress("0x047ffe1fc7f6d0b7168c4ccc312221089629f470"),
					common.HexToAddress("0x74d3ac0efc4c22ea05150d7501c95c610b130c4b"),
					common.HexToAddress("0x785076b971f2a90b029b680f90d4d609060c01d5"),
					common.HexToAddress("0x49d3fa92eec838f644e8cacf2c93533d29b6c713"),
					common.HexToAddress("0x241ff0d3096e2e0b477780f9f551918a06827c05"),
					common.HexToAddress("0xbbd2d417a8b6f1b1d7a267cd1d7402b443f35cfe"),
					common.HexToAddress("0x4b7076c988da8a0ef87f1af137f7abc39557b746"),
					common.HexToAddress("0x39ee018a85e4469a1b335efe014067e315bd6594"),
					common.HexToAddress("0x9fce52c5c451599235c17bc37e99f846d25ee6ec"),
					common.HexToAddress("0x497c44f4a22099109ad7d194aad4fbe78dceb788"),
					common.HexToAddress("0xe4710a854b24062ff37ab6636bd9a456e24c1635"),
					common.HexToAddress("0xc02aed857b01b4d60b378096221db3b60afadc37"),
					common.HexToAddress("0xf04f32c46f1a16663bc7f6409b35b33f3daa9a03"),
					common.HexToAddress("0x609cc32e7513135349fbe9ebd78ea8cdcfd9f819"),
					common.HexToAddress("0x72fb467ef6da285b6b0d8f7a25abd6049385d5fd"),
					common.HexToAddress("0x8e455bb521212bdcf8cb326e32dc1183cb3fd887"),
					common.HexToAddress("0xd22fdac1459760f698618d927bbe22249e2b29b9"),
					common.HexToAddress("0xe2bc9a03d5ae35e130c8bf99ea50c022de375db7"),
					common.HexToAddress("0x2f86476faa31c3f5a3d5b9376282e1b02b4dfa00"),
					common.HexToAddress("0x9043fafbe8833adafb449b559cef300a9632763f"),
					common.HexToAddress("0xe865a5b2bf699a4b498de8a8c55da14bb0d94b21"),
					common.HexToAddress("0x8f2fb5da850042b7da5097061f098493f8ec6dd8"),
					common.HexToAddress("0x1a7c3d7481adc7e067f2f73f35f44143d7bf02d4"),
					common.HexToAddress("0xd5bb37763625bc16f2ad0791d87e2726004241e4"),
					common.HexToAddress("0xb38aba47a5563fa4aedc2a649ef819b9fb160b6a"),
					common.HexToAddress("0x7525f63e5f739ef952fbea50c1dc97ef5d5bd984"),
					common.HexToAddress("0x619f838ea2a12cdb508e759c3e0697e021d52ceb"),
					common.HexToAddress("0x450d714e65f4de007937c56fb1c4686efd4fb4ec"),
					common.HexToAddress("0x03d9e17ae3ff2c6712e44e25b09ac5ee91f6c9ff"),
					common.HexToAddress("0xdb2e141595d8edf6b1ce40b10d57ca5b83855ec5"),
					common.HexToAddress("0xdccd99da1c942a36c5dcaf26d19b98c815dfcb73"),
					common.HexToAddress("0xa70b87c39a1237ba53953a1da04b23d4db28eace"),
					common.HexToAddress("0xd2fefdd118aa2bea5991dc079fd341d3e7a92caf"),
					common.HexToAddress("0x35898873c021f9f4fa01a76c7fa595159f5523e7"),
					common.HexToAddress("0xaf3db8ad8154820303adc6be0d9b10ef8e33024f"),
					common.HexToAddress("0xcfccdea1006a5cfa7d9484b5b293b46964c265c0"),
					common.HexToAddress("0xdef4bd67f9e2627ca495b5f71794fab1bab40619"),
					common.HexToAddress("0x360b9e5870fc91e375f902fc134f91739f4a99c7"),
					common.HexToAddress("0x65c90c2d3e99d8366f90db7f4d25f23a0a569d49"),
					common.HexToAddress("0xc67c2dec79da735d6587d8db3c23271d557196ab"),
					common.HexToAddress("0xa72ce94a09db26dce57a4852409abc2fff07a962"),
					common.HexToAddress("0x63443ffdb5c139c3bbab97d3b06ee0674d75ab7f"),
					common.HexToAddress("0x92d32364313c376dcae272e113fd04cea194d2c8"),
					common.HexToAddress("0xec4a5fbd2e46e97be98c212e668ef1d08d695440"),
					common.HexToAddress("0xe8e8194c0a8e5a32306c7a86052a4e8ca4b8729d"),
					common.HexToAddress("0x1aff171caa8c1ea93bac4c27676f356d054412b4"),
					common.HexToAddress("0x1d393817ab218ebade3e8ad591593ec3b132b1f6"),
					common.HexToAddress("0x1e0103ba7665d15328b3886927d4f0a85f8b2299"),
					common.HexToAddress("0x0b0afb41c14dd921a9a4511c226dc29254ba0d8f"),
					common.HexToAddress("0x2d74d0125982bdc3a9f54a10216d82509379e821"),
					common.HexToAddress("0xe230905c99aaa7b68402af8611b89ceda743191e"),
					common.HexToAddress("0xe494fe5a38b7212ab999152d1d45adab8d84a8a7"),
					common.HexToAddress("0xa4657c02208797985adedcbd048efc82291dbdb2"),
					common.HexToAddress("0x25c65b4b379ac37cf78357c4915f73677022eaff"),
					common.HexToAddress("0x24c0832d9df8189166d8e4e2cedc40ad69077b17"),
					common.HexToAddress("0xc7d49d0a2cf198deebd6ce581af465944ec8b2bb"),
					common.HexToAddress("0xb9a3a97f6a02a86483bf02cb33f8b33d2d117708"),
					common.HexToAddress("0xccab2f5267bc66b69f1688560c2e075216908a2c"),
					common.HexToAddress("0x4e111142fbf2edacc4ab122feb54b031dc3d95d9"),
					common.HexToAddress("0x051572edba4a8290bf45dd2d7ab80eb6cd56ccc6"),
					common.HexToAddress("0x239b8e6cfe09d9324cf99412dd069788446385bc"),
					common.HexToAddress("0x04a76d9f7ae68f1e3771f5d1c8bd319bb0b09e13"),
					common.HexToAddress("0x89e07253f5eb733fc3aefe983b53189cfeafa141"),
					common.HexToAddress("0x53fca59ae84841ba3c57fd709e57a01fe18801ab"),
					common.HexToAddress("0x205720bb184a61d69c270a77789ae94b7d2c5e88"),
					common.HexToAddress("0x39dae44e488ad467b5fa48889053758fb4e15acb"),
					common.HexToAddress("0x0b80bf9615e7fb34d48504dc51386da3cabf20ef"),
					common.HexToAddress("0x19a1e02fec5d52be689f59b22d9c0f1765bd7052"),
					common.HexToAddress("0x24eaf6eda6b6bdde516c71bb3445712ce57a3ea0"),
					common.HexToAddress("0x1bc85db77617515381cbbb28fdd2b1a10264de11"),
					common.HexToAddress("0xfce02e190f722e790be06b3a6ec43e2f606dba65"),
					common.HexToAddress("0x33e45ae78f3bee669e97e13a14619f6cb51bde3a"),
					common.HexToAddress("0x59c4aa10ab424cb33868c05af2626e72c1d41a6d"),
					common.HexToAddress("0xfd65b556175f32d98673ec32a2046b50dc39e12d"),
					common.HexToAddress("0xee68d8bf300b427f6bfefdb27972abb7e7f97c81"),
					common.HexToAddress("0x346ada489c70c85ca665428389f1a971abbee960"),
					common.HexToAddress("0x249f443d5c8400d7bc638a199d1f458b47a41a47"),
					common.HexToAddress("0xb95d3439a7d3654e7871e72213caaad472ec8325"),
					common.HexToAddress("0xb495b026cbf87664d68f279e55524aa61e6e9d5e"),
					common.HexToAddress("0x823a47d0a1f4c5781ead9f0d5b361557a45355bd"),
					common.HexToAddress("0x43bb2e3bb47d0a12d45c87dcdbd6d16a47e1000a"),
					common.HexToAddress("0xcac04ac16876a65d3bf797679f34fc8272a1f6b4"),
					common.HexToAddress("0xc1c9152c47ddb5002ed2501df812061ae6f75398"),
					common.HexToAddress("0xc533d1fdd6f4728d37fbed50caaecfce477f784c"),
					common.HexToAddress("0xd64c15787bb52bbfe0d195df0d954725469a318e"),
					common.HexToAddress("0x349563f9b0e3167f816cc39b272e3f888e23d3f3"),
					common.HexToAddress("0x09bae325e54edf4dc8b79a8bb29f90deb90e8fe7"),
					common.HexToAddress("0xe7a5556c87fe764dcba9bcd31e1f4aa27b638117"),
					common.HexToAddress("0x64e2e07bb17d978108824219741b9cc9e52b4443"),
					common.HexToAddress("0x200f1c0b9411dd0f1fad9a76cc47cf8d56e0a19d"),
					common.HexToAddress("0xc7f52a1c275d470ff92718dfe27be7800f7bb697"),
					common.HexToAddress("0xc7bf1cd426e6f47d879fbaba789d7c5740ce9b4b"),
					common.HexToAddress("0xfcbddd58be4616042543637a84ad18cb065adba4"),
					common.HexToAddress("0x13afe4210b6340723883be07618d3a4f019c2adc"),
					common.HexToAddress("0x83e12760c1e324b16fe68bc23ffc69b37d17ee23"),
					common.HexToAddress("0x5a39debded5481a5e5b73a1551fd31208b88da4e"),
					common.HexToAddress("0x0afe5a6890cf357022dfdaac7e2d6e248755cdfd"),
					common.HexToAddress("0xc6b903af2816a2423a3300ed853e5e7d26ea0cf0"),
					common.HexToAddress("0x3b8a906602422fe9f316e6fa0c1728cfaa238766"),
					common.HexToAddress("0x1c908c36c4470c3f66860e7c5152cc17e480ff54"),
					common.HexToAddress("0x7b03e5e7912b0ce65f8be7549e23cb08392e369c"),
					common.HexToAddress("0xaab7c7b91ba9322109fb761928e14ea37f7e5426"),
				},
				Penalties: []common.Address{
					common.HexToAddress("0x66bb8c2724ed2dc09ece6024045e90e65c29eaff"),
					common.HexToAddress("0x3056a8bff9a17b12d08f1837d0b44cf1e2018fbe"),
					common.HexToAddress("0xa6d916b338291ae14402d67af2b9d9e19bf72fd5"),
					common.HexToAddress("0x1a1a8229e4a2fa06f73a564092976ba2dfe6aab8"),
					common.HexToAddress("0x70916660766043c23443479658008eeedad8cb94"),
					common.HexToAddress("0x4d21849446a60c9ecbcf6155d1152676b8a76b44"),
					common.HexToAddress("0x95e58330cc798c8f079b8c91ba4d960d114cd785"),
					common.HexToAddress("0x69a809f4d6e65792158c1bef35b316f6292eefb1"),
				},
			},
		},
	}

	// XDCApothemChainConfig contains the chain parameters to run a node on the XDC Apothem testnet.
	// Chain ID: 51
	// Fork blocks aligned with XDPoSChain v2.6.8/v2.7.0 (TestnetChainConfig +
	// TestnetConstant). Pre-Byzantium 1/2/3/3/4 match canonical; Constantinople/
	// Petersburg/Istanbul are set to BerlinBlock so they pass CheckConfigForkOrder
	// while the XDC-specific TIPXDCXCancellationFee fallback in IsIstanbul/
	// IsPetersburg activates them earlier (at block 23,779,191 on Apothem) —
	// matching canonical behaviour. Activating Istanbul at block 0 would reprice
	// SLOAD/BALANCE/EXTCODEHASH (EIP-1884) and rewrite SSTORE (EIP-2200), causing
	// gas overcharge on early-history blocks vs canonical (~30k/tx at block 17).
	XDCApothemChainConfig = &ChainConfig{
		ChainID:                big.NewInt(51),
		HomesteadBlock:         big.NewInt(1),
		DAOForkBlock:           nil,
		DAOForkSupport:         false,
		EIP150Block:            big.NewInt(2),
		EIP155Block:            big.NewInt(3),
		EIP158Block:            big.NewInt(3),
		ByzantiumBlock:         big.NewInt(4),
		ConstantinopleBlock:    big.NewInt(61_290_000), // align with Berlin; effective Istanbul activation via TIPXDCXCancellationFee=23779191
		PetersburgBlock:        big.NewInt(61_290_000),
		IstanbulBlock:          big.NewInt(61_290_000),
		MuirGlacierBlock:       nil,
		BerlinBlock:            big.NewInt(61_290_000), // XDPoSChain TestnetConstant.berlinBlock — Target 31st March 2024
		LondonBlock:            big.NewInt(61_290_000), // XDPoSChain TestnetConstant.londonBlock — Target 31st March 2024
		Eip1559Block:           big.NewInt(71_550_000), // XDPoSChain TestnetConstant.eip1559Block — Target 14th Feb 2025
		CancunBlock:            big.NewInt(71_551_800), // XDPoSChain TestnetConstant.cancunBlock
		TIPUpgradeRewardBlock:  big.NewInt(83_600_000), // XinFinOrg/XDPoSChain#2383 (v2.8.0); activation verified on canonical (round>27,360,000; header@83,577,112 carries 25 validators)
		TIPUpgradePenaltyBlock: big.NewInt(83_600_000), // XinFinOrg/XDPoSChain#2383 (v2.8.0)
		XDPoS: &XDPoSConfig{
			Period:              2,                                                                 // 2 second block time
			Epoch:               900,                                                               // 900 blocks per epoch (~30 minutes)
			Reward:              5000,                                                              // Block reward in XDC
			RewardCheckpoint:    900,                                                               // Checkpoint for rewards
			Gap:                 450,                                                               // Gap blocks before epoch end
			FoudationWalletAddr: common.HexToAddress("0x746249c61f5832c5eed53172776b460491bdcd5c"), // Apothem foundation wallet
			V2: &V2{
				SwitchBlock:   big.NewInt(56828700), // TIPV2SwitchBlock — constants.testnet.go
				SwitchEpoch:   63143,                // Epoch number at V2 switch (56828700/900)
				AllConfigs:    ApothemV2Configs,
				CurrentConfig: ApothemV2Configs[0], // Initial config active at round 0
			},
		},
		// TrustedSyncCheckpoints: hardcoded Apothem checkpoints for near-instant sync.
		// Verified against xdc03-v268-apothem-113 (v2.6.8-stable) at 2026-05-08.
		// Current Apothem head: ~81,868,193.
		//
		// V2-era checkpoints use Path B: the active masternode set is embedded
		// directly in the entry, because Apothem V2 header.Validators is empty
		// and contract state isn't downloaded during checkpoint sync. The pre-seed
		// path in InsertHeadersBeforeCutoff falls back to these embedded addresses
		// to seed the V2 snapshot store.
		//
		// Selecting V2 anchor blocks: pick a *gap block* (block % 900 == 450),
		// not an arbitrary V2 block — the existing pre-seed path only fires when
		// cpNum % epoch == epoch - gap. The masternode list must match the active
		// set as of that gap block (sourced via XDPoS_getMasternodesByNumber).
		TrustedSyncCheckpoints: []*TrustedSyncCheckpoint{
			// Pre-NoHalvingMNReward (23,779,191).
			{Number: 23000000, Hash: common.HexToHash("0xe6e12585e21513b1a60c5654fbcecc29de294aae3b86e8d0fef9a3162a895d13"), Root: common.HexToHash("0xa0261f8050e775e73e0246e65833ef25cfcceea9c61b3c7b4857906971d5f174")},
			{Number: 50000000, Hash: common.HexToHash("0xaa1490d9dfca4e1da57be6a3701f0d8595d82e83eb00c6863f1092aca0df1a59"), Root: common.HexToHash("0x1223d8a8ab4fede337920456ef7d3abbc5f284b4728eb342a39e8c0b24aed9e0")},
			{Number: 55000000, Hash: common.HexToHash("0x8d46eed913abf4942eb6154512bee3b46ec8605e2499ec68a6177dd4fa6d5c5f"), Root: common.HexToHash("0xb70e4d1d65bc4cea3793e9308a5ca2c13eac058803cc3684aa86c10d26eca6b2")},
			{Number: 56000000, Hash: common.HexToHash("0x631c8d6db706b2b3380c9c38f649eeb5db0c5c457b85a1d43c3252a1b0ba8bd3"), Root: common.HexToHash("0x04c6365b9b7466c13c547f6fd1a06a13e8c82612cd5b207e4e06d229943bdd4d")},
			{Number: 56700000, Hash: common.HexToHash("0xb2f51bf5cf817c792e6b1391dcdb23b6bbf0c199c395d2d024b080fde7ea74ce"), Root: common.HexToHash("0x702f5e59786495f867c984c5334b266cce1e6daf7c4adb129c550e5d752feb65")},
			// V1→V2 switch (TIPV2SwitchBlock). InsertHeadersBeforeCutoff
			// special-cases this via Source 1 (header.Validators / V1 Extra) and
			// falls back to Source 2 (the embedded list below) if header decoding
			// returns empty — necessary on V1-format Extra paths that may return
			// no addresses during checkpoint sync.
			// Source: rpc.ankr.com/xdc_testnet, XDPoS_getMasternodesByNumber, 2026-05-11. Round 0.
			{
				Number: 56828700,
				Hash:   common.HexToHash("0x5ac967a20d0826edb4e50d0d6ceb6c2f3ae3356b43b28b307756e42e0bd35905"),
				Root:   common.HexToHash("0x425aa61465e293f9282d297095db05d7525e2b2777f4ed1cea87036f34e4f3ee"),
				Masternodes: []common.Address{
					common.HexToAddress("0x219ad4fc274b5c82bca6600f32ebd6063feb6837"),
					common.HexToAddress("0x40964fcdd7cd130d6938976b06885d1a914480b4"),
					common.HexToAddress("0x45afe257f28f70333d91b2978d7d4d0013d04c48"),
					common.HexToAddress("0x59ebbff1abd4c9307b745b23bdd73e4fbffd64e9"),
					common.HexToAddress("0x7f77fff1df908bcf4795c20a3291b013735dceb1"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0x9c712e7769bb70b4f0618af7acebd32670657ff6"),
					common.HexToAddress("0xce04ae211d19b8138c7783964aaa1f7addd22275"),
					common.HexToAddress("0xd03da188bb791ef1dfc7638302b51a6a30ee83fc"),
					common.HexToAddress("0xda133da5981bf90e51c35e9dfe5b9f604d65ce47"),
					common.HexToAddress("0xe60986d35497291dde76c066df27d56f153cbf06"),
					common.HexToAddress("0xe65f06590ee4ed6d814309e5fa014b642b9272bd"),
					common.HexToAddress("0xebb849cfe83c46c68ba4c2d6f07a16bca991ea79"),
				},
				// PenaltyLen=0 at the V2 switch block (clean start). Omit Penalties.
			},
			// Pre-Berlin/London (61,290,000). Non-gap blocks (Number % 900 != 450),
			// so InsertHeadersBeforeCutoff's Path B pre-seed does NOT fire here.
			// Anchors still work for hash/root verification; V2 snapshot is recovered
			// via the post-anchor catchup window (PR #569) instead.
			{Number: 60000000, Hash: common.HexToHash("0x0f983fae967864722b208c79a630e9f805b653f1dbc81540f89fa6a0d2f132bc"), Root: common.HexToHash("0x96126561e5b5139eca576c8fbc2743909fa7866251222a8f99ed1a8c4db6d41c")},
			{Number: 60387450, Hash: common.HexToHash("0x705e8140707db85f2f59307c49c2cc95963a8c8cd681e2c86455b2af6569f4f6"), Root: common.HexToHash("0xc2d817c1e940a9a75b0c67024b14cc97055c62322c398b1a8e3ac49d9eac544b")},
			// Current V2-era gap-block anchor at 60,514,650 (round 3730159, epoch 67238).
			// ~53 blocks behind head — for near-instant sync to current Apothem state.
			// Source: rpc.xdcrpc.com, XDPoS_getMasternodesByNumber, 2026-05-11.
			{
				Number: 60514650,
				Hash:   common.HexToHash("0x685397cea246e9c0aa21a470c24167ddeb6c267c8169c4ce89a90d1648153233"),
				Root:   common.HexToHash("0x8a98ca5d4fbff2afec6039e0190c376f6cd7dfa3dd6bbb976c799c767230a100"),
				Masternodes: []common.Address{
					common.HexToAddress("0xfffee9d20a8b70145711433f5d53fc35ad753c42"),
					common.HexToAddress("0x3efa4d1d78391cc0929f7d7e01e9eeaaac8f4862"),
					common.HexToAddress("0x9594884daf2acde67e89095702459b06dd60c302"),
					common.HexToAddress("0xebb849cfe83c46c68ba4c2d6f07a16bca991ea79"),
					common.HexToAddress("0xd6f1314f450b0a391b99a8aad8e6f2be2482aa68"),
					common.HexToAddress("0x7d4953d9a2b055467dac460726842f30d6598c0e"),
					common.HexToAddress("0xce04ae211d19b8138c7783964aaa1f7addd22275"),
					common.HexToAddress("0x2d0fa4912bd4c65b392075be9a6bf29c43d8c3ee"),
					common.HexToAddress("0x93eea33bc34371ad5fe0e5741199bf8e038ad19b"),
					common.HexToAddress("0xe71bf07a2f502bd7dd8a92a10e13b441ee72b908"),
					common.HexToAddress("0x59ebbff1abd4c9307b745b23bdd73e4fbffd64e9"),
					common.HexToAddress("0x9c5b33fc32cf8126be3436c3a59db6067b4a577f"),
					common.HexToAddress("0x219ad4fc274b5c82bca6600f32ebd6063feb6837"),
					common.HexToAddress("0x3176fd7a840920d3b2869a46fed4231e4e4d4103"),
					common.HexToAddress("0x40964fcdd7cd130d6938976b06885d1a914480b4"),
					common.HexToAddress("0x8767e56fe79aff44d1edcfd7dbaed1b1499c7b3d"),
					common.HexToAddress("0x45afe257f28f70333d91b2978d7d4d0013d04c48"),
					common.HexToAddress("0xeae878c4ee2bfe1f9b3583f30fb2e48c85de3969"),
					common.HexToAddress("0xb5e5acab644dcbdf64103af723be8d62ccec76f4"),
					common.HexToAddress("0x9c712e7769bb70b4f0618af7acebd32670657ff6"),
					common.HexToAddress("0xcd13ed39d35ffdcf3c6d982cfd75883517f392fb"),
					common.HexToAddress("0x32fb028453207699d7c15bb66377bcf9b29fb0fc"),
					common.HexToAddress("0x8d9532faf1690dd03b4822b6953052fe597231a6"),
					common.HexToAddress("0x70e0038d2ec66c5737f2561efcb60c10588cc7af"),
					common.HexToAddress("0xb84bf95eaf3f18f4893a1f3057f38fb0544ac2aa"),
					common.HexToAddress("0x33fb554db5a905e3faa77c2e88c55cd497a30998"),
					common.HexToAddress("0x0dc32713f06f5dc52e152f0fbdfe01b490ff1642"),
					common.HexToAddress("0x81ac7b84abc4ee6e8e021963b113ee8cd2a7732d"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0xd9285aaba32a2b38541de12126d969bd8da90ded"),
				},
				Penalties: []common.Address{
					common.HexToAddress("0xd03da188bb791ef1dfc7638302b51a6a30ee83fc"),
					common.HexToAddress("0x5df57b8cca482d69d5274e38231dcec7da2781d0"),
					common.HexToAddress("0x34f48c6407d9778ba848c0ae01f36d63a58fa791"),
					common.HexToAddress("0x7f77fff1df908bcf4795c20a3291b013735dceb1"),
					common.HexToAddress("0x1a1b58d133effb6ba1631da7297d8cd58f65fa73"),
					common.HexToAddress("0x20ae82dc469de249c6814af6c71f5617621fe92d"),
					common.HexToAddress("0x42e490e0c04f1be8c8cb9b76f630bf97f662169d"),
					common.HexToAddress("0xda133da5981bf90e51c35e9dfe5b9f604d65ce47"),
					common.HexToAddress("0xe60986d35497291dde76c066df27d56f153cbf06"),
					common.HexToAddress("0xe65f06590ee4ed6d814309e5fa014b642b9272bd"),
				},
			},
			// Pre-Constantinople gap-block anchor at 61,289,550 (450 blocks before
			// fork at 61,290,000). Post-V2-switch (V2 at 56,828,700), so V2-era
			// anchor with embedded masternodes + penalties. Use for fast fork-
			// upgrade testing of Constantinople/Petersburg/Istanbul/Berlin/London
			// (all share the 61,290,000 block on Apothem).
			// Source: rpc.ankr.com/xdc_testnet, XDPoS_getMasternodesByNumber, 2026-05-12.
			{
				Number: 61289550,
				Hash:   common.HexToHash("0xa1b5c1adc433c92f27b3848b100f221ca82beea8c070175d7cd74f5b9bffc995"),
				Root:   common.HexToHash("0x14391b6b48a002ee2cad28c2905b6791005f0472358a1e9819d72eb1173413c0"),
				Masternodes: []common.Address{
					common.HexToAddress("0xfffee9d20a8b70145711433f5d53fc35ad753c42"),
					common.HexToAddress("0x3efa4d1d78391cc0929f7d7e01e9eeaaac8f4862"),
					common.HexToAddress("0x9594884daf2acde67e89095702459b06dd60c302"),
					common.HexToAddress("0xd6f1314f450b0a391b99a8aad8e6f2be2482aa68"),
					common.HexToAddress("0x7d4953d9a2b055467dac460726842f30d6598c0e"),
					common.HexToAddress("0xce04ae211d19b8138c7783964aaa1f7addd22275"),
					common.HexToAddress("0x2d0fa4912bd4c65b392075be9a6bf29c43d8c3ee"),
					common.HexToAddress("0x93eea33bc34371ad5fe0e5741199bf8e038ad19b"),
					common.HexToAddress("0xe71bf07a2f502bd7dd8a92a10e13b441ee72b908"),
					common.HexToAddress("0x59ebbff1abd4c9307b745b23bdd73e4fbffd64e9"),
					common.HexToAddress("0x9c5b33fc32cf8126be3436c3a59db6067b4a577f"),
					common.HexToAddress("0x219ad4fc274b5c82bca6600f32ebd6063feb6837"),
					common.HexToAddress("0x3176fd7a840920d3b2869a46fed4231e4e4d4103"),
					common.HexToAddress("0x40964fcdd7cd130d6938976b06885d1a914480b4"),
					common.HexToAddress("0x8767e56fe79aff44d1edcfd7dbaed1b1499c7b3d"),
					common.HexToAddress("0x45afe257f28f70333d91b2978d7d4d0013d04c48"),
					common.HexToAddress("0xeae878c4ee2bfe1f9b3583f30fb2e48c85de3969"),
					common.HexToAddress("0xb5e5acab644dcbdf64103af723be8d62ccec76f4"),
					common.HexToAddress("0x9c712e7769bb70b4f0618af7acebd32670657ff6"),
					common.HexToAddress("0xcd13ed39d35ffdcf3c6d982cfd75883517f392fb"),
					common.HexToAddress("0x32fb028453207699d7c15bb66377bcf9b29fb0fc"),
					common.HexToAddress("0x8d9532faf1690dd03b4822b6953052fe597231a6"),
					common.HexToAddress("0x70e0038d2ec66c5737f2561efcb60c10588cc7af"),
					common.HexToAddress("0xb84bf95eaf3f18f4893a1f3057f38fb0544ac2aa"),
					common.HexToAddress("0x33fb554db5a905e3faa77c2e88c55cd497a30998"),
					common.HexToAddress("0x0dc32713f06f5dc52e152f0fbdfe01b490ff1642"),
					common.HexToAddress("0x81ac7b84abc4ee6e8e021963b113ee8cd2a7732d"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0xd9285aaba32a2b38541de12126d969bd8da90ded"),
				},
				Penalties: []common.Address{
					common.HexToAddress("0x7f77fff1df908bcf4795c20a3291b013735dceb1"),
					common.HexToAddress("0xebb849cfe83c46c68ba4c2d6f07a16bca991ea79"),
					common.HexToAddress("0xd03da188bb791ef1dfc7638302b51a6a30ee83fc"),
					common.HexToAddress("0x5df57b8cca482d69d5274e38231dcec7da2781d0"),
					common.HexToAddress("0x34f48c6407d9778ba848c0ae01f36d63a58fa791"),
					common.HexToAddress("0x1a1b58d133effb6ba1631da7297d8cd58f65fa73"),
					common.HexToAddress("0x20ae82dc469de249c6814af6c71f5617621fe92d"),
					common.HexToAddress("0x42e490e0c04f1be8c8cb9b76f630bf97f662169d"),
					common.HexToAddress("0xda133da5981bf90e51c35e9dfe5b9f604d65ce47"),
					common.HexToAddress("0xe60986d35497291dde76c066df27d56f153cbf06"),
					common.HexToAddress("0xe65f06590ee4ed6d814309e5fa014b642b9272bd"),
				},
			},
			// V2-era gap-block anchor at 71,490,150 (round 14821951, epoch 79434).
			// Sits ~60k blocks before Eip1559Block=71,550,000 — primary use case is
			// short-path sync to test EIP-1559 activation on Apothem.
			// Source: rpc.ankr.com/xdc_testnet, XDPoS_getMasternodesByNumber, 2026-05-10.
			{
				Number: 71490150,
				Hash:   common.HexToHash("0x9f8598582d2a0a328abec59b26fa9c386cf75b9f459b04f9ccfb34e7793ca26d"),
				Root:   common.HexToHash("0xe655fe7bde5f2dc0deef45409b0f1cc7f6819dc9c036bfcff6547ea19e12fd0a"),
				Masternodes: []common.Address{
					common.HexToAddress("0xfffee9d20a8b70145711433f5d53fc35ad753c42"),
					common.HexToAddress("0x7f77fff1df908bcf4795c20a3291b013735dceb1"),
					common.HexToAddress("0x0dc32713f06f5dc52e152f0fbdfe01b490ff1642"),
					common.HexToAddress("0x2d0fa4912bd4c65b392075be9a6bf29c43d8c3ee"),
					common.HexToAddress("0x59ebbff1abd4c9307b745b23bdd73e4fbffd64e9"),
					common.HexToAddress("0x9594884daf2acde67e89095702459b06dd60c302"),
					common.HexToAddress("0x5df57b8cca482d69d5274e38231dcec7da2781d0"),
					common.HexToAddress("0x33fb554db5a905e3faa77c2e88c55cd497a30998"),
					common.HexToAddress("0xe71bf07a2f502bd7dd8a92a10e13b441ee72b908"),
					common.HexToAddress("0xebb849cfe83c46c68ba4c2d6f07a16bca991ea79"),
					common.HexToAddress("0x9c5b33fc32cf8126be3436c3a59db6067b4a577f"),
					common.HexToAddress("0x3efa4d1d78391cc0929f7d7e01e9eeaaac8f4862"),
					common.HexToAddress("0xfcdcd51159092e923a3011f626f99228923830f1"),
					common.HexToAddress("0x219ad4fc274b5c82bca6600f32ebd6063feb6837"),
					common.HexToAddress("0x8767e56fe79aff44d1edcfd7dbaed1b1499c7b3d"),
					common.HexToAddress("0x40964fcdd7cd130d6938976b06885d1a914480b4"),
					common.HexToAddress("0x70e0038d2ec66c5737f2561efcb60c10588cc7af"),
					common.HexToAddress("0x45afe257f28f70333d91b2978d7d4d0013d04c48"),
					common.HexToAddress("0xb5e5acab644dcbdf64103af723be8d62ccec76f4"),
					common.HexToAddress("0xcd13ed39d35ffdcf3c6d982cfd75883517f392fb"),
					common.HexToAddress("0x32fb028453207699d7c15bb66377bcf9b29fb0fc"),
					common.HexToAddress("0x8d9532faf1690dd03b4822b6953052fe597231a6"),
					common.HexToAddress("0xeae878c4ee2bfe1f9b3583f30fb2e48c85de3969"),
					common.HexToAddress("0xb84bf95eaf3f18f4893a1f3057f38fb0544ac2aa"),
					common.HexToAddress("0x34f48c6407d9778ba848c0ae01f36d63a58fa791"),
					common.HexToAddress("0x93eea33bc34371ad5fe0e5741199bf8e038ad19b"),
					common.HexToAddress("0x1a1b58d133effb6ba1631da7297d8cd58f65fa73"),
					common.HexToAddress("0xd6f1314f450b0a391b99a8aad8e6f2be2482aa68"),
					common.HexToAddress("0x81ac7b84abc4ee6e8e021963b113ee8cd2a7732d"),
					common.HexToAddress("0xd9285aaba32a2b38541de12126d969bd8da90ded"),
					common.HexToAddress("0x05a18817360bab4a2fab4958ab43beea66985828"),
					common.HexToAddress("0x7d4953d9a2b055467dac460726842f30d6598c0e"),
					common.HexToAddress("0x3176fd7a840920d3b2869a46fed4231e4e4d4103"),
				},
				Penalties: []common.Address{
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0xce04ae211d19b8138c7783964aaa1f7addd22275"),
					common.HexToAddress("0x11e75cff00b1e9e9a7c8b3d069e908713ed3e049"),
					common.HexToAddress("0x8ebe9b0ce09105714e6a006d751faf45c435570b"),
					common.HexToAddress("0xd03da188bb791ef1dfc7638302b51a6a30ee83fc"),
					common.HexToAddress("0x20ae82dc469de249c6814af6c71f5617621fe92d"),
					common.HexToAddress("0x42e490e0c04f1be8c8cb9b76f630bf97f662169d"),
					common.HexToAddress("0xda133da5981bf90e51c35e9dfe5b9f604d65ce47"),
					common.HexToAddress("0xe60986d35497291dde76c066df27d56f153cbf06"),
					common.HexToAddress("0xe65f06590ee4ed6d814309e5fa014b642b9272bd"),
				},
			},
			// Pre-EIP1559 gap-block anchor at 71,549,550 (450 blocks before
			// Eip1559Block = 71,550,000). Use for fast fork-upgrade testing of
			// EIP-1559 activation on Apothem (vs the 71,490,150 anchor which is
			// ~60k blocks earlier — useful when you want to start right at the
			// fork boundary instead of sync-stress-test the preceding range).
			// Source: rpc.ankr.com/xdc_testnet, XDPoS_getMasternodesByNumber, 2026-05-12.
			{
				Number: 71549550,
				Hash:   common.HexToHash("0xda2f702fafb5767f60ec85098b863b24c2e18a8fe149d13a69d8b095f475c626"),
				Root:   common.HexToHash("0x84a5ec6ce512d3a604e495877f93e89df9f4ca79b056fbbd0e9c13c8fd83ad4a"),
				Masternodes: []common.Address{
					common.HexToAddress("0xfffee9d20a8b70145711433f5d53fc35ad753c42"),
					common.HexToAddress("0x7f77fff1df908bcf4795c20a3291b013735dceb1"),
					common.HexToAddress("0x0dc32713f06f5dc52e152f0fbdfe01b490ff1642"),
					common.HexToAddress("0x2d0fa4912bd4c65b392075be9a6bf29c43d8c3ee"),
					common.HexToAddress("0x59ebbff1abd4c9307b745b23bdd73e4fbffd64e9"),
					common.HexToAddress("0x9594884daf2acde67e89095702459b06dd60c302"),
					common.HexToAddress("0x5df57b8cca482d69d5274e38231dcec7da2781d0"),
					common.HexToAddress("0x33fb554db5a905e3faa77c2e88c55cd497a30998"),
					common.HexToAddress("0xe71bf07a2f502bd7dd8a92a10e13b441ee72b908"),
					common.HexToAddress("0xebb849cfe83c46c68ba4c2d6f07a16bca991ea79"),
					common.HexToAddress("0x9c5b33fc32cf8126be3436c3a59db6067b4a577f"),
					common.HexToAddress("0x3efa4d1d78391cc0929f7d7e01e9eeaaac8f4862"),
					common.HexToAddress("0x219ad4fc274b5c82bca6600f32ebd6063feb6837"),
					common.HexToAddress("0x8767e56fe79aff44d1edcfd7dbaed1b1499c7b3d"),
					common.HexToAddress("0x40964fcdd7cd130d6938976b06885d1a914480b4"),
					common.HexToAddress("0x70e0038d2ec66c5737f2561efcb60c10588cc7af"),
					common.HexToAddress("0x45afe257f28f70333d91b2978d7d4d0013d04c48"),
					common.HexToAddress("0xb5e5acab644dcbdf64103af723be8d62ccec76f4"),
					common.HexToAddress("0xcd13ed39d35ffdcf3c6d982cfd75883517f392fb"),
					common.HexToAddress("0x32fb028453207699d7c15bb66377bcf9b29fb0fc"),
					common.HexToAddress("0x8d9532faf1690dd03b4822b6953052fe597231a6"),
					common.HexToAddress("0xeae878c4ee2bfe1f9b3583f30fb2e48c85de3969"),
					common.HexToAddress("0xb84bf95eaf3f18f4893a1f3057f38fb0544ac2aa"),
					common.HexToAddress("0x34f48c6407d9778ba848c0ae01f36d63a58fa791"),
					common.HexToAddress("0x93eea33bc34371ad5fe0e5741199bf8e038ad19b"),
					common.HexToAddress("0x1a1b58d133effb6ba1631da7297d8cd58f65fa73"),
					common.HexToAddress("0xd6f1314f450b0a391b99a8aad8e6f2be2482aa68"),
					common.HexToAddress("0x81ac7b84abc4ee6e8e021963b113ee8cd2a7732d"),
					common.HexToAddress("0xd9285aaba32a2b38541de12126d969bd8da90ded"),
					common.HexToAddress("0x05a18817360bab4a2fab4958ab43beea66985828"),
					common.HexToAddress("0x7d4953d9a2b055467dac460726842f30d6598c0e"),
					common.HexToAddress("0x3176fd7a840920d3b2869a46fed4231e4e4d4103"),
				},
				Penalties: []common.Address{
					common.HexToAddress("0xfcdcd51159092e923a3011f626f99228923830f1"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0xce04ae211d19b8138c7783964aaa1f7addd22275"),
					common.HexToAddress("0x11e75cff00b1e9e9a7c8b3d069e908713ed3e049"),
					common.HexToAddress("0x8ebe9b0ce09105714e6a006d751faf45c435570b"),
					common.HexToAddress("0xd03da188bb791ef1dfc7638302b51a6a30ee83fc"),
					common.HexToAddress("0x20ae82dc469de249c6814af6c71f5617621fe92d"),
					common.HexToAddress("0x42e490e0c04f1be8c8cb9b76f630bf97f662169d"),
					common.HexToAddress("0xda133da5981bf90e51c35e9dfe5b9f604d65ce47"),
					common.HexToAddress("0xe60986d35497291dde76c066df27d56f153cbf06"),
					common.HexToAddress("0xe65f06590ee4ed6d814309e5fa014b642b9272bd"),
				},
			},
			// Pre-Cancun gap-block anchor at 71,551,350 (450 blocks before
			// CancunBlock = 71,551,800, 1,350 blocks past Eip1559Block).
			// Same epoch group as Cancun fork; anchor here to test Cancun
			// activation independently of EIP-1559.
			// Source: rpc.ankr.com/xdc_testnet, XDPoS_getMasternodesByNumber, 2026-05-12.
			{
				Number: 71551350,
				Hash:   common.HexToHash("0x883ab4e1ce75f31d1ef692f29c608fed65d2ae373d4646bdd9683a7ab531f6f4"),
				Root:   common.HexToHash("0x2348f986093d509693f588cd15dc0f7f81ec7a7b441c533d7ab49712cd68e397"),
				Masternodes: []common.Address{
					common.HexToAddress("0xe71bf07a2f502bd7dd8a92a10e13b441ee72b908"),
					common.HexToAddress("0x9c5b33fc32cf8126be3436c3a59db6067b4a577f"),
					common.HexToAddress("0x0dc32713f06f5dc52e152f0fbdfe01b490ff1642"),
					common.HexToAddress("0x2d0fa4912bd4c65b392075be9a6bf29c43d8c3ee"),
					common.HexToAddress("0x59ebbff1abd4c9307b745b23bdd73e4fbffd64e9"),
					common.HexToAddress("0x219ad4fc274b5c82bca6600f32ebd6063feb6837"),
					common.HexToAddress("0x40964fcdd7cd130d6938976b06885d1a914480b4"),
					common.HexToAddress("0x93eea33bc34371ad5fe0e5741199bf8e038ad19b"),
					common.HexToAddress("0x34f48c6407d9778ba848c0ae01f36d63a58fa791"),
					common.HexToAddress("0xebb849cfe83c46c68ba4c2d6f07a16bca991ea79"),
					common.HexToAddress("0xfffee9d20a8b70145711433f5d53fc35ad753c42"),
					common.HexToAddress("0x3efa4d1d78391cc0929f7d7e01e9eeaaac8f4862"),
					common.HexToAddress("0x45afe257f28f70333d91b2978d7d4d0013d04c48"),
					common.HexToAddress("0xeae878c4ee2bfe1f9b3583f30fb2e48c85de3969"),
					common.HexToAddress("0x1a1b58d133effb6ba1631da7297d8cd58f65fa73"),
					common.HexToAddress("0x32fb028453207699d7c15bb66377bcf9b29fb0fc"),
					common.HexToAddress("0xcd13ed39d35ffdcf3c6d982cfd75883517f392fb"),
					common.HexToAddress("0x8d9532faf1690dd03b4822b6953052fe597231a6"),
					common.HexToAddress("0x33fb554db5a905e3faa77c2e88c55cd497a30998"),
					common.HexToAddress("0xb84bf95eaf3f18f4893a1f3057f38fb0544ac2aa"),
					common.HexToAddress("0x5df57b8cca482d69d5274e38231dcec7da2781d0"),
					common.HexToAddress("0x81ac7b84abc4ee6e8e021963b113ee8cd2a7732d"),
					common.HexToAddress("0xd6f1314f450b0a391b99a8aad8e6f2be2482aa68"),
					common.HexToAddress("0xd9285aaba32a2b38541de12126d969bd8da90ded"),
					common.HexToAddress("0x05a18817360bab4a2fab4958ab43beea66985828"),
					common.HexToAddress("0x3176fd7a840920d3b2869a46fed4231e4e4d4103"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
				},
				Penalties: []common.Address{
					common.HexToAddress("0x7f77fff1df908bcf4795c20a3291b013735dceb1"),
					common.HexToAddress("0x9594884daf2acde67e89095702459b06dd60c302"),
					common.HexToAddress("0x8767e56fe79aff44d1edcfd7dbaed1b1499c7b3d"),
					common.HexToAddress("0x70e0038d2ec66c5737f2561efcb60c10588cc7af"),
					common.HexToAddress("0xb5e5acab644dcbdf64103af723be8d62ccec76f4"),
					common.HexToAddress("0x7d4953d9a2b055467dac460726842f30d6598c0e"),
					common.HexToAddress("0xfcdcd51159092e923a3011f626f99228923830f1"),
					common.HexToAddress("0xce04ae211d19b8138c7783964aaa1f7addd22275"),
					common.HexToAddress("0x11e75cff00b1e9e9a7c8b3d069e908713ed3e049"),
					common.HexToAddress("0x8ebe9b0ce09105714e6a006d751faf45c435570b"),
					common.HexToAddress("0xd03da188bb791ef1dfc7638302b51a6a30ee83fc"),
					common.HexToAddress("0x20ae82dc469de249c6814af6c71f5617621fe92d"),
					common.HexToAddress("0x42e490e0c04f1be8c8cb9b76f630bf97f662169d"),
					common.HexToAddress("0xda133da5981bf90e51c35e9dfe5b9f604d65ce47"),
					common.HexToAddress("0xe60986d35497291dde76c066df27d56f153cbf06"),
					common.HexToAddress("0xe65f06590ee4ed6d814309e5fa014b642b9272bd"),
				},
			},
			// V2-era gap-block anchor at 80,000,550 (round 23640417, epoch 88889).
			// ~1.85M blocks behind current Apothem head (~81.8M).
			// Source: apothem.xdcrpc.com, XDPoS_getMasternodesByNumber, 2026-05-11.
			{
				Number: 80000550,
				Hash:   common.HexToHash("0xa019b6fa24690e9322f682a046c28300689af9bab337050b6d81c10c90c106ce"),
				Root:   common.HexToHash("0x9fdf8f1c5678abff1acf5074ddcebceba063855d6c565c50aa67f1974445ee35"),
				Masternodes: []common.Address{
					common.HexToAddress("0xe71bf07a2f502bd7dd8a92a10e13b441ee72b908"),
					common.HexToAddress("0x9c5b33fc32cf8126be3436c3a59db6067b4a577f"),
					common.HexToAddress("0x0dc32713f06f5dc52e152f0fbdfe01b490ff1642"),
					common.HexToAddress("0x2d0fa4912bd4c65b392075be9a6bf29c43d8c3ee"),
					common.HexToAddress("0x59ebbff1abd4c9307b745b23bdd73e4fbffd64e9"),
					common.HexToAddress("0x219ad4fc274b5c82bca6600f32ebd6063feb6837"),
					common.HexToAddress("0x40964fcdd7cd130d6938976b06885d1a914480b4"),
					common.HexToAddress("0x34f48c6407d9778ba848c0ae01f36d63a58fa791"),
					common.HexToAddress("0xfffee9d20a8b70145711433f5d53fc35ad753c42"),
					common.HexToAddress("0x3efa4d1d78391cc0929f7d7e01e9eeaaac8f4862"),
					common.HexToAddress("0x8767e56fe79aff44d1edcfd7dbaed1b1499c7b3d"),
					common.HexToAddress("0x45afe257f28f70333d91b2978d7d4d0013d04c48"),
					common.HexToAddress("0xeae878c4ee2bfe1f9b3583f30fb2e48c85de3969"),
					common.HexToAddress("0xcd13ed39d35ffdcf3c6d982cfd75883517f392fb"),
					common.HexToAddress("0x70e0038d2ec66c5737f2561efcb60c10588cc7af"),
					common.HexToAddress("0x33fb554db5a905e3faa77c2e88c55cd497a30998"),
					common.HexToAddress("0xb84bf95eaf3f18f4893a1f3057f38fb0544ac2aa"),
					common.HexToAddress("0x5df57b8cca482d69d5274e38231dcec7da2781d0"),
					common.HexToAddress("0x81ac7b84abc4ee6e8e021963b113ee8cd2a7732d"),
					common.HexToAddress("0xd6f1314f450b0a391b99a8aad8e6f2be2482aa68"),
					common.HexToAddress("0xd9285aaba32a2b38541de12126d969bd8da90ded"),
					common.HexToAddress("0x7d4953d9a2b055467dac460726842f30d6598c0e"),
					common.HexToAddress("0x05a18817360bab4a2fab4958ab43beea66985828"),
					common.HexToAddress("0x3176fd7a840920d3b2869a46fed4231e4e4d4103"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0x9594884daf2acde67e89095702459b06dd60c302"),
				},
				Penalties: []common.Address{
					common.HexToAddress("0x1a1b58d133effb6ba1631da7297d8cd58f65fa73"),
					common.HexToAddress("0xb5e5acab644dcbdf64103af723be8d62ccec76f4"),
					common.HexToAddress("0x8d9532faf1690dd03b4822b6953052fe597231a6"),
					common.HexToAddress("0x93eea33bc34371ad5fe0e5741199bf8e038ad19b"),
					common.HexToAddress("0xebb849cfe83c46c68ba4c2d6f07a16bca991ea79"),
					common.HexToAddress("0xce04ae211d19b8138c7783964aaa1f7addd22275"),
					common.HexToAddress("0x32fb028453207699d7c15bb66377bcf9b29fb0fc"),
					common.HexToAddress("0xfcdcd51159092e923a3011f626f99228923830f1"),
					common.HexToAddress("0x11e75cff00b1e9e9a7c8b3d069e908713ed3e049"),
					common.HexToAddress("0x8ebe9b0ce09105714e6a006d751faf45c435570b"),
					common.HexToAddress("0xd03da188bb791ef1dfc7638302b51a6a30ee83fc"),
					common.HexToAddress("0x20ae82dc469de249c6814af6c71f5617621fe92d"),
					common.HexToAddress("0x42e490e0c04f1be8c8cb9b76f630bf97f662169d"),
					common.HexToAddress("0xda133da5981bf90e51c35e9dfe5b9f604d65ce47"),
					common.HexToAddress("0xe60986d35497291dde76c066df27d56f153cbf06"),
					common.HexToAddress("0xe65f06590ee4ed6d814309e5fa014b642b9272bd"),
				},
			},
			// Near-tip V2-era gap-block anchor at 81,856,350 (round 25567421).
			// ~5k blocks behind current Apothem head (~81.86M) — for reproducing
			// "syncs to tip then stalls" issue by anchoring close to the tip and
			// observing peer/header behavior over the final stretch.
			// Source: apothem.xdcrpc.com, XDPoS_getMasternodesByNumber, 2026-05-11.
			{
				Number: 81856350,
				Hash:   common.HexToHash("0xb098e0b7ce34b8220c5e2d6e11c356390f9ef0ca162659ba0b610ccd47b2c337"),
				Root:   common.HexToHash("0x19665538a49cea163a5c70e5a0b5d0c9118d3ea9d31009d06f63813efab1ebe2"),
				Masternodes: []common.Address{
					common.HexToAddress("0x0dc32713f06f5dc52e152f0fbdfe01b490ff1642"),
					common.HexToAddress("0x9c5b33fc32cf8126be3436c3a59db6067b4a577f"),
					common.HexToAddress("0xeae878c4ee2bfe1f9b3583f30fb2e48c85de3969"),
					common.HexToAddress("0x59ebbff1abd4c9307b745b23bdd73e4fbffd64e9"),
					common.HexToAddress("0x05a18817360bab4a2fab4958ab43beea66985828"),
					common.HexToAddress("0x0cfe1a1533737d303ebdddaeccb658003b21c49c"),
					common.HexToAddress("0x40964fcdd7cd130d6938976b06885d1a914480b4"),
					common.HexToAddress("0xfffee9d20a8b70145711433f5d53fc35ad753c42"),
					common.HexToAddress("0x219ad4fc274b5c82bca6600f32ebd6063feb6837"),
					common.HexToAddress("0x5ae9b7c0534cd2885f78e71a6909526abf6d9f94"),
					common.HexToAddress("0xcd13ed39d35ffdcf3c6d982cfd75883517f392fb"),
					common.HexToAddress("0x2d0fa4912bd4c65b392075be9a6bf29c43d8c3ee"),
					common.HexToAddress("0x33fb554db5a905e3faa77c2e88c55cd497a30998"),
					common.HexToAddress("0x81ac7b84abc4ee6e8e021963b113ee8cd2a7732d"),
					common.HexToAddress("0x70e0038d2ec66c5737f2561efcb60c10588cc7af"),
					common.HexToAddress("0xd6f1314f450b0a391b99a8aad8e6f2be2482aa68"),
					common.HexToAddress("0x34f48c6407d9778ba848c0ae01f36d63a58fa791"),
					common.HexToAddress("0xe71bf07a2f502bd7dd8a92a10e13b441ee72b908"),
					common.HexToAddress("0xb5e5acab644dcbdf64103af723be8d62ccec76f4"),
					common.HexToAddress("0x8d9532faf1690dd03b4822b6953052fe597231a6"),
					common.HexToAddress("0x3efa4d1d78391cc0929f7d7e01e9eeaaac8f4862"),
					common.HexToAddress("0xb84bf95eaf3f18f4893a1f3057f38fb0544ac2aa"),
					common.HexToAddress("0xd9285aaba32a2b38541de12126d969bd8da90ded"),
					common.HexToAddress("0x5df57b8cca482d69d5274e38231dcec7da2781d0"),
					common.HexToAddress("0x7d4953d9a2b055467dac460726842f30d6598c0e"),
					common.HexToAddress("0x3176fd7a840920d3b2869a46fed4231e4e4d4103"),
					common.HexToAddress("0x9cc7b8bd05b45baa6ab6a080f6ea9ef8bc873df9"),
					common.HexToAddress("0x9594884daf2acde67e89095702459b06dd60c302"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0x8767e56fe79aff44d1edcfd7dbaed1b1499c7b3d"),
				},
				Penalties: []common.Address{
					common.HexToAddress("0x45afe257f28f70333d91b2978d7d4d0013d04c48"),
					common.HexToAddress("0x1a1b58d133effb6ba1631da7297d8cd58f65fa73"),
					common.HexToAddress("0x93eea33bc34371ad5fe0e5741199bf8e038ad19b"),
					common.HexToAddress("0xebb849cfe83c46c68ba4c2d6f07a16bca991ea79"),
					common.HexToAddress("0xce04ae211d19b8138c7783964aaa1f7addd22275"),
					common.HexToAddress("0x32fb028453207699d7c15bb66377bcf9b29fb0fc"),
					common.HexToAddress("0xfcdcd51159092e923a3011f626f99228923830f1"),
					common.HexToAddress("0x11e75cff00b1e9e9a7c8b3d069e908713ed3e049"),
					common.HexToAddress("0x8ebe9b0ce09105714e6a006d751faf45c435570b"),
					common.HexToAddress("0xd03da188bb791ef1dfc7638302b51a6a30ee83fc"),
					common.HexToAddress("0x20ae82dc469de249c6814af6c71f5617621fe92d"),
					common.HexToAddress("0x42e490e0c04f1be8c8cb9b76f630bf97f662169d"),
					common.HexToAddress("0xda133da5981bf90e51c35e9dfe5b9f604d65ce47"),
					common.HexToAddress("0xe60986d35497291dde76c066df27d56f153cbf06"),
					common.HexToAddress("0xe65f06590ee4ed6d814309e5fa014b642b9272bd"),
				},
			},
			// Fresh near-tip checkpoint for snap-sync validation (#807 Phase 5).
			// Block 82,293,750 is a gap block (% 900 == 450), ~10,500 below
			// Apothem tip at this commit. State at this block is retained on
			// xdc04 archivepath (state.scheme=path keeps ~90k blocks of state
			// history; this block is within that window).
			// Hash + Root sourced from xdc04 archivepath via eth.getBlock.
			// Masternodes reused from the 81,856,350 entry above (Apothem
			// turnover is rare across ~450k blocks of the same era).
			{
				Number: 82293750,
				Hash:   common.HexToHash("0xef1ded39bbf5932640834cf34174bafa349b3613ddd82ecc336be1ebe804f38a"),
				Root:   common.HexToHash("0xff3ceb66756b0ef150d842fb12d64f5ecb41a6e4d319358bde091214bcaf28df"),
				Masternodes: []common.Address{
					common.HexToAddress("0x0dc32713f06f5dc52e152f0fbdfe01b490ff1642"),
					common.HexToAddress("0x9c5b33fc32cf8126be3436c3a59db6067b4a577f"),
					common.HexToAddress("0xeae878c4ee2bfe1f9b3583f30fb2e48c85de3969"),
					common.HexToAddress("0x59ebbff1abd4c9307b745b23bdd73e4fbffd64e9"),
					common.HexToAddress("0x05a18817360bab4a2fab4958ab43beea66985828"),
					common.HexToAddress("0x0cfe1a1533737d303ebdddaeccb658003b21c49c"),
					common.HexToAddress("0x40964fcdd7cd130d6938976b06885d1a914480b4"),
					common.HexToAddress("0xfffee9d20a8b70145711433f5d53fc35ad753c42"),
					common.HexToAddress("0x219ad4fc274b5c82bca6600f32ebd6063feb6837"),
					common.HexToAddress("0x5ae9b7c0534cd2885f78e71a6909526abf6d9f94"),
					common.HexToAddress("0xcd13ed39d35ffdcf3c6d982cfd75883517f392fb"),
					common.HexToAddress("0x2d0fa4912bd4c65b392075be9a6bf29c43d8c3ee"),
					common.HexToAddress("0x33fb554db5a905e3faa77c2e88c55cd497a30998"),
					common.HexToAddress("0x81ac7b84abc4ee6e8e021963b113ee8cd2a7732d"),
					common.HexToAddress("0x70e0038d2ec66c5737f2561efcb60c10588cc7af"),
					common.HexToAddress("0xd6f1314f450b0a391b99a8aad8e6f2be2482aa68"),
					common.HexToAddress("0x34f48c6407d9778ba848c0ae01f36d63a58fa791"),
					common.HexToAddress("0xe71bf07a2f502bd7dd8a92a10e13b441ee72b908"),
					common.HexToAddress("0xb5e5acab644dcbdf64103af723be8d62ccec76f4"),
					common.HexToAddress("0x8d9532faf1690dd03b4822b6953052fe597231a6"),
					common.HexToAddress("0x3efa4d1d78391cc0929f7d7e01e9eeaaac8f4862"),
					common.HexToAddress("0xb84bf95eaf3f18f4893a1f3057f38fb0544ac2aa"),
					common.HexToAddress("0xd9285aaba32a2b38541de12126d969bd8da90ded"),
					common.HexToAddress("0x5df57b8cca482d69d5274e38231dcec7da2781d0"),
					common.HexToAddress("0x7d4953d9a2b055467dac460726842f30d6598c0e"),
					common.HexToAddress("0x3176fd7a840920d3b2869a46fed4231e4e4d4103"),
					common.HexToAddress("0x9cc7b8bd05b45baa6ab6a080f6ea9ef8bc873df9"),
					common.HexToAddress("0x9594884daf2acde67e89095702459b06dd60c302"),
					common.HexToAddress("0x90c87c9ff588e9268a1c7c79a5986886e98c2f04"),
					common.HexToAddress("0x8767e56fe79aff44d1edcfd7dbaed1b1499c7b3d"),
				},
			},
		},
	}

	// XDCDevnetChainConfig contains the chain parameters to run a node on the XDC
	// devnet (chain ID 5551). Mirrors XDCApothemChainConfig's field set with the
	// XDPoSChain dev-upgrade DevnetChainConfig values.
	//
	// Fork schedule (XDPoSChain dev-upgrade):
	//   - All base/pre-1559 forks activate at block 0 (Homestead, EIP150/155/158,
	//     Byzantium, Berlin, London).
	//   - Constantinople / Petersburg / Istanbul are nil (disabled): XDPoS devnet
	//     starts already at Berlin/London semantics from genesis, and the XDC
	//     IsIstanbul/IsPetersburg fallback gates on TIPXDCXCancellationFee (not set
	//     for devnet), so there is no early activation to mirror.
	//   - EIP1559Block = 25000, CancunBlock = 25000 (London fee-market + Cancun
	//     blob/4788 features at block 25000).
	//   - PragueBlock = 50000, plus the XDC v2.8.0 per-network fork blocks
	//     TIPUpgradeRewardBlock / TIPUpgradePenaltyBlock = 50000 (the tiered
	//     reward + penalty upgrade lands together with the v2.8.0 DevnetV2Configs
	//     round-50000 tier). Osaka and TIPEpochHalving are disabled (nil) on devnet.
	//
	// Note: the XDPoSChain dev-upgrade DynamicGasLimitBlock = 50000 and the
	// block-0 base forks (TIPSigning/TIPRandomize/TIPIncreaseMasternodes/Denylist/
	// TIPNoHalvingMNReward/Gas50x/Merge/Shanghai) are XDPoSChain-specific gates that
	// are not modelled as fields on this go-ethereum ChainConfig struct; they are
	// handled via the XDPoS engine's global TIP sentinels / consensus paths and so
	// have no field to set here (same as XDCApothemChainConfig).
	XDCDevnetChainConfig = &ChainConfig{
		ChainID:        big.NewInt(5551),
		HomesteadBlock: big.NewInt(0),
		DAOForkBlock:   nil,
		DAOForkSupport: false,
		EIP150Block:    big.NewInt(0),
		EIP155Block:    big.NewInt(0),
		EIP158Block:    big.NewInt(0),
		ByzantiumBlock: big.NewInt(0),
		// XDPoSChain DevnetChainConfig leaves Constantinople/Petersburg/Istanbul nil,
		// but go-ethereum's CheckConfigForkOrder forbids a gap: with Byzantium and the
		// later Berlin/London enabled at block 0, the intervening forks must also be
		// enabled. We pin them to block 0 (the devnet genesis already runs Berlin/London
		// semantics, of which Istanbul is a strict subset), mirroring how XDCApothemChainConfig
		// pins them to its Berlin block to satisfy the same invariant. This does NOT affect
		// the genesis block hash (only header/alloc do) — verified by TestXDCDevnetGenesisHash.
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    nil,
		BerlinBlock:         big.NewInt(0), // XDPoSChain DevnetChainConfig: Berlin @ 0
		LondonBlock:         big.NewInt(0), // XDPoSChain DevnetChainConfig: London @ 0
		Eip1559Block:        big.NewInt(25000),
		CancunBlock:         big.NewInt(25000),
		PragueBlock:         big.NewInt(50000),
		// XDC v2.8.0 (#963) per-network fork blocks — devnet activates the tiered
		// reward + penalty upgrade at block 50000, in step with DevnetV2Configs[50000].
		TIPUpgradeRewardBlock:  big.NewInt(50000),
		TIPUpgradePenaltyBlock: big.NewInt(50000),
		XDPoS: &XDPoSConfig{
			Period:              2,                                                                 // 2 second block time
			Epoch:               900,                                                               // 900 blocks per epoch
			Reward:              7125,                                                              // Block reward in XDC
			RewardCheckpoint:    900,                                                               // Checkpoint for rewards
			Gap:                 450,                                                               // Gap blocks before epoch end
			FoudationWalletAddr: common.HexToAddress("0x4f288181b1d1aa599c6d7629f1168d46d5f96338"), // Devnet foundation wallet
			V2: &V2{
				SwitchBlock:   big.NewInt(2700), // XDPoSChain dev-upgrade DevnetChainConfig V2 SwitchBlock
				SwitchEpoch:   3,                // Epoch number at V2 switch (2700/900)
				AllConfigs:    DevnetV2Configs,
				CurrentConfig: DevnetV2Configs[0], // Initial config active at round 0
			},
		},
	}

	// XDCDefaultPrivateChainConfig is the fork-block and XDPoS-parameter template
	// inherited by any unregistered XDPoS chain ID (i.e. any chain that is not
	// mainnet/50, Apothem/51, or devnet/551). It is LEGACY-COMPATIBLE: it mirrors
	// the legacy XDPoSChain v2.7.1 base upgrade ORDER — base EVM forks first, then
	// the V1→V2 BFT switch, then EIP-1559, then Cancun — staged at small, reachable
	// blocks (net5151/5152 ladder) so a fresh private net exercises each transition
	// and a modern geth node computes the SAME state root as the legacy oldxdc
	// validators (real parity, no skipV1Validation/bypass):
	//
	//	base EVM (Byzantium/Constantinople/Istanbul/Berlin/London)  block 0
	//	V1 -> V2 switch                                             block 1800  (epoch 2)
	//	EIP-1559                                                    block 2250
	//	Cancun                                                      block 3150
	//
	// The gas/economics PROFILE (gas-charged TIPSigning = 3,000,000, mainnet-base
	// randomize/XDCx/reward gates) lives in defaultXDCConstants
	// (consensus/XDPoS/network_constants.go) and common's package defaults, so it
	// is NOT expressed here. Deployment identity (chainId, staged V2 SwitchBlock,
	// TIPSigningBlock) still comes from the genesis JSON — ChainID is intentionally
	// nil because this var is only read for its fork-block and XDPoS fields, never
	// for its ChainID. Private nets reuse MainnetV2Configs so that the V2 BFT engine
	// receives a complete per-round config map (cap 108 masternodes). Fork values
	// are kept in sync with defaultXDCConstants.
	//
	// IMPORTANT (genesis-authoritative forks, ethOne#62): patchMissingForkBlocks
	// only ever consults this profile up to the genesis's own declared ceiling
	// (core/genesis.go). This profile is the baseline for a genesis that
	// declares NO fork schedule at all; a genesis that declares any fork owns
	// its whole schedule from that fork upward, and none of THIS profile's
	// values above that point are ever injected — including the block-0
	// entries (Constantinople/Petersburg/Istanbul/Berlin/London) below. A
	// genesis that stops at byzantiumBlock stays byzantium-only; it does not
	// silently pick up Istanbul/Berlin/London=0 from here.
	XDCDefaultPrivateChainConfig = &ChainConfig{
		ChainID:             nil, // sentinel: never copied — deployment identity comes from genesis
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      false,
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    nil,
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		Eip1559Block:        big.NewInt(2250),
		CancunBlock:         big.NewInt(3150),
		XDPoS: &XDPoSConfig{
			Period:              2,
			Epoch:               900,
			Reward:              5000,
			RewardCheckpoint:    900,
			Gap:                 450,
			FoudationWalletAddr: common.HexToAddress("0x92a289fe95a85c53b8d0d113cbaef0c1ec98ac65"), // mainnet foundation wallet
			V2: &V2{
				SwitchBlock:   big.NewInt(1800), // V1 -> V2 BFT switch (epoch 2, mirrors mainnet upgrade order at devnet scale)
				SwitchEpoch:   2,                // 1800 / 900
				AllConfigs:    MainnetV2Configs,
				CurrentConfig: MainnetV2Configs[0],
			},
		},
		// No TrustedSyncCheckpoints — private nets have none.
	}

	// AllEthashProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers into the Ethash consensus.
	AllEthashProtocolChanges = &ChainConfig{
		ChainID:                 big.NewInt(1337),
		HomesteadBlock:          big.NewInt(0),
		DAOForkBlock:            nil,
		DAOForkSupport:          false,
		EIP150Block:             big.NewInt(0),
		EIP155Block:             big.NewInt(0),
		EIP158Block:             big.NewInt(0),
		ByzantiumBlock:          big.NewInt(0),
		ConstantinopleBlock:     big.NewInt(0),
		PetersburgBlock:         big.NewInt(0),
		IstanbulBlock:           big.NewInt(0),
		MuirGlacierBlock:        big.NewInt(0),
		BerlinBlock:             big.NewInt(0),
		LondonBlock:             big.NewInt(0),
		ArrowGlacierBlock:       big.NewInt(0),
		GrayGlacierBlock:        big.NewInt(0),
		TerminalTotalDifficulty: big.NewInt(math.MaxInt64),
		MergeNetsplitBlock:      nil,
		ShanghaiTime:            nil,
		CancunTime:              nil,
		PragueTime:              nil,
		OsakaTime:               nil,
		VerkleTime:              nil,
		BogotaTime:              nil,
		Ethash:                  new(EthashConfig),
		Clique:                  nil,
	}

	AllDevChainProtocolChanges = &ChainConfig{
		ChainID:                 big.NewInt(1337),
		HomesteadBlock:          big.NewInt(0),
		EIP150Block:             big.NewInt(0),
		EIP155Block:             big.NewInt(0),
		EIP158Block:             big.NewInt(0),
		ByzantiumBlock:          big.NewInt(0),
		ConstantinopleBlock:     big.NewInt(0),
		PetersburgBlock:         big.NewInt(0),
		IstanbulBlock:           big.NewInt(0),
		MuirGlacierBlock:        big.NewInt(0),
		BerlinBlock:             big.NewInt(0),
		LondonBlock:             big.NewInt(0),
		ArrowGlacierBlock:       big.NewInt(0),
		GrayGlacierBlock:        big.NewInt(0),
		ShanghaiTime:            newUint64(0),
		CancunTime:              newUint64(0),
		TerminalTotalDifficulty: big.NewInt(0),
		PragueTime:              newUint64(0),
		OsakaTime:               newUint64(0),
		BogotaTime:              newUint64(0),
		BlobScheduleConfig: &BlobScheduleConfig{
			Cancun: DefaultCancunBlobConfig,
			Prague: DefaultPragueBlobConfig,
		},
	}

	// AllCliqueProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers into the Clique consensus.
	AllCliqueProtocolChanges = &ChainConfig{
		ChainID:                 big.NewInt(1337),
		HomesteadBlock:          big.NewInt(0),
		DAOForkBlock:            nil,
		DAOForkSupport:          false,
		EIP150Block:             big.NewInt(0),
		EIP155Block:             big.NewInt(0),
		EIP158Block:             big.NewInt(0),
		ByzantiumBlock:          big.NewInt(0),
		ConstantinopleBlock:     big.NewInt(0),
		PetersburgBlock:         big.NewInt(0),
		IstanbulBlock:           big.NewInt(0),
		MuirGlacierBlock:        big.NewInt(0),
		BerlinBlock:             big.NewInt(0),
		LondonBlock:             big.NewInt(0),
		ArrowGlacierBlock:       nil,
		GrayGlacierBlock:        nil,
		MergeNetsplitBlock:      nil,
		ShanghaiTime:            nil,
		CancunTime:              nil,
		PragueTime:              nil,
		OsakaTime:               nil,
		VerkleTime:              nil,
		BogotaTime:              nil,
		TerminalTotalDifficulty: big.NewInt(math.MaxInt64),
		Ethash:                  nil,
		Clique:                  &CliqueConfig{Period: 0, Epoch: 30000},
	}

	// TestChainConfig contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers for testing purposes.
	TestChainConfig = &ChainConfig{
		ChainID:                 big.NewInt(1),
		HomesteadBlock:          big.NewInt(0),
		DAOForkBlock:            nil,
		DAOForkSupport:          false,
		EIP150Block:             big.NewInt(0),
		EIP155Block:             big.NewInt(0),
		EIP158Block:             big.NewInt(0),
		ByzantiumBlock:          big.NewInt(0),
		ConstantinopleBlock:     big.NewInt(0),
		PetersburgBlock:         big.NewInt(0),
		IstanbulBlock:           big.NewInt(0),
		MuirGlacierBlock:        big.NewInt(0),
		BerlinBlock:             big.NewInt(0),
		LondonBlock:             big.NewInt(0),
		ArrowGlacierBlock:       big.NewInt(0),
		GrayGlacierBlock:        big.NewInt(0),
		MergeNetsplitBlock:      nil,
		ShanghaiTime:            nil,
		CancunTime:              nil,
		PragueTime:              nil,
		OsakaTime:               nil,
		VerkleTime:              nil,
		BogotaTime:              nil,
		TerminalTotalDifficulty: big.NewInt(math.MaxInt64),
		Ethash:                  new(EthashConfig),
		Clique:                  nil,
	}

	// MergedTestChainConfig contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers for testing purposes.
	MergedTestChainConfig = &ChainConfig{
		ChainID:                 big.NewInt(1),
		HomesteadBlock:          big.NewInt(0),
		DAOForkBlock:            nil,
		DAOForkSupport:          false,
		EIP150Block:             big.NewInt(0),
		EIP155Block:             big.NewInt(0),
		EIP158Block:             big.NewInt(0),
		ByzantiumBlock:          big.NewInt(0),
		ConstantinopleBlock:     big.NewInt(0),
		PetersburgBlock:         big.NewInt(0),
		IstanbulBlock:           big.NewInt(0),
		MuirGlacierBlock:        big.NewInt(0),
		BerlinBlock:             big.NewInt(0),
		LondonBlock:             big.NewInt(0),
		ArrowGlacierBlock:       big.NewInt(0),
		GrayGlacierBlock:        big.NewInt(0),
		MergeNetsplitBlock:      big.NewInt(0),
		ShanghaiTime:            newUint64(0),
		CancunTime:              newUint64(0),
		PragueTime:              newUint64(0),
		OsakaTime:               newUint64(0),
		VerkleTime:              nil,
		BogotaTime:              nil,
		TerminalTotalDifficulty: big.NewInt(0),
		Ethash:                  new(EthashConfig),
		Clique:                  nil,
		BlobScheduleConfig: &BlobScheduleConfig{
			Cancun: DefaultCancunBlobConfig,
			Prague: DefaultPragueBlobConfig,
		},
	}

	// NonActivatedConfig defines the chain configuration without activating
	// any protocol change (EIPs).
	NonActivatedConfig = &ChainConfig{
		ChainID:                 big.NewInt(1),
		HomesteadBlock:          nil,
		DAOForkBlock:            nil,
		DAOForkSupport:          false,
		EIP150Block:             nil,
		EIP155Block:             nil,
		EIP158Block:             nil,
		ByzantiumBlock:          nil,
		ConstantinopleBlock:     nil,
		PetersburgBlock:         nil,
		IstanbulBlock:           nil,
		MuirGlacierBlock:        nil,
		BerlinBlock:             nil,
		LondonBlock:             nil,
		ArrowGlacierBlock:       nil,
		GrayGlacierBlock:        nil,
		MergeNetsplitBlock:      nil,
		ShanghaiTime:            nil,
		CancunTime:              nil,
		PragueTime:              nil,
		OsakaTime:               nil,
		VerkleTime:              nil,
		BogotaTime:              nil,
		TerminalTotalDifficulty: big.NewInt(math.MaxInt64),
		Ethash:                  new(EthashConfig),
		Clique:                  nil,
	}
	TestRules = TestChainConfig.Rules(new(big.Int), false, 0)
)

var (
	// DefaultCancunBlobConfig is the default blob configuration for the Cancun fork.
	DefaultCancunBlobConfig = &BlobConfig{
		Target:         3,
		Max:            6,
		UpdateFraction: 3338477,
	}
	// DefaultPragueBlobConfig is the default blob configuration for the Prague fork.
	DefaultPragueBlobConfig = &BlobConfig{
		Target:         6,
		Max:            9,
		UpdateFraction: 5007716,
	}
	// DefaultBPO1BlobConfig is the default blob configuration for the BPO1 fork.
	DefaultBPO1BlobConfig = &BlobConfig{
		Target:         10,
		Max:            15,
		UpdateFraction: 8346193,
	}
	// DefaultBPO2BlobConfig is the default blob configuration for the BPO2 fork.
	DefaultBPO2BlobConfig = &BlobConfig{
		Target:         14,
		Max:            21,
		UpdateFraction: 11684671,
	}
	// DefaultBPO3BlobConfig is the default blob configuration for the BPO3 fork.
	DefaultBPO3BlobConfig = &BlobConfig{
		Target:         21,
		Max:            32,
		UpdateFraction: 20609697,
	}
	// DefaultBPO4BlobConfig is the default blob configuration for the BPO4 fork.
	DefaultBPO4BlobConfig = &BlobConfig{
		Target:         14,
		Max:            21,
		UpdateFraction: 13739630,
	}
	// DefaultBlobSchedule is the latest configured blob schedule for Ethereum mainnet.
	DefaultBlobSchedule = &BlobScheduleConfig{
		Cancun: DefaultCancunBlobConfig,
		Prague: DefaultPragueBlobConfig,
	}
)

// NetworkNames are user friendly names to use in the chain spec banner.
var NetworkNames = map[string]string{
	MainnetChainConfig.ChainID.String():    "mainnet",
	SepoliaChainConfig.ChainID.String():    "sepolia",
	HoleskyChainConfig.ChainID.String():    "holesky",
	HoodiChainConfig.ChainID.String():      "hoodi",
	XDCMainnetChainConfig.ChainID.String(): "xdc-mainnet",
	XDCApothemChainConfig.ChainID.String(): "xdc-apothem",
	XDCDevnetChainConfig.ChainID.String():  "xdc-devnet",
}

// ChainConfig is the core config which determines the blockchain settings.
//
// ChainConfig is stored in the database on a per block basis. This means
// that any network, identified by its genesis block, can have its own
// set of configuration options.
type ChainConfig struct {
	ChainID *big.Int `json:"chainId"` // chainId identifies the current chain and is used for replay protection

	HomesteadBlock *big.Int `json:"homesteadBlock,omitempty"` // Homestead switch block (nil = no fork, 0 = already homestead)

	DAOForkBlock   *big.Int `json:"daoForkBlock,omitempty"`   // TheDAO hard-fork switch block (nil = no fork)
	DAOForkSupport bool     `json:"daoForkSupport,omitempty"` // Whether the nodes supports or opposes the DAO hard-fork

	// EIP150 implements the Gas price changes (https://github.com/ethereum/EIPs/issues/150)
	EIP150Block *big.Int `json:"eip150Block,omitempty"` // EIP150 HF block (nil = no fork)
	EIP155Block *big.Int `json:"eip155Block,omitempty"` // EIP155 HF block
	EIP158Block *big.Int `json:"eip158Block,omitempty"` // EIP158 HF block

	ByzantiumBlock      *big.Int `json:"byzantiumBlock,omitempty"`      // Byzantium switch block (nil = no fork, 0 = already on byzantium)
	ConstantinopleBlock *big.Int `json:"constantinopleBlock,omitempty"` // Constantinople switch block (nil = no fork, 0 = already activated)
	PetersburgBlock     *big.Int `json:"petersburgBlock,omitempty"`     // Petersburg switch block (nil = same as Constantinople)
	IstanbulBlock       *big.Int `json:"istanbulBlock,omitempty"`       // Istanbul switch block (nil = no fork, 0 = already on istanbul)
	MuirGlacierBlock    *big.Int `json:"muirGlacierBlock,omitempty"`    // Eip-2384 (bomb delay) switch block (nil = no fork, 0 = already activated)
	BerlinBlock         *big.Int `json:"berlinBlock,omitempty"`         // Berlin switch block (nil = no fork, 0 = already on berlin)
	LondonBlock         *big.Int `json:"londonBlock,omitempty"`         // London switch block (nil = no fork, 0 = already on london)
	Eip1559Block        *big.Int `json:"eip1559Block,omitempty"`        // EIP-1559 fee market switch block (nil = same as LondonBlock); XDC mainnet: 98,800,200
	CancunBlock         *big.Int `json:"cancunBlock,omitempty"`         // Cancun features switch block (nil = no fork, 0 = already on cancun); XDC mainnet: 98,802,000
	PragueBlock         *big.Int `json:"pragueBlock,omitempty"`         // Prague features switch block (nil = no fork, block-number based for XDC); XDPoSChain v2.8.0 apothem: 83,600,000 (held disabled until #963 parity)
	// XDC v2.8.0 (#963) per-network fork-block fields. nil = disabled. These
	// supersede the disabled global sentinels (common.TIPUpgradeReward etc.).
	TIPUpgradeRewardBlock  *big.Int `json:"tipUpgradeRewardBlock,omitempty"`  // Tiered (masternode/protector/observer) reward fork; XDPoSChain v2.8.0 apothem: 83,600,000 (held disabled)
	TIPUpgradePenaltyBlock *big.Int `json:"tipUpgradePenaltyBlock,omitempty"` // Penalty-upgrade fork; XDPoSChain v2.8.0 apothem: 83,600,000 (held disabled)
	// TIPSigningBlock is an explicit per-genesis override for the BlockSigners
	// (0x89) contract-wipe fork block. Historically this value came ONLY from
	// the hardcoded per-chainID table in common.CopyXDCConstants /
	// XDPoS.SetNetworkConstants, which silently ignored a genesis file's own
	// "tipSigningBlock" JSON field — ChainConfig had no matching struct field,
	// so json.Unmarshal dropped it. On devnet-5151 (genesis tipSigningBlock=4)
	// this caused a real state-root divergence: our node's common.TIPSigning
	// defaulted to 0 (block 0 is genesis and is never routed through
	// ProcessBlock, so the wipe never fires), while the canonical network
	// applies genesis's tipSigningBlock=4 and the state root changes at block
	// 4 (208ec15a...->db699d2c...). When set, this field takes priority over
	// the hardcoded table (see eth/backend.go); nil (the default for every
	// existing genesis) preserves the hardcoded per-chainID value exactly as
	// before. Refs devnet-5151 A.94 sticky-checkpointSyncNoState investigation.
	TIPSigningBlock    *big.Int `json:"tipSigningBlock,omitempty"`
	ArrowGlacierBlock  *big.Int `json:"arrowGlacierBlock,omitempty"`  // Eip-4345 (bomb delay) switch block (nil = no fork, 0 = already activated)
	GrayGlacierBlock   *big.Int `json:"grayGlacierBlock,omitempty"`   // Eip-5133 (bomb delay) switch block (nil = no fork, 0 = already activated)
	MergeNetsplitBlock *big.Int `json:"mergeNetsplitBlock,omitempty"` // Virtual fork after The Merge to use as a network splitter

	// Fork scheduling was switched from blocks to timestamps here

	ShanghaiTime  *uint64 `json:"shanghaiTime,omitempty"`  // Shanghai switch time (nil = no fork, 0 = already on shanghai)
	CancunTime    *uint64 `json:"cancunTime,omitempty"`    // Cancun switch time (nil = no fork, 0 = already on cancun)
	PragueTime    *uint64 `json:"pragueTime,omitempty"`    // Prague switch time (nil = no fork, 0 = already on prague)
	OsakaTime     *uint64 `json:"osakaTime,omitempty"`     // Osaka switch time (nil = no fork, 0 = already on osaka)
	BPO1Time      *uint64 `json:"bpo1Time,omitempty"`      // BPO1 switch time (nil = no fork, 0 = already on bpo1)
	BPO2Time      *uint64 `json:"bpo2Time,omitempty"`      // BPO2 switch time (nil = no fork, 0 = already on bpo2)
	BPO3Time      *uint64 `json:"bpo3Time,omitempty"`      // BPO3 switch time (nil = no fork, 0 = already on bpo3)
	BPO4Time      *uint64 `json:"bpo4Time,omitempty"`      // BPO4 switch time (nil = no fork, 0 = already on bpo4)
	BPO5Time      *uint64 `json:"bpo5Time,omitempty"`      // BPO5 switch time (nil = no fork, 0 = already on bpo5)
	AmsterdamTime *uint64 `json:"amsterdamTime,omitempty"` // Amsterdam switch time (nil = no fork, 0 = already on amsterdam)
	VerkleTime    *uint64 `json:"verkleTime,omitempty"`    // Verkle switch time (nil = no fork, 0 = already on verkle)
	BogotaTime    *uint64 `json:"bogotaTime,omitempty"`    // Bogota switch time (nil = no fork, 0 = already on bogota)
	FrameTxTime   *uint64 `json:"frameTxTime,omitempty"`   // FrameTx switch time (nil = no fork, 0 = already on frame txs); EIP-8141
	// Note: UBTTime is declared further below (kept as an always-false XDC
	// stub alongside IsUBT/IsUBTGenesis) — not duplicated here.

	// TerminalTotalDifficulty is the amount of total difficulty reached by
	// the network that triggers the consensus upgrade.
	TerminalTotalDifficulty *big.Int `json:"terminalTotalDifficulty,omitempty"`

	DepositContractAddress common.Address `json:"depositContractAddress,omitempty"`

	// EnableVerkleAtGenesis is a flag that specifies whether the network uses
	// the Verkle tree starting from the genesis block. If set to true, the
	// genesis state will be committed using the Verkle tree, eliminating the
	// need for any Verkle transition later.
	//
	// This is a temporary flag only for verkle devnet testing, where verkle is
	// activated at genesis, and the configured activation date has already passed.
	//
	// In production networks (mainnet and public testnets), verkle activation
	// always occurs after the genesis block, making this flag irrelevant in
	// those cases.
	EnableVerkleAtGenesis bool `json:"enableVerkleAtGenesis,omitempty"`

	// Various consensus engines
	Ethash             *EthashConfig       `json:"ethash,omitempty"`
	Clique             *CliqueConfig       `json:"clique,omitempty"`
	XDPoS              *XDPoSConfig        `json:"xdpos,omitempty"`
	BlobScheduleConfig *BlobScheduleConfig `json:"blobSchedule,omitempty"`

	// XDC-specific features (nil for non-XDC chains)
	// These align with Geth 1.17's ChainConfig pattern for feature flags
	XDCFeatures *XDCFeatures `json:"xdcFeatures,omitempty"` // XDC-specific consensus features (V2 switch, etc.)

	// TrustedSyncCheckpoints is a list of hardcoded checkpoints for near-instant sync-from-block.
	// When --syncfromblock matches any checkpoint, the node skips downloading all
	// headers before the checkpoint and anchors directly to the trusted hash/state root.
	//
	// Migration note: two paths still consult these transitionally until the dynamic
	// pivot lands — fast-sync auto-pin (A.96, eth/backend.go AutoPinPivotFromCheckpoints)
	// and experimental snap-sync pivot selection (eth/sync_xdc.go snapSelectOnce). The
	// replacement verifies the pivot's QuorumCert against the masternode set read from the
	// epoch-switch header's validators, so no baked-in trust anchor is required. Do NOT add
	// new entries here; this field and the checkpoint paths are slated for removal once
	// #894 lands and the dynamic pivot is validated on mainnet.
	//
	// Deprecated: superseded by dynamic header-derived QC-verified pivot selection (A.97 / #894).
	TrustedSyncCheckpoints []*TrustedSyncCheckpoint `json:"trustedSyncCheckpoints,omitempty"`

	// UBT (Unbounded Trie / Verkle) fork — v1.17.3 upstream addition.
	// XDC chains never activate UBT; placeholders for upstream-package compat.
	UBTTime            *uint64 `json:"ubtTime,omitempty"`
	EnableUBTAtGenesis bool    `json:"enableUBTAtGenesis,omitempty"`
}

// EthashConfig is the consensus engine configs for proof-of-work based sealing.
type EthashConfig struct{}

// String implements the stringer interface, returning the consensus engine details.
func (c EthashConfig) String() string {
	return "ethash"
}

// CliqueConfig is the consensus engine configs for proof-of-authority based sealing.
type CliqueConfig struct {
	Period uint64 `json:"period"` // Number of seconds between blocks to enforce
	Epoch  uint64 `json:"epoch"`  // Epoch length to reset votes and checkpoint
}

// String implements the stringer interface, returning the consensus engine details.
func (c CliqueConfig) String() string {
	return fmt.Sprintf("clique(period: %d, epoch: %d)", c.Period, c.Epoch)
}

// TrustedSyncCheckpoint is a hardcoded checkpoint for near-instant sync-from-block.
// When --syncfromblock matches this checkpoint, the node skips downloading all
// headers before the checkpoint and anchors directly to the trusted hash/state root.
//
// Masternodes/Penalties are optional and only used for V2-era Apothem checkpoints
// where header.Validators is empty. When present, InsertHeadersBeforeCutoff seeds
// the V2 snapshot from this list instead of reading contract state, which the node
// does not have during checkpoint sync.
//
// Deprecated: superseded by dynamic header-derived QC-verified pivot selection (A.97 / #894). See ChainConfig.TrustedSyncCheckpoints.
type TrustedSyncCheckpoint struct {
	Number      uint64           `json:"number"`                // Block number of the checkpoint
	Hash        common.Hash      `json:"hash"`                  // Canonical hash at the checkpoint
	Root        common.Hash      `json:"root"`                  // State root at the checkpoint (for snap-sync pivot)
	Masternodes []common.Address `json:"masternodes,omitempty"` // Active V2 masternode set at the checkpoint (Path B for V2-era anchors)
	Penalties   []common.Address `json:"penalties,omitempty"`   // Penalty set at the checkpoint (informational; V2 snapshot stores penalties separately)
}

// XDPoSConfig is the consensus engine configs for XDC Network's delegated-proof-of-stake based sealing.
type XDPoSConfig struct {
	Period              uint64         `json:"period"`                        // Number of seconds between blocks to enforce
	Epoch               uint64         `json:"epoch"`                         // Epoch length to reset votes and checkpoint
	Reward              uint64         `json:"reward"`                        // Block reward - unit Ether
	RewardCheckpoint    uint64         `json:"rewardCheckpoint,omitempty"`    // Checkpoint block for calculate rewards
	Gap                 uint64         `json:"gap"`                           // Gap time preparing for the next epoch
	FoudationWalletAddr common.Address `json:"foudationWalletAddr,omitempty"` // Foundation Address Wallet
	V2                  *V2            `json:"v2,omitempty"`                  // V2 upgrade config
}

// UnmarshalJSON accepts BOTH the canonical correctly-spelled genesis key
// "foundationWalletAddr" and the historical XDC-typo key "foudationWalletAddr"
// for the foundation wallet address. The Go struct field/tag carries the typo
// ("foudation") for historical compatibility, but real genesis files in the
// field — including the canonical mainnet/apothem/devnet XinFin-Node genesis
// and the net5050 stress-testbed genesis — use the correctly-spelled
// "foundationWalletAddr". When a custom-networkid chain loads its config from a
// genesis JSON (not the built-in params defaults), the typo'd tag silently
// dropped the address, leaving FoudationWalletAddr == zero. That made
// HookReward log "Foundation wallet address is empty" and credit no reward at
// the first reward checkpoint (block 1800 for rewardCheckpoint=900), producing
// a post-state == pre-state stateRoot that diverged from the legacy
// XDPoSChain producers (which DO read the address) — wedging modern geth at the
// epoch checkpoint. The foundation address is a runtime consensus parameter and
// is NOT part of the genesis block hash, so accepting the correct spelling
// changes no block hashes; it only brings the reward path into parity with
// legacy. The typo'd key still wins if both are present (backward compatible).
// Refs net5050 block-1800 reward divergence; same class as #938/#985.
func (c *XDPoSConfig) UnmarshalJSON(data []byte) error {
	type xdposConfigAlias XDPoSConfig
	aux := struct {
		*xdposConfigAlias
		FoundationWalletAddr *common.Address `json:"foundationWalletAddr,omitempty"`
	}{xdposConfigAlias: (*xdposConfigAlias)(c)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	// If the typo'd key was absent (field still zero) but the correctly-spelled
	// key was present, adopt it.
	if c.FoudationWalletAddr == (common.Address{}) && aux.FoundationWalletAddr != nil {
		c.FoudationWalletAddr = *aux.FoundationWalletAddr
	}
	return nil
}

// V2 holds XDPoS 2.0 configuration
type V2 struct {
	SwitchBlock   *big.Int             `json:"switchBlock,omitempty"` // Block number to switch to V2
	CurrentConfig *V2Config            `json:"config"`                // Current active V2 configuration (fix #96: match XDPoSChain v2.6.8 JSON tag "config")
	AllConfigs    map[uint64]*V2Config `json:"allConfigs,omitempty"`  // Per-round config map (key = SwitchRound)
	SwitchEpoch   uint64               `json:"switchEpoch,omitempty"` // Epoch number at V2 switch block

	mu          sync.RWMutex `json:"-"` // Protects CurrentConfig from concurrent read/write (#74)
	configIndex []uint64     `json:"-"` // Descending-sorted round keys for O(n) lookup (#117)
}

// BuildConfigIndex builds the descending-sorted config index from AllConfigs.
// Must be called once after AllConfigs is populated (e.g. in engine New()).
// Matches v2.6.8 params/config.go V2.BuildConfigIndex. (#117)
func (v *V2) BuildConfigIndex() {
	var list []uint64
	for i := range v.AllConfigs {
		list = append(list, i)
	}
	// Sort descending — O(n²) is fine for the small config list
	for i := 0; i < len(list)-1; i++ {
		for j := i + 1; j < len(list); j++ {
			if list[i] < list[j] {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
	log.Info("[BuildConfigIndex] config list", "list", list)
	v.configIndex = list
}

// Config returns the V2Config that is active at the given round.
// Uses the pre-built configIndex for efficient lookup.
// Matches v2.6.8 params/config.go V2.Config(round). (#117)
func (v *V2) Config(round uint64) *V2Config {
	if v == nil {
		return nil
	}
	if len(v.configIndex) == 0 {
		return v.CurrentConfig
	}
	for _, idx := range v.configIndex {
		if idx <= round {
			return v.AllConfigs[idx]
		}
	}
	return v.CurrentConfig
}

// UpdateConfig updates CurrentConfig to the config active at the given round.
// Thread-safe. Matches v2.6.8 params/config.go V2.UpdateConfig. (#117)
func (v *V2) UpdateConfig(round uint64) {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	if len(v.configIndex) == 0 {
		return
	}
	var index uint64
	for _, idx := range v.configIndex {
		if idx <= round {
			index = idx
			break
		}
	}
	log.Info("[updateV2Config] Update config", "index", index, "round", round, "SwitchRound", v.AllConfigs[index].SwitchRound)
	v.CurrentConfig = v.AllConfigs[index]
}

// V2Config holds V2-specific configuration
// Matches XDPoSChain v2.6.8 params/config.go V2Config struct
type V2Config struct {
	SwitchRound          uint64  `json:"switchRound,omitempty"`          // Round to switch to new config
	MinePeriod           int     `json:"minePeriod,omitempty"`           // Mining period in seconds
	TimeoutSyncThreshold int     `json:"timeoutSyncThreshold,omitempty"` // Timeout sync threshold
	TimeoutPeriod        int     `json:"timeoutPeriod,omitempty"`        // Timeout period in seconds
	CertThreshold        float64 `json:"certificateThreshold,omitempty"` // Certificate threshold (2/3 = 0.6667)
	MaxMasternodes       int     `json:"maxMasternodes,omitempty"`       // Max masternodes in V2

	// Node governance tiers (v2.6.8 additions)
	MaxProtectorNodes int `json:"maxProtectorNodes,omitempty"` // Max protector nodes
	MaxObserverNodes  int `json:"maxObserverNodes,omitempty"`  // Max observer nodes

	// Tiered rewards (v2.6.8 — replaces flat reward)
	MasternodeReward float64 `json:"masternodeReward,omitempty"` // Block reward per masternode (XDC)
	ProtectorReward  float64 `json:"protectorReward,omitempty"`  // Block reward per protector (XDC)
	ObserverReward   float64 `json:"observerReward,omitempty"`   // Block reward per observer (XDC)

	// Penalty parameters
	MinimumMinerBlockPerEpoch int `json:"minimumMinerBlockPerEpoch,omitempty"` // Min blocks per epoch to avoid penalty
	LimitPenaltyEpoch         int `json:"limitPenaltyEpoch,omitempty"`         // Max consecutive penalty epochs
	MinimumSigningTx          int `json:"minimumSigningTx,omitempty"`          // Min signing txs to exit penalty

	// Exponential timeout configuration
	ExpTimeoutConfig ExpTimeoutConfig `json:"expTimeoutConfig,omitempty"`
}

// ExpTimeoutConfig defines exponential timeout backoff parameters
// Timeout = Base^min(exponent, MaxExponent) * TimeoutPeriod
type ExpTimeoutConfig struct {
	Base        float64 `json:"base,omitempty"`        // Base for exponential backoff (default: 2)
	MaxExponent uint8   `json:"maxExponent,omitempty"` // Maximum exponent cap (default: 8)
}

// MainnetV2Configs holds per-round V2 configuration changes for mainnet
// Matches XinFinOrg/XDPoSChain v2.6.8 params/config.go MainnetV2Configs exactly.
// Key = switchRound at which config activates.
var MainnetV2Configs = map[uint64]*V2Config{
	0: {
		MaxMasternodes:       108,
		CertThreshold:        0.667,
		TimeoutSyncThreshold: 3,
		TimeoutPeriod:        30,
		MinePeriod:           2,
		ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
	},
	2000: {
		MaxMasternodes:       108,
		CertThreshold:        0.667,
		TimeoutSyncThreshold: 2,
		TimeoutPeriod:        600,
		MinePeriod:           2,
		ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
	},
	8000: {
		MaxMasternodes:       108,
		CertThreshold:        0.667,
		TimeoutSyncThreshold: 2,
		TimeoutPeriod:        60,
		MinePeriod:           2,
		ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
	},
	220000: {
		MaxMasternodes:       108,
		CertThreshold:        0.667,
		TimeoutSyncThreshold: 2,
		TimeoutPeriod:        30,
		MinePeriod:           2,
		ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
	},
	460000: {
		MaxMasternodes:       108,
		CertThreshold:        0.667,
		TimeoutSyncThreshold: 2,
		TimeoutPeriod:        20,
		MinePeriod:           2,
		ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
	},
	3200000: {
		MaxMasternodes:       108,
		CertThreshold:        0.667,
		TimeoutSyncThreshold: 3,
		TimeoutPeriod:        10,
		MinePeriod:           2,
		ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
	},
	// fix #105: round 17579700 — TimeoutPeriod reverts to 60s (matches XDPoSChain v2.6.8 MainnetV2Configs)
	17579700: {
		MaxMasternodes:       108,
		CertThreshold:        0.667,
		TimeoutSyncThreshold: 3,
		TimeoutPeriod:        60,
		MinePeriod:           2,
		ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
	},
}

// ApothemV2Configs holds per-round V2 configuration changes for Apothem testnet
// Matches XinFinOrg/XDPoSChain v2.6.8 params/config.go TestnetV2Configs.
var ApothemV2Configs = map[uint64]*V2Config{
	0: {
		MaxMasternodes:       15,
		CertThreshold:        0.45,
		TimeoutSyncThreshold: 3,
		TimeoutPeriod:        60,
		MinePeriod:           2,
		ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
	},
	900000: {
		MaxMasternodes:       108,
		CertThreshold:        0.667,
		TimeoutSyncThreshold: 3,
		TimeoutPeriod:        60,
		MinePeriod:           2,
		ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
	},
	15000000: {
		MaxMasternodes:       108,
		CertThreshold:        0.667,
		TimeoutSyncThreshold: 3,
		TimeoutPeriod:        10,
		MinePeriod:           2,
		ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
	},
	// XDPoSChain v2.8.0 (PR #2383) masternode/protector/observer tier, active from
	// round 27,360,000. ADDED now that activation is verified on canonical apothem
	// (resolves the #963 Stage D R1 precondition; fixes #998): canonical is at round
	// 27,460,297 (> 27,360,000) and the canonical header at block 83,577,112 carries
	// exactly 25 validators (tip is also past the block-83,600,000 TIP fork). Config(round)
	// must therefore cap the active set at 25 to match canonical; without this entry our
	// nodes compute 108 and wedge with "validators not legit" at the epoch boundary.
	27360000: {
		SwitchRound:               27360000,
		MaxMasternodes:            25,
		MaxProtectorNodes:         3,
		MaxObserverNodes:          2,
		CertThreshold:             0.667,
		TimeoutSyncThreshold:      3,
		TimeoutPeriod:             10,
		MinePeriod:                2,
		MasternodeReward:          63.42,
		ProtectorReward:           50.27,
		ObserverReward:            25.13,
		MinimumMinerBlockPerEpoch: 5,
		LimitPenaltyEpoch:         5,
		MinimumSigningTx:          30,
		ExpTimeoutConfig:          ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
	},
}

// DevnetV2Configs holds per-round V2 configuration changes for the XDC devnet
// (chain ID 5551). Mirrors XDPoSChain dev-upgrade DevnetV2Configs:
//   - round 0: V2 bootstrap config (108 masternodes, no tiers/rewards yet)
//   - round 50000: v2.8.0 tiered config (masternode/protector/observer rewards)
//
// NOTE: the XDPoSChain source spells the observer-cap field "MaxObverserNodes"
// (a typo). Our V2Config Go field is the corrected MaxObserverNodes.
var DevnetV2Configs = map[uint64]*V2Config{
	0: {
		MaxMasternodes:       108,
		CertThreshold:        0.667,
		TimeoutSyncThreshold: 3,
		TimeoutPeriod:        10,
		MinePeriod:           2,
		ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
	},
	50000: {
		SwitchRound:               50000,
		MaxMasternodes:            108,
		MaxProtectorNodes:         324,
		MaxObserverNodes:          2000,
		CertThreshold:             0.667,
		TimeoutSyncThreshold:      3,
		TimeoutPeriod:             10,
		MinePeriod:                2,
		ExpTimeoutConfig:          ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
		MasternodeReward:          63.42,
		ProtectorReward:           50.27,
		ObserverReward:            25.13,
		MinimumMinerBlockPerEpoch: 5,
		LimitPenaltyEpoch:         5,
		MinimumSigningTx:          30,
	},
}

// String implements the stringer interface, returning the consensus engine details.
func (c XDPoSConfig) String() string {
	return fmt.Sprintf("xdpos(period: %d, epoch: %d, gap: %d, reward: %d)", c.Period, c.Epoch, c.Gap, c.Reward)
}

// String implements the fmt.Stringer interface, returning a string representation
// of ChainConfig.
func (c *ChainConfig) String() string {
	result := fmt.Sprintf("ChainConfig{ChainID: %v", c.ChainID)

	// Add block-based forks
	if c.HomesteadBlock != nil {
		result += fmt.Sprintf(", HomesteadBlock: %v", c.HomesteadBlock)
	}
	if c.DAOForkBlock != nil {
		result += fmt.Sprintf(", DAOForkBlock: %v", c.DAOForkBlock)
	}
	if c.EIP150Block != nil {
		result += fmt.Sprintf(", EIP150Block: %v", c.EIP150Block)
	}
	if c.EIP155Block != nil {
		result += fmt.Sprintf(", EIP155Block: %v", c.EIP155Block)
	}
	if c.EIP158Block != nil {
		result += fmt.Sprintf(", EIP158Block: %v", c.EIP158Block)
	}
	if c.ByzantiumBlock != nil {
		result += fmt.Sprintf(", ByzantiumBlock: %v", c.ByzantiumBlock)
	}
	if c.ConstantinopleBlock != nil {
		result += fmt.Sprintf(", ConstantinopleBlock: %v", c.ConstantinopleBlock)
	}
	if c.PetersburgBlock != nil {
		result += fmt.Sprintf(", PetersburgBlock: %v", c.PetersburgBlock)
	}
	if c.IstanbulBlock != nil {
		result += fmt.Sprintf(", IstanbulBlock: %v", c.IstanbulBlock)
	}
	if c.MuirGlacierBlock != nil {
		result += fmt.Sprintf(", MuirGlacierBlock: %v", c.MuirGlacierBlock)
	}
	if c.BerlinBlock != nil {
		result += fmt.Sprintf(", BerlinBlock: %v", c.BerlinBlock)
	}
	if c.LondonBlock != nil {
		result += fmt.Sprintf(", LondonBlock: %v", c.LondonBlock)
	}
	if c.ArrowGlacierBlock != nil {
		result += fmt.Sprintf(", ArrowGlacierBlock: %v", c.ArrowGlacierBlock)
	}
	if c.GrayGlacierBlock != nil {
		result += fmt.Sprintf(", GrayGlacierBlock: %v", c.GrayGlacierBlock)
	}
	if c.MergeNetsplitBlock != nil {
		result += fmt.Sprintf(", MergeNetsplitBlock: %v", c.MergeNetsplitBlock)
	}

	// Add timestamp-based forks
	if c.ShanghaiTime != nil {
		result += fmt.Sprintf(", ShanghaiTime: %v", *c.ShanghaiTime)
	}
	if c.CancunTime != nil {
		result += fmt.Sprintf(", CancunTime: %v", *c.CancunTime)
	}
	if c.PragueTime != nil {
		result += fmt.Sprintf(", PragueTime: %v", *c.PragueTime)
	}
	if c.OsakaTime != nil {
		result += fmt.Sprintf(", OsakaTime: %v", *c.OsakaTime)
	}
	if c.BPO1Time != nil {
		result += fmt.Sprintf(", BPO1Time: %v", *c.BPO1Time)
	}
	if c.BPO2Time != nil {
		result += fmt.Sprintf(", BPO2Time: %v", *c.BPO2Time)
	}
	if c.BPO3Time != nil {
		result += fmt.Sprintf(", BPO3Time: %v", *c.BPO3Time)
	}
	if c.BPO4Time != nil {
		result += fmt.Sprintf(", BPO4Time: %v", *c.BPO4Time)
	}
	if c.BPO5Time != nil {
		result += fmt.Sprintf(", BPO5Time: %v", *c.BPO5Time)
	}
	if c.AmsterdamTime != nil {
		result += fmt.Sprintf(", AmsterdamTime: %v", *c.AmsterdamTime)
	}
	if c.VerkleTime != nil {
		result += fmt.Sprintf(", VerkleTime: %v", *c.VerkleTime)
	}
	if c.BogotaTime != nil {
		result += fmt.Sprintf(", BogotaTime: %v", *c.BogotaTime)
	}
	result += "}"
	return result
}

// Description returns a human-readable description of ChainConfig.
func (c *ChainConfig) Description() string {
	var banner string

	// Create some basic network config output
	network := NetworkNames[c.ChainID.String()]
	if network == "" {
		network = "unknown"
	}
	banner += fmt.Sprintf("Chain ID:  %v (%s)\n", c.ChainID, network)
	switch {
	case c.Ethash != nil:
		banner += "Consensus: Beacon (proof-of-stake), merged from Ethash (proof-of-work)\n"
	case c.Clique != nil:
		banner += "Consensus: Beacon (proof-of-stake), merged from Clique (proof-of-authority)\n"
	default:
		banner += "Consensus: unknown\n"
	}
	banner += "\n"

	// Create a list of forks with a short description of them. Forks that only
	// makes sense for mainnet should be optional at printing to avoid bloating
	// the output for testnets and private networks.
	banner += "Pre-Merge hard forks (block based):\n"
	banner += fmt.Sprintf(" - Homestead:                   #%-8v\n", c.HomesteadBlock)
	if c.DAOForkBlock != nil {
		banner += fmt.Sprintf(" - DAO Fork:                    #%-8v\n", c.DAOForkBlock)
	}
	banner += fmt.Sprintf(" - Tangerine Whistle (EIP 150): #%-8v\n", c.EIP150Block)
	banner += fmt.Sprintf(" - Spurious Dragon/1 (EIP 155): #%-8v\n", c.EIP155Block)
	banner += fmt.Sprintf(" - Spurious Dragon/2 (EIP 158): #%-8v\n", c.EIP158Block)
	banner += fmt.Sprintf(" - Byzantium:                   #%-8v\n", c.ByzantiumBlock)
	banner += fmt.Sprintf(" - Constantinople:              #%-8v\n", c.ConstantinopleBlock)
	banner += fmt.Sprintf(" - Petersburg:                  #%-8v\n", c.PetersburgBlock)
	banner += fmt.Sprintf(" - Istanbul:                    #%-8v\n", c.IstanbulBlock)
	if c.MuirGlacierBlock != nil {
		banner += fmt.Sprintf(" - Muir Glacier:                #%-8v\n", c.MuirGlacierBlock)
	}
	banner += fmt.Sprintf(" - Berlin:                      #%-8v\n", c.BerlinBlock)
	banner += fmt.Sprintf(" - London:                      #%-8v\n", c.LondonBlock)
	if c.ArrowGlacierBlock != nil {
		banner += fmt.Sprintf(" - Arrow Glacier:               #%-8v\n", c.ArrowGlacierBlock)
	}
	if c.GrayGlacierBlock != nil {
		banner += fmt.Sprintf(" - Gray Glacier:                #%-8v\n", c.GrayGlacierBlock)
	}
	banner += "\n"

	// Add a special section for the merge as it's non-obvious
	banner += "Merge configured:\n"
	banner += fmt.Sprintf(" - Total terminal difficulty:  %v\n", c.TerminalTotalDifficulty)
	if c.MergeNetsplitBlock != nil {
		banner += fmt.Sprintf(" - Merge netsplit block:       #%-8v\n", c.MergeNetsplitBlock)
	}
	banner += "\n"

	// Create a list of forks post-merge
	banner += "Post-Merge hard forks (timestamp based):\n"
	if c.ShanghaiTime != nil {
		banner += fmt.Sprintf(" - Shanghai:                    @%-10v\n", *c.ShanghaiTime)
	}
	if c.CancunTime != nil {
		banner += fmt.Sprintf(" - Cancun:                      @%-10v blob: (%s)\n", *c.CancunTime, c.BlobScheduleConfig.Cancun)
	}
	if c.PragueTime != nil {
		banner += fmt.Sprintf(" - Prague:                      @%-10v blob: (%s)\n", *c.PragueTime, c.BlobScheduleConfig.Prague)
	}
	if c.OsakaTime != nil {
		banner += fmt.Sprintf(" - Osaka:                       @%-10v\n", *c.OsakaTime)
	}
	if c.BPO1Time != nil {
		banner += fmt.Sprintf(" - BPO1:                        @%-10v blob: (%s)\n", *c.BPO1Time, c.BlobScheduleConfig.BPO1)
	}
	if c.BPO2Time != nil {
		banner += fmt.Sprintf(" - BPO2:                        @%-10v blob: (%s)\n", *c.BPO2Time, c.BlobScheduleConfig.BPO2)
	}
	if c.BPO3Time != nil {
		banner += fmt.Sprintf(" - BPO3:                        @%-10v blob: (%s)\n", *c.BPO3Time, c.BlobScheduleConfig.BPO3)
	}
	if c.BPO4Time != nil {
		banner += fmt.Sprintf(" - BPO4:                        @%-10v blob: (%s)\n", *c.BPO4Time, c.BlobScheduleConfig.BPO4)
	}
	if c.BPO5Time != nil {
		banner += fmt.Sprintf(" - BPO5:                        @%-10v blob: (%s)\n", *c.BPO5Time, c.BlobScheduleConfig.BPO5)
	}
	if c.AmsterdamTime != nil {
		banner += fmt.Sprintf(" - Amsterdam:                   @%-10v\n", *c.AmsterdamTime)
	}
	if c.BogotaTime != nil {
		banner += fmt.Sprintf(" - Bogota:                      @%-10v\n", *c.BogotaTime)
	}
	if c.VerkleTime != nil {
		banner += fmt.Sprintf(" - Verkle:                      @%-10v\n", *c.VerkleTime)
	}
	banner += fmt.Sprintf("\nAll fork specifications can be found at https://ethereum.github.io/execution-specs/src/ethereum/forks/\n")
	return banner
}

// BlobConfig specifies the target and max blobs per block for the associated fork.
type BlobConfig struct {
	Target         int    `json:"target"`
	Max            int    `json:"max"`
	UpdateFraction uint64 `json:"baseFeeUpdateFraction"`
}

// String implement fmt.Stringer, returning string format blob config.
func (bc *BlobConfig) String() string {
	if bc == nil {
		return "nil"
	}
	return fmt.Sprintf("target: %d, max: %d, fraction: %d", bc.Target, bc.Max, bc.UpdateFraction)
}

// BlobScheduleConfig determines target and max number of blobs allow per fork.
//
// From Prague onward, the blob schedule is updated only at BPO (Blob Parameter-Only)
// forks. Named forks such as Osaka or Amsterdam inherit the most recently configured
// BPO entry and must not declare their own BlobConfig.
type BlobScheduleConfig struct {
	Cancun *BlobConfig `json:"cancun,omitempty"`
	Prague *BlobConfig `json:"prague,omitempty"`
	BPO1   *BlobConfig `json:"bpo1,omitempty"`
	BPO2   *BlobConfig `json:"bpo2,omitempty"`
	BPO3   *BlobConfig `json:"bpo3,omitempty"`
	BPO4   *BlobConfig `json:"bpo4,omitempty"`
	BPO5   *BlobConfig `json:"bpo5,omitempty"`
}

// IsHomestead returns whether num is either equal to the homestead block or greater.
func (c *ChainConfig) IsHomestead(num *big.Int) bool {
	return isBlockForked(c.HomesteadBlock, num)
}

// IsDAOFork returns whether num is either equal to the DAO fork block or greater.
func (c *ChainConfig) IsDAOFork(num *big.Int) bool {
	return isBlockForked(c.DAOForkBlock, num)
}

// IsEIP150 returns whether num is either equal to the EIP150 fork block or greater.
func (c *ChainConfig) IsEIP150(num *big.Int) bool {
	return isBlockForked(c.EIP150Block, num)
}

// IsEIP155 returns whether num is either equal to the EIP155 fork block or greater.
func (c *ChainConfig) IsEIP155(num *big.Int) bool {
	return isBlockForked(c.EIP155Block, num)
}

// IsEIP158 returns whether num is either equal to the EIP158 fork block or greater.
func (c *ChainConfig) IsEIP158(num *big.Int) bool {
	return isBlockForked(c.EIP158Block, num)
}

// IsByzantium returns whether num is either equal to the Byzantium fork block or greater.
func (c *ChainConfig) IsByzantium(num *big.Int) bool {
	return isBlockForked(c.ByzantiumBlock, num)
}

// IsConstantinople returns whether num is either equal to the Constantinople fork block or greater.
func (c *ChainConfig) IsConstantinople(num *big.Int) bool {
	return isBlockForked(c.ConstantinopleBlock, num)
}

// IsMuirGlacier returns whether num is either equal to the Muir Glacier (EIP-2384) fork block or greater.
func (c *ChainConfig) IsMuirGlacier(num *big.Int) bool {
	return isBlockForked(c.MuirGlacierBlock, num)
}

// IsPetersburg returns whether num is either
//   - at or past the XDC-specific TIPXDCXCancellationFee activation (canonical
//     XDPoSChain config_forks.go gates Petersburg on TIPXDCXCancellationFeeBlock:
//     38,383,838 mainnet / 23,779,191 apothem / 0 devnet), OR
//   - equal to or greater than the PetersburgBlock fork block, OR
//   - PetersburgBlock is nil and Constantinople is active (upstream fallback).
//
// XDC parity: the TIPXDCXCancellationFee clause mirrors IsIstanbul and matches
// canonical XDPoSChain exactly. Without it, modern activated Petersburg at
// BerlinBlock (76,321,000 mainnet) instead of 38,383,838 — a 38M-block flag
// mismatch. Benign in execution (Istanbul instruction set + EIP-2200 gas table
// dominate from 38,383,838 on both clients) but corrected here for bit-exact
// fork-schedule parity across the full mainnet range.
func (c *ChainConfig) IsPetersburg(num *big.Int) bool {
	return isBlockForked(common.TIPXDCXCancellationFee, num) || isBlockForked(c.PetersburgBlock, num) || c.PetersburgBlock == nil && isBlockForked(c.ConstantinopleBlock, num)
}

// IsIstanbul returns whether num is either equal to the Istanbul fork block or greater.
func (c *ChainConfig) IsIstanbul(num *big.Int) bool {
	return isBlockForked(common.TIPXDCXCancellationFee, num) || isBlockForked(c.IstanbulBlock, num)
}

// IsBerlin returns whether num is either equal to the Berlin fork block or greater.
func (c *ChainConfig) IsBerlin(num *big.Int) bool {
	return isBlockForked(c.BerlinBlock, num)
}

// IsLondon returns whether num is either equal to the London fork block or greater.
func (c *ChainConfig) IsLondon(num *big.Int) bool {
	return isBlockForked(c.LondonBlock, num)
}

// IsEIP1559 returns whether EIP-1559 (basefee / fee market) is active at num.
// For XDC chains, EIP-1559 may be activated at a different block than London.
// XDC mainnet: Eip1559Block = 98,800,200 (matches XDPoSChain v2.6.8 constants.mainnet.go).
// XDC Apothem: Eip1559Block = 71,550,000.
// For non-XDC chains (Eip1559Block == nil), falls back to IsLondon.
func (c *ChainConfig) IsEIP1559(num *big.Int) bool {
	if c.Eip1559Block != nil {
		return isBlockForked(c.Eip1559Block, num)
	}
	return false
}

// IsCancunBlock returns whether the Cancun fork (block-number based) is active at num.
// XDC mainnet: CancunBlock = 98,802,000 (matches XDPoSChain v2.6.8 constants.mainnet.go).
// For non-XDC chains (CancunBlock == nil), this always returns false (use IsCancun for timestamp).
func (c *ChainConfig) IsCancunBlock(num *big.Int) bool {
	if c.CancunBlock != nil {
		return isBlockForked(c.CancunBlock, num)
	}
	return false
}

// IsPragueBlock returns whether the Prague fork (block-number based) is active at num.
// XDC chains gate Prague by block (matching XDPoSChain v2.8.0 PragueBlock) rather than
// the upstream timestamp-based PragueTime; apothem target = 83,600,000 (held disabled
// until #963 parity). For non-XDC chains (PragueBlock == nil) this returns false and the
// timestamp-based IsPrague path is used instead.
func (c *ChainConfig) IsPragueBlock(num *big.Int) bool {
	if c.PragueBlock != nil {
		return isBlockForked(c.PragueBlock, num)
	}
	return false
}

// IsArrowGlacier returns whether num is either equal to the Arrow Glacier (EIP-4345) fork block or greater.
func (c *ChainConfig) IsArrowGlacier(num *big.Int) bool {
	return isBlockForked(c.ArrowGlacierBlock, num)
}

// IsGrayGlacier returns whether num is either equal to the Gray Glacier (EIP-5133) fork block or greater.
func (c *ChainConfig) IsGrayGlacier(num *big.Int) bool {
	return isBlockForked(c.GrayGlacierBlock, num)
}

// IsTerminalPoWBlock returns whether the given block is the last block of PoW stage.
func (c *ChainConfig) IsTerminalPoWBlock(parentTotalDiff *big.Int, totalDiff *big.Int) bool {
	if c.TerminalTotalDifficulty == nil {
		return false
	}
	return parentTotalDiff.Cmp(c.TerminalTotalDifficulty) < 0 && totalDiff.Cmp(c.TerminalTotalDifficulty) >= 0
}

// IsPostMerge reports whether the given block number is assumed to be post-merge.
// Here we check the MergeNetsplitBlock to allow configuring networks with a PoW or
// PoA chain for unit testing purposes.
func (c *ChainConfig) IsPostMerge(blockNum uint64, timestamp uint64) bool {
	mergedAtGenesis := c.TerminalTotalDifficulty != nil && c.TerminalTotalDifficulty.Sign() == 0
	return mergedAtGenesis ||
		c.MergeNetsplitBlock != nil && blockNum >= c.MergeNetsplitBlock.Uint64() ||
		c.ShanghaiTime != nil && timestamp >= *c.ShanghaiTime
}

// IsShanghai returns whether time is either equal to the Shanghai fork time or greater.
func (c *ChainConfig) IsShanghai(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.ShanghaiTime, time)
}

// IsCancun returns whether time is either equal to the Cancun fork time or greater.
func (c *ChainConfig) IsCancun(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.CancunTime, time)
}

// IsPrague returns whether time is either equal to the Prague fork time or greater.
func (c *ChainConfig) IsPrague(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.PragueTime, time)
}

// IsOsaka returns whether time is either equal to the Osaka fork time or greater.
func (c *ChainConfig) IsOsaka(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.OsakaTime, time)
}

// IsBPO1 returns whether time is either equal to the BPO1 fork time or greater.
func (c *ChainConfig) IsBPO1(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.BPO1Time, time)
}

// IsBPO2 returns whether time is either equal to the BPO2 fork time or greater.
func (c *ChainConfig) IsBPO2(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.BPO2Time, time)
}

// IsBPO3 returns whether time is either equal to the BPO3 fork time or greater.
func (c *ChainConfig) IsBPO3(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.BPO3Time, time)
}

// IsBPO4 returns whether time is either equal to the BPO4 fork time or greater.
func (c *ChainConfig) IsBPO4(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.BPO4Time, time)
}

// IsBPO5 returns whether time is either equal to the BPO5 fork time or greater.
func (c *ChainConfig) IsBPO5(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.BPO5Time, time)
}

// IsAmsterdam returns whether time is either equal to the Amsterdam fork time or greater.
func (c *ChainConfig) IsAmsterdam(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.AmsterdamTime, time)
}

// IsVerkle returns whether time is either equal to the Verkle fork time or greater.
func (c *ChainConfig) IsVerkle(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.VerkleTime, time)
}

// IsBogota returns whether time is either equal to the Bogota fork time or greater.
func (c *ChainConfig) IsBogota(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.BogotaTime, time)
}

// IsFrameTx returns whether time is either equal to the FrameTx fork time or
// greater. EIP-8141 frame transactions are only admissible once this fork is
// active. The fork is inactive by default (nil) on every preset config.
func (c *ChainConfig) IsFrameTx(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.FrameTxTime, time)
}

// Note: IsUBT is NOT defined here — it is declared further below as an
// always-false XDC stub (kept so TestProcessUBT / genesis_test.go compile).
// A duplicate definition here would be a compile error.

// IsXDC reports whether the chain config is for an XDC-managed chain. The
// XDPoS engine is the authoritative discriminator — it's set only for chains
// that use XDPoS consensus, which by definition means XDC.
//
// This predicate replaces 11 chainID-hardcode sites that historically used
// some variant of `chainID == 50 || chainID == 51` or
// `cid == 50 || cid == 51 || cid == 5551`. The unified predicate matches:
//
//   - mainnet (50)
//   - Apothem testnet (51)
//   - devnet (551, XDPoSChain main)
//   - legacy devnet (5551)
//   - private dev chain (99999, generated via cmd/puppeth)
//
// At runtime each of these constructs a ChainConfig with XDPoS set, so the
// predicate captures them all without enumeration. See issues #694 §A and
// #686 §A for the audit trail.
func (c *ChainConfig) IsXDC() bool {
	return c != nil && c.XDPoS != nil
}

// XDCBlocksPerYear returns the number of blocks produced in a 365-day year
// at this chain's configured block time (XDPoS.Period seconds). For
// Apothem/Mainnet Period=2 → 15,768,000 (= common.BlocksPerYear). For other
// configured periods the value differs; the package-level
// `common.BlocksPerYear` constant is the Apothem/Mainnet value baked in at
// compile time and is wrong for any chain with Period != 2.
//
// This matters for RewardInflation halving thresholds: trying to halve at a
// chain-relative anniversary requires the chain's own BlocksPerYear, not the
// Apothem default. Bug #692 (RewardInflation called with chain=nil) and
// audit #694 §H surfaced this. Use this method in any code path that
// derives a "years since genesis" or "halving epoch" from block number.
//
// Fall back to common.BlocksPerYear when c.XDPoS is nil or Period is 0,
// preserving behavior for non-XDC chains and badly-configured XDC chains.
func (c *ChainConfig) XDCBlocksPerYear() uint64 {
	if c != nil && c.XDPoS != nil && c.XDPoS.Period > 0 {
		return common.OneYear / c.XDPoS.Period
	}
	return common.BlocksPerYear
}

// IsVerkleGenesis checks whether the verkle fork is activated at the genesis block.
//
// Verkle mode is considered enabled if the verkle fork time is configured,
// regardless of whether the local time has surpassed the fork activation time.
// This is a temporary workaround for verkle devnet testing, where verkle is
// activated at genesis, and the configured activation date has already passed.
//
// In production networks (mainnet and public testnets), verkle activation
// always occurs after the genesis block, making this function irrelevant in
// those cases.
func (c *ChainConfig) IsVerkleGenesis() bool {
	return c.EnableVerkleAtGenesis
}

// IsEIP4762 returns whether eip 4762 has been activated at given block.
func (c *ChainConfig) IsEIP4762(num *big.Int, time uint64) bool {
	return c.IsVerkle(num, time)
}

// IsTIP2019 checks if block number is past TIP2019 fork
func (c *ChainConfig) IsTIP2019(num *big.Int) bool {
	return isBlockForked(common.TIP2019Block, num)
}

// IsTIPSigning checks if block number is past TIPSigning fork
func (c *ChainConfig) IsTIPSigning(num *big.Int) bool {
	return isBlockForked(common.TIPSigning, num)
}

// IsTIPNoHalvingMNReward checks if block number is past TIPNoHalvingMNReward fork
// (when this fork is active, masternode reward is no longer halved)
func (c *ChainConfig) IsTIPNoHalvingMNReward(num *big.Int) bool {
	return isBlockForked(common.TIPNoHalvingMNReward, num)
}

// IsTIPRandomize checks if block number is past TIPRandomize fork
func (c *ChainConfig) IsTIPRandomize(num *big.Int) bool {
	return isBlockForked(common.TIPRandomize, num)
}

// IsTIPUpgradeReward checks if block number is past TIPUpgradeReward fork.
// XDC v2.8.0 (#963): gated per-network on ChainConfig.TIPUpgradeRewardBlock
// (nil = disabled), superseding the disabled global common.TIPUpgradeReward.
func (c *ChainConfig) IsTIPUpgradeReward(num *big.Int) bool {
	return isBlockForked(c.TIPUpgradeRewardBlock, num)
}

// IsTIPUpgradePenalty checks if block number is past TipUpgradePenalty fork.
// XDC v2.8.0 (#963): gated per-network on ChainConfig.TIPUpgradePenaltyBlock
// (nil = disabled), superseding the disabled global common.TipUpgradePenalty.
func (c *ChainConfig) IsTIPUpgradePenalty(num *big.Int) bool {
	return isBlockForked(c.TIPUpgradePenaltyBlock, num)
}

// IsTIPXDCX checks if block number is past TIPXDCX fork (trading/lending enabled)
func (c *ChainConfig) IsTIPXDCX(num *big.Int) bool {
	return isBlockForked(common.TIPXDCX, num)
}

// IsTIPXDCXMiner checks if block number is past TIPXDCXMinerDisable fork
// When active, miner no longer processes trading/lending as empty transactions
func (c *ChainConfig) IsTIPXDCXMiner(num *big.Int) bool {
	return isBlockForked(common.TIPXDCXMinerDisable, num)
}

// IsTIPXDCXReceiver checks if block number is past TIPXDCXReceiverDisable fork
// When active, receiver no longer processes trading/lending as empty transactions
// For devnet: TIPXDCX=0 and TIPXDCXReceiverDisable=0 => isForked(0,num)=true && !isForked(0,num)=false => returns false
// This means devnet processes trading/lending as normal EVM transactions (not empty)
func (c *ChainConfig) IsTIPXDCXReceiver(num *big.Int) bool {
	return isBlockForked(common.TIPXDCX, num) && !isBlockForked(common.TIPXDCXReceiverDisable, num)
}

// CheckCompatible checks whether scheduled fork transitions have been imported
// with a mismatching chain configuration.
func (c *ChainConfig) CheckCompatible(newcfg *ChainConfig, height uint64, time uint64) *ConfigCompatError {
	var (
		bhead = new(big.Int).SetUint64(height)
		btime = time
	)
	// Iterate checkCompatible to find the lowest conflict.
	var lasterr *ConfigCompatError
	for {
		err := c.checkCompatible(newcfg, bhead, btime)
		if err == nil || (lasterr != nil && err.RewindToBlock == lasterr.RewindToBlock && err.RewindToTime == lasterr.RewindToTime) {
			break
		}
		lasterr = err

		if err.RewindToTime > 0 {
			btime = err.RewindToTime
		} else {
			bhead.SetUint64(err.RewindToBlock)
		}
	}
	return lasterr
}

// CheckConfigForkOrder checks that we don't "skip" any forks, geth isn't pluggable enough
// to guarantee that forks can be implemented in a different order than on official networks
func (c *ChainConfig) CheckConfigForkOrder() error {
	type fork struct {
		name      string
		block     *big.Int // forks up to - and including the merge - were defined with block numbers
		timestamp *uint64  // forks after the merge are scheduled using timestamps
		optional  bool     // if true, the fork may be nil and next fork is still allowed
	}
	var lastFork fork
	for _, cur := range []fork{
		{name: "homesteadBlock", block: c.HomesteadBlock},
		{name: "daoForkBlock", block: c.DAOForkBlock, optional: true},
		{name: "eip150Block", block: c.EIP150Block},
		{name: "eip155Block", block: c.EIP155Block},
		{name: "eip158Block", block: c.EIP158Block},
		{name: "byzantiumBlock", block: c.ByzantiumBlock},
		{name: "constantinopleBlock", block: c.ConstantinopleBlock},
		{name: "petersburgBlock", block: c.PetersburgBlock},
		{name: "istanbulBlock", block: c.IstanbulBlock},
		{name: "muirGlacierBlock", block: c.MuirGlacierBlock, optional: true},
		{name: "berlinBlock", block: c.BerlinBlock},
		{name: "londonBlock", block: c.LondonBlock},
		{name: "arrowGlacierBlock", block: c.ArrowGlacierBlock, optional: true},
		{name: "grayGlacierBlock", block: c.GrayGlacierBlock, optional: true},
		{name: "mergeNetsplitBlock", block: c.MergeNetsplitBlock, optional: true},
		{name: "shanghaiTime", timestamp: c.ShanghaiTime},
		{name: "cancunTime", timestamp: c.CancunTime, optional: true},
		{name: "pragueTime", timestamp: c.PragueTime, optional: true},
		{name: "osakaTime", timestamp: c.OsakaTime, optional: true},
		{name: "verkleTime", timestamp: c.VerkleTime, optional: true},
		{name: "bpo1", timestamp: c.BPO1Time, optional: true},
		{name: "bpo2", timestamp: c.BPO2Time, optional: true},
		{name: "bpo3", timestamp: c.BPO3Time, optional: true},
		{name: "bpo4", timestamp: c.BPO4Time, optional: true},
		{name: "bpo5", timestamp: c.BPO5Time, optional: true},
		{name: "amsterdam", timestamp: c.AmsterdamTime, optional: true},
		{name: "bogota", timestamp: c.BogotaTime, optional: true},
	} {
		if lastFork.name != "" {
			switch {
			// Non-optional forks must all be present in the chain config up to the last defined fork
			case lastFork.block == nil && lastFork.timestamp == nil && (cur.block != nil || cur.timestamp != nil):
				if cur.block != nil {
					return fmt.Errorf("unsupported fork ordering: %v not enabled, but %v enabled at block %v",
						lastFork.name, cur.name, cur.block)
				} else {
					return fmt.Errorf("unsupported fork ordering: %v not enabled, but %v enabled at timestamp %v",
						lastFork.name, cur.name, *cur.timestamp)
				}

			// Fork (whether defined by block or timestamp) must follow the fork definition sequence
			case (lastFork.block != nil && cur.block != nil) || (lastFork.timestamp != nil && cur.timestamp != nil):
				if lastFork.block != nil && lastFork.block.Cmp(cur.block) > 0 {
					return fmt.Errorf("unsupported fork ordering: %v enabled at block %v, but %v enabled at block %v",
						lastFork.name, lastFork.block, cur.name, cur.block)
				} else if lastFork.timestamp != nil && *lastFork.timestamp > *cur.timestamp {
					return fmt.Errorf("unsupported fork ordering: %v enabled at timestamp %v, but %v enabled at timestamp %v",
						lastFork.name, *lastFork.timestamp, cur.name, *cur.timestamp)
				}

				// Timestamp based forks can follow block based ones, but not the other way around
				if lastFork.timestamp != nil && cur.block != nil {
					return fmt.Errorf("unsupported fork ordering: %v used timestamp ordering, but %v reverted to block ordering",
						lastFork.name, cur.name)
				}
			}
		}
		// If it was optional and not set, then ignore it
		if !cur.optional || (cur.block != nil || cur.timestamp != nil) {
			lastFork = cur
		}
	}

	// Check that all forks with blobs explicitly define the blob schedule configuration.
	bsc := c.BlobScheduleConfig
	if bsc == nil {
		bsc = new(BlobScheduleConfig)
	}
	for _, cur := range []struct {
		name      string
		timestamp *uint64
		config    *BlobConfig
	}{
		{name: "cancun", timestamp: c.CancunTime, config: bsc.Cancun},
		{name: "prague", timestamp: c.PragueTime, config: bsc.Prague},
		{name: "bpo1", timestamp: c.BPO1Time, config: bsc.BPO1},
		{name: "bpo2", timestamp: c.BPO2Time, config: bsc.BPO2},
		{name: "bpo3", timestamp: c.BPO3Time, config: bsc.BPO3},
		{name: "bpo4", timestamp: c.BPO4Time, config: bsc.BPO4},
		{name: "bpo5", timestamp: c.BPO5Time, config: bsc.BPO5},
	} {
		if cur.config != nil {
			if err := cur.config.validate(); err != nil {
				return fmt.Errorf("invalid chain configuration in blobSchedule for fork %q: %v", cur.name, err)
			}
		}
		if cur.timestamp != nil {
			// If the fork is configured, a blob schedule must be defined for it.
			if cur.config == nil {
				return fmt.Errorf("invalid chain configuration: missing entry for fork %q in blobSchedule", cur.name)
			}
		}
	}
	return nil
}

func (bc *BlobConfig) validate() error {
	if bc.Max < 0 {
		return errors.New("max < 0")
	}
	if bc.Target < 0 {
		return errors.New("target < 0")
	}
	if bc.UpdateFraction == 0 {
		return errors.New("update fraction must be defined and non-zero")
	}
	return nil
}

func (c *ChainConfig) checkCompatible(newcfg *ChainConfig, headNumber *big.Int, headTimestamp uint64) *ConfigCompatError {
	if isForkBlockIncompatible(c.HomesteadBlock, newcfg.HomesteadBlock, headNumber) {
		return newBlockCompatError("Homestead fork block", c.HomesteadBlock, newcfg.HomesteadBlock)
	}
	if isForkBlockIncompatible(c.DAOForkBlock, newcfg.DAOForkBlock, headNumber) {
		return newBlockCompatError("DAO fork block", c.DAOForkBlock, newcfg.DAOForkBlock)
	}
	if c.IsDAOFork(headNumber) && c.DAOForkSupport != newcfg.DAOForkSupport {
		return newBlockCompatError("DAO fork support flag", c.DAOForkBlock, newcfg.DAOForkBlock)
	}
	if isForkBlockIncompatible(c.EIP150Block, newcfg.EIP150Block, headNumber) {
		return newBlockCompatError("EIP150 fork block", c.EIP150Block, newcfg.EIP150Block)
	}
	if isForkBlockIncompatible(c.EIP155Block, newcfg.EIP155Block, headNumber) {
		return newBlockCompatError("EIP155 fork block", c.EIP155Block, newcfg.EIP155Block)
	}
	if isForkBlockIncompatible(c.EIP158Block, newcfg.EIP158Block, headNumber) {
		return newBlockCompatError("EIP158 fork block", c.EIP158Block, newcfg.EIP158Block)
	}
	if c.IsEIP158(headNumber) && !configBlockEqual(c.ChainID, newcfg.ChainID) {
		return newBlockCompatError("EIP158 chain ID", c.EIP158Block, newcfg.EIP158Block)
	}
	if isForkBlockIncompatible(c.ByzantiumBlock, newcfg.ByzantiumBlock, headNumber) {
		return newBlockCompatError("Byzantium fork block", c.ByzantiumBlock, newcfg.ByzantiumBlock)
	}
	if isForkBlockIncompatible(c.ConstantinopleBlock, newcfg.ConstantinopleBlock, headNumber) {
		return newBlockCompatError("Constantinople fork block", c.ConstantinopleBlock, newcfg.ConstantinopleBlock)
	}
	if isForkBlockIncompatible(c.PetersburgBlock, newcfg.PetersburgBlock, headNumber) {
		// the only case where we allow Petersburg to be set in the past is if it is equal to Constantinople
		// mainly to satisfy fork ordering requirements which state that Petersburg fork be set if Constantinople fork is set
		if isForkBlockIncompatible(c.ConstantinopleBlock, newcfg.PetersburgBlock, headNumber) {
			return newBlockCompatError("Petersburg fork block", c.PetersburgBlock, newcfg.PetersburgBlock)
		}
	}
	if isForkBlockIncompatible(c.IstanbulBlock, newcfg.IstanbulBlock, headNumber) {
		return newBlockCompatError("Istanbul fork block", c.IstanbulBlock, newcfg.IstanbulBlock)
	}
	if isForkBlockIncompatible(c.MuirGlacierBlock, newcfg.MuirGlacierBlock, headNumber) {
		return newBlockCompatError("Muir Glacier fork block", c.MuirGlacierBlock, newcfg.MuirGlacierBlock)
	}
	if isForkBlockIncompatible(c.BerlinBlock, newcfg.BerlinBlock, headNumber) {
		return newBlockCompatError("Berlin fork block", c.BerlinBlock, newcfg.BerlinBlock)
	}
	if isForkBlockIncompatible(c.LondonBlock, newcfg.LondonBlock, headNumber) {
		return newBlockCompatError("London fork block", c.LondonBlock, newcfg.LondonBlock)
	}
	if isForkBlockIncompatible(c.ArrowGlacierBlock, newcfg.ArrowGlacierBlock, headNumber) {
		return newBlockCompatError("Arrow Glacier fork block", c.ArrowGlacierBlock, newcfg.ArrowGlacierBlock)
	}
	if isForkBlockIncompatible(c.GrayGlacierBlock, newcfg.GrayGlacierBlock, headNumber) {
		return newBlockCompatError("Gray Glacier fork block", c.GrayGlacierBlock, newcfg.GrayGlacierBlock)
	}
	if isForkBlockIncompatible(c.MergeNetsplitBlock, newcfg.MergeNetsplitBlock, headNumber) {
		return newBlockCompatError("Merge netsplit fork block", c.MergeNetsplitBlock, newcfg.MergeNetsplitBlock)
	}
	if isForkTimestampIncompatible(c.ShanghaiTime, newcfg.ShanghaiTime, headTimestamp) {
		return newTimestampCompatError("Shanghai fork timestamp", c.ShanghaiTime, newcfg.ShanghaiTime)
	}
	if isForkTimestampIncompatible(c.CancunTime, newcfg.CancunTime, headTimestamp) {
		return newTimestampCompatError("Cancun fork timestamp", c.CancunTime, newcfg.CancunTime)
	}
	if isForkTimestampIncompatible(c.PragueTime, newcfg.PragueTime, headTimestamp) {
		return newTimestampCompatError("Prague fork timestamp", c.PragueTime, newcfg.PragueTime)
	}
	if isForkTimestampIncompatible(c.OsakaTime, newcfg.OsakaTime, headTimestamp) {
		return newTimestampCompatError("Osaka fork timestamp", c.OsakaTime, newcfg.OsakaTime)
	}
	if isForkTimestampIncompatible(c.VerkleTime, newcfg.VerkleTime, headTimestamp) {
		return newTimestampCompatError("Verkle fork timestamp", c.VerkleTime, newcfg.VerkleTime)
	}
	if isForkTimestampIncompatible(c.BPO1Time, newcfg.BPO1Time, headTimestamp) {
		return newTimestampCompatError("BPO1 fork timestamp", c.BPO1Time, newcfg.BPO1Time)
	}
	if isForkTimestampIncompatible(c.BPO2Time, newcfg.BPO2Time, headTimestamp) {
		return newTimestampCompatError("BPO2 fork timestamp", c.BPO2Time, newcfg.BPO2Time)
	}
	if isForkTimestampIncompatible(c.BPO3Time, newcfg.BPO3Time, headTimestamp) {
		return newTimestampCompatError("BPO3 fork timestamp", c.BPO3Time, newcfg.BPO3Time)
	}
	if isForkTimestampIncompatible(c.BPO4Time, newcfg.BPO4Time, headTimestamp) {
		return newTimestampCompatError("BPO4 fork timestamp", c.BPO4Time, newcfg.BPO4Time)
	}
	if isForkTimestampIncompatible(c.BPO5Time, newcfg.BPO5Time, headTimestamp) {
		return newTimestampCompatError("BPO5 fork timestamp", c.BPO5Time, newcfg.BPO5Time)
	}
	if isForkTimestampIncompatible(c.AmsterdamTime, newcfg.AmsterdamTime, headTimestamp) {
		return newTimestampCompatError("Amsterdam fork timestamp", c.AmsterdamTime, newcfg.AmsterdamTime)
	}
	if isForkTimestampIncompatible(c.BogotaTime, newcfg.BogotaTime, headTimestamp) {
		return newTimestampCompatError("Bogota fork timestamp", c.BogotaTime, newcfg.BogotaTime)
	}
	return nil
}

// BaseFeeChangeDenominator bounds the amount the base fee can change between blocks.
func (c *ChainConfig) BaseFeeChangeDenominator() uint64 {
	return DefaultBaseFeeChangeDenominator
}

// ElasticityMultiplier bounds the maximum gas limit an EIP-1559 block may have.
func (c *ChainConfig) ElasticityMultiplier() uint64 {
	return DefaultElasticityMultiplier
}

// LatestFork returns the latest time-based fork that would be active for the given time.
func (c *ChainConfig) LatestFork(time uint64) forks.Fork {
	// Assume last non-time-based fork has passed.
	london := c.LondonBlock

	switch {
	case c.IsBogota(london, time):
		return forks.Bogota
	case c.IsAmsterdam(london, time):
		return forks.Amsterdam
	case c.IsBPO5(london, time):
		return forks.BPO5
	case c.IsBPO4(london, time):
		return forks.BPO4
	case c.IsBPO3(london, time):
		return forks.BPO3
	case c.IsBPO2(london, time):
		return forks.BPO2
	case c.IsBPO1(london, time):
		return forks.BPO1
	case c.IsOsaka(london, time):
		return forks.Osaka
	case c.IsPrague(london, time):
		return forks.Prague
	case c.IsCancun(london, time):
		return forks.Cancun
	case c.IsShanghai(london, time):
		return forks.Shanghai
	default:
		return forks.Paris
	}
}

// BlobConfig returns the blob config active at the provided fork. Since named
// forks (Osaka, Amsterdam, ...) no longer carry their own blob schedule, the
// lookup walks down from fork through the BPO chain to Prague/Cancun and returns
// the first non-nil entry.
func (c *ChainConfig) BlobConfig(fork forks.Fork) *BlobConfig {
	if c.BlobScheduleConfig == nil {
		return nil
	}
	bsc := c.BlobScheduleConfig
	chain := []struct {
		at  forks.Fork
		cfg *BlobConfig
	}{
		{forks.BPO5, bsc.BPO5},
		{forks.BPO4, bsc.BPO4},
		{forks.BPO3, bsc.BPO3},
		{forks.BPO2, bsc.BPO2},
		{forks.BPO1, bsc.BPO1},
		{forks.Prague, bsc.Prague},
		{forks.Cancun, bsc.Cancun},
	}
	for _, e := range chain {
		if e.at <= fork && e.cfg != nil {
			return e.cfg
		}
	}
	return nil
}

// ActiveSystemContracts returns the currently active system contracts at the
// given timestamp.
func (c *ChainConfig) ActiveSystemContracts(time uint64) map[string]common.Address {
	fork := c.LatestFork(time)
	active := make(map[string]common.Address)
	if fork >= forks.Amsterdam {
		// EIP-8282 - Builder Execution Requests
		active["BUILDER_DEPOSIT_CONTRACT_ADDRESS"] = BuilderDepositAddress
		active["BUILDER_EXIT_CONTRACT_ADDRESS"] = BuilderExitAddress
	}
	if fork >= forks.Osaka {
		// no new system contracts
	}
	if fork >= forks.Prague {
		active["CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS"] = ConsolidationQueueAddress
		active["DEPOSIT_CONTRACT_ADDRESS"] = c.DepositContractAddress
		active["HISTORY_STORAGE_ADDRESS"] = HistoryStorageAddress
		active["WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS"] = WithdrawalQueueAddress
	}
	if fork >= forks.Cancun {
		active["BEACON_ROOTS_ADDRESS"] = BeaconRootsAddress
	}
	return active
}

// Timestamp returns the timestamp associated with the fork or returns nil if
// the fork isn't defined or isn't a time-based fork.
func (c *ChainConfig) Timestamp(fork forks.Fork) *uint64 {
	switch {
	case fork == forks.Bogota:
		return c.BogotaTime
	case fork == forks.Amsterdam:
		return c.AmsterdamTime
	case fork == forks.BPO5:
		return c.BPO5Time
	case fork == forks.BPO4:
		return c.BPO4Time
	case fork == forks.BPO3:
		return c.BPO3Time
	case fork == forks.BPO2:
		return c.BPO2Time
	case fork == forks.BPO1:
		return c.BPO1Time
	case fork == forks.Osaka:
		return c.OsakaTime
	case fork == forks.Prague:
		return c.PragueTime
	case fork == forks.Cancun:
		return c.CancunTime
	case fork == forks.Shanghai:
		return c.ShanghaiTime
	default:
		return nil
	}
}

// isForkBlockIncompatible returns true if a fork scheduled at block s1 cannot be
// rescheduled to block s2 because head is already past the fork.
func isForkBlockIncompatible(s1, s2, head *big.Int) bool {
	return (isBlockForked(s1, head) || isBlockForked(s2, head)) && !configBlockEqual(s1, s2)
}

// isBlockForked returns whether a fork scheduled at block s is active at the
// given head block. Whilst this method is the same as isTimestampForked, they
// are explicitly separate for clearer reading.
func isBlockForked(s, head *big.Int) bool {
	if s == nil || head == nil {
		return false
	}
	return s.Cmp(head) <= 0
}

func configBlockEqual(x, y *big.Int) bool {
	if x == nil {
		return y == nil
	}
	if y == nil {
		return x == nil
	}
	return x.Cmp(y) == 0
}

// isForkTimestampIncompatible returns true if a fork scheduled at timestamp s1
// cannot be rescheduled to timestamp s2 because head is already past the fork.
func isForkTimestampIncompatible(s1, s2 *uint64, head uint64) bool {
	return (isTimestampForked(s1, head) || isTimestampForked(s2, head)) && !configTimestampEqual(s1, s2)
}

// isTimestampForked returns whether a fork scheduled at timestamp s is active
// at the given head timestamp. Whilst this method is the same as isBlockForked,
// they are explicitly separate for clearer reading.
func isTimestampForked(s *uint64, head uint64) bool {
	if s == nil {
		return false
	}
	return *s <= head
}

func configTimestampEqual(x, y *uint64) bool {
	if x == nil {
		return y == nil
	}
	if y == nil {
		return x == nil
	}
	return *x == *y
}

// ConfigCompatError is raised if the locally-stored blockchain is initialised with a
// ChainConfig that would alter the past.
type ConfigCompatError struct {
	What string

	// block numbers of the stored and new configurations if block based forking
	StoredBlock, NewBlock *big.Int

	// timestamps of the stored and new configurations if time based forking
	StoredTime, NewTime *uint64

	// the block number to which the local chain must be rewound to correct the error
	RewindToBlock uint64

	// the timestamp to which the local chain must be rewound to correct the error
	RewindToTime uint64
}

func newBlockCompatError(what string, storedblock, newblock *big.Int) *ConfigCompatError {
	var rew *big.Int
	switch {
	case storedblock == nil:
		rew = newblock
	case newblock == nil || storedblock.Cmp(newblock) < 0:
		rew = storedblock
	default:
		rew = newblock
	}
	err := &ConfigCompatError{
		What:          what,
		StoredBlock:   storedblock,
		NewBlock:      newblock,
		RewindToBlock: 0,
	}
	if rew != nil && rew.Sign() > 0 {
		err.RewindToBlock = rew.Uint64() - 1
	}
	return err
}

func newTimestampCompatError(what string, storedtime, newtime *uint64) *ConfigCompatError {
	var rew *uint64
	switch {
	case storedtime == nil:
		rew = newtime
	case newtime == nil || *storedtime < *newtime:
		rew = storedtime
	default:
		rew = newtime
	}
	err := &ConfigCompatError{
		What:         what,
		StoredTime:   storedtime,
		NewTime:      newtime,
		RewindToTime: 0,
	}
	if rew != nil && *rew != 0 {
		err.RewindToTime = *rew - 1
	}
	return err
}

func (err *ConfigCompatError) Error() string {
	if err.StoredBlock != nil {
		return fmt.Sprintf("mismatching %s in database (have block %d, want block %d, rewindto block %d)", err.What, err.StoredBlock, err.NewBlock, err.RewindToBlock)
	}

	if err.StoredTime == nil && err.NewTime == nil {
		return ""
	} else if err.StoredTime == nil && err.NewTime != nil {
		return fmt.Sprintf("mismatching %s in database (have timestamp nil, want timestamp %d, rewindto timestamp %d)", err.What, *err.NewTime, err.RewindToTime)
	} else if err.StoredTime != nil && err.NewTime == nil {
		return fmt.Sprintf("mismatching %s in database (have timestamp %d, want timestamp nil, rewindto timestamp %d)", err.What, *err.StoredTime, err.RewindToTime)
	}
	return fmt.Sprintf("mismatching %s in database (have timestamp %d, want timestamp %d, rewindto timestamp %d)", err.What, *err.StoredTime, *err.NewTime, err.RewindToTime)
}

// Rules wraps ChainConfig and is merely syntactic sugar or can be used for functions
// that do not have or require information about the block.
//
// Rules is a one time interface meaning that it shouldn't be used in between transition
// phases.
type Rules struct {
	IsHomestead, IsEIP150, IsEIP155, IsEIP158               bool
	IsEIP2929, IsEIP4762                                    bool
	IsByzantium, IsConstantinople, IsPetersburg, IsIstanbul bool
	IsBerlin, IsLondon                                      bool
	IsMerge, IsShanghai, IsCancun, IsPrague, IsOsaka        bool
	IsAmsterdam, IsVerkle, IsUBT, IsBogota                  bool
	IsFrameTx                                               bool // EIP-8141 frame transactions (inactive unless FrameTxTime is set)
	// IsEIP3860 gates the EIP-3860 initcode word-cost surcharge in
	// IntrinsicGas (state_transition.go) and the MAX_INITCODE_SIZE check.
	// Upstream geth couples this with IsShanghai. For XDC chains, this is
	// gated on IsEIP1559 — see #716 / canonical XDPoSChain's
	// newEip1559InstructionSet enables 2929/3529/3860 together at the
	// Eip1559Block (not Cancun).
	IsEIP3860 bool
	// IsXDC is true when this chain is configured with XDPoS (Apothem,
	// Mainnet, devnets, or private XDC networks). Carried in Rules so
	// downstream consumers (core/vm precompile selection, etc.) can
	// branch on it without re-deriving from a chain config they may not
	// hold. Issue #710.
	IsXDC bool
	// IsEIP1559 is true at-or-after the chain's Eip1559Block. For XDC
	// chains this is a major opcode-pricing boundary: canonical
	// XDPoSChain enables EIP-2929 (cold/warm), EIP-3529 (refund cap +
	// schedule), EIP-2565 (cheaper MODEXP), and EIP-3860 (initcode word
	// cost) all in newEip1559InstructionSet — not at Cancun. Issue #716.
	IsEIP1559 bool
}

// Rules ensures c's ChainID is not nil.
func (c *ChainConfig) Rules(num *big.Int, isMerge bool, timestamp uint64) Rules {
	// disallow setting Merge out of order
	isMerge = isMerge && c.IsLondon(num)
	isVerkle := isMerge && c.IsVerkle(num, timestamp)
	// XDC chains defer EIP-2929 (cold/warm state access) from Berlin to
	// the EIP-1559 block — canonical XDPoSChain's newEip1559InstructionSet
	// enables it together with EIP-3529 and EIP-3860. Berlin/London/
	// Merge/Shanghai on XDC are marker-only opcode boundaries until
	// IsEIP1559 flips on. Issue #716 (supersedes #705/#710's earlier
	// IsCancunBlock gating). Non-XDC chains keep upstream behaviour.
	isEIP2929 := c.IsBerlin(num) && !isVerkle
	if c.IsXDC() {
		isEIP2929 = c.IsEIP1559(num) && !isVerkle
	}
	// Default upstream wiring: Merge/Shanghai/Cancun all gated on the
	// caller-supplied isMerge bool plus a timestamp-based check.
	isMergeRule := isMerge
	isShanghai := isMerge && c.IsShanghai(num, timestamp)
	isCancun := isMerge && c.IsCancun(num, timestamp)
	isPrague := isMerge && c.IsPrague(num, timestamp)
	// EIP-3860 (initcode word cost + size limit) is upstream-coupled to
	// Shanghai but on XDC defers to Cancun (canonical XDPoSChain enables it
	// in newCancunInstructionSet, not newShanghaiInstructionSet).
	isEIP3860 := isShanghai
	if c.IsXDC() {
		// XDC chains: Berlin/London/Merge/Shanghai all fire at the same
		// block (canonical XDPoSChain testnet/mainnet constants). Drive
		// Merge/Shanghai from IsLondon so PREVRANDAO and PUSH0 are
		// available at the documented heights — see issue #707. Drive
		// IsCancun from IsCancunBlock for Cancun-specific opcodes
		// (BLOBHASH, MCOPY, TLOAD/TSTORE, etc.).
		//
		// EIP-2929/3529/3860 activate at Eip1559Block on XDC (canonical's
		// newEip1559InstructionSet), NOT at Cancun. Issue #716 corrected
		// this — prior PRs #705/#707/#710 had it at IsCancunBlock.
		isMergeRule = c.IsLondon(num)
		isShanghai = c.IsLondon(num)
		isCancun = c.IsCancunBlock(num)
		isEIP3860 = c.IsEIP1559(num)
		// Prague on XDC is block-gated (XDPoSChain v2.8.0 PragueBlock), not
		// timestamp-gated. nil PragueBlock => false => Prague stays off (#963).
		isPrague = c.IsPragueBlock(num)
	}
	return Rules{
		IsHomestead:      c.IsHomestead(num),
		IsEIP150:         c.IsEIP150(num),
		IsEIP155:         c.IsEIP155(num),
		IsEIP158:         c.IsEIP158(num),
		IsByzantium:      c.IsByzantium(num),
		IsConstantinople: c.IsConstantinople(num),
		IsPetersburg:     c.IsPetersburg(num),
		IsIstanbul:       c.IsIstanbul(num),
		IsBerlin:         c.IsBerlin(num),
		IsEIP2929:        isEIP2929,
		IsEIP3860:        isEIP3860,
		IsXDC:            c.IsXDC(),
		IsEIP1559:        c.IsEIP1559(num),
		IsLondon:         c.IsLondon(num),
		IsMerge:          isMergeRule,
		IsShanghai:       isShanghai,
		IsCancun:         isCancun,
		IsPrague:         isPrague,
		IsOsaka:          isMerge && c.IsOsaka(num, timestamp),
		IsAmsterdam:      isMerge && c.IsAmsterdam(num, timestamp),
		IsVerkle:         isVerkle,
		IsEIP4762:        isVerkle,
		// EIP-5920: NOT merge-gated, same reasoning as IsFrameTx below —
		// XDPoS headers never have zero difficulty, so an isMerge-gated
		// Rules field would keep Bogotá (and the PAY opcode) permanently
		// inactive on every XDC chain even after BogotaTime is scheduled.
		IsBogota: c.IsBogota(num, timestamp),
		// EIP-8141: NOT merge-gated. The fork condition is defined by
		// IsFrameTx itself (IsLondon && FrameTxTime reached), and XDPoS
		// headers never have zero difficulty, so the isMerge signal
		// (head.Difficulty.Sign() == 0) is permanently false on XDC chains.
		// Merge-gating here made every FrameTx fail the pool's
		// rules.IsFrameTx check ("pool not yet in FrameTx fork") even on
		// chains with FrameTxTime active. See core/txpool/validation.go.
		IsFrameTx: c.IsFrameTx(num, timestamp),
		IsUBT:            false, // XDC never activates UBT; see the IsUBT stub below
	}
}

// IsUBT returns whether the UBT (Unbounded Trie) fork is active.
// Restored from v1.17.3 baseline (refs #740). XDC doesn't activate UBT;
// this method exists only to satisfy v1.17.3's core/blockchain.go and
// core/chain_makers.go consumers — returns false on all XDC chain configs.
func (c *ChainConfig) IsUBT(num *big.Int, time uint64) bool {
	return false
}

// UBTTime and EnableUBTAtGenesis are v1.17.3 ChainConfig fields for the UBT
// (Unbounded Trie / Verkle) fork. XDC chains do not activate UBT — these
// fields exist as zero-value placeholders so upstream code (core/genesis.go,
// core/blockchain.go) builds against the XDC overlay.
// Refs #740 — see docs/PORT_LOG.md.

func (c *ChainConfig) IsUBTGenesis() bool {
	return c.EnableUBTAtGenesis
}
