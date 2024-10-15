const { createPublicClient, http, createWalletClient } = require("viem");
const { privateKeyToAccount } = require("viem/accounts");
const validatorABI = require("../abi/validatorABI.json");
require("dotenv").config();
const o1PrivateKey = process.env.O1_PRIVATE_KEY;
const o2PrivateKey = process.env.O2_PRIVATE_KEY;
const o3PrivateKey = process.env.O3_PRIVATE_KEY;
const o4PrivateKey = process.env.O4_PRIVATE_KEY;
const o5PrivateKey = process.env.O5_PRIVATE_KEY;

const rpcUrl = process.env.RPC_URL;
const xdc = {
  id: 551,
  name: "XDC Devnet",
  network: "XDC Devnet",
  nativeCurrency: {
    decimals: 18,
    name: "XDC",
    symbol: "XDC",
  },
  rpcUrls: {
    public: { http: [rpcUrl] },
    default: { http: [rpcUrl] },
  },
};

const onwer1 = privateKeyToAccount(o1PrivateKey);
const onwer2 = privateKeyToAccount(o2PrivateKey);
const onwer3 = privateKeyToAccount(o3PrivateKey);
const onwe4 = privateKeyToAccount(o4PrivateKey);
const onwe5 = privateKeyToAccount(o5PrivateKey);

const publicClient = createPublicClient({
  chain: xdc,
  transport: http(rpcUrl),
});

const walletClient = createWalletClient({
  chain: xdc,
  transport: http(rpcUrl),
});

const validator = {
  address: "0x0000000000000000000000000000000000000088",
  abi: validatorABI,
};

function expect(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

module.exports = {
  publicClient,
  walletClient,
  validator,
  expect,
  onwer1,
  onwer2,
  onwer3,
  onwe4,
  onwe5,
};
