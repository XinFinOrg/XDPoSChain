const { parseEther } = require("viem");
const {
  walletClient,
  publicClient,
  validator,
  expect,
  onwer1,
} = require("./constant");
const { generatePrivateKey, privateKeyToAccount } = require("viem/accounts");
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
async function run() {
  const list = [
    "0x77e0b4a7aabef3b07db42f1f2aa43130ba5a3175ec47f2ff8891d49ad87cbed9",
    "0x31b0fbcba7b60ea9974ae1bac0523af8cd72661de47ea2d3569344c975b93801",
    "0x5a3457e9323ef7f9351d7b6d8f4d5c2c7c66a5e094142d6e186c86402b29a787",
    "0x363f48b205f95859e13ea1acf6b047631ab34e69d193bbf5eb0df871decca69e",
    "0x1c40ebf394c9c9db15f60528f6a030ba9f465a7c615acd9b9d79792175b6bcd6",
    "0x58fbe847ab6faa2fb5559b4d1f1e02573e222d2524b6f4598a301897c0881e71",
    "0x64651f33879becd32391e3cf802680f3621500c55fb53db7b6b041ff74c3a62f",
    "0xe754b95280b2232ffb4398de0cdda06c2be24ef8aa5c6aba090802e0cd706022",
    "0xd4ead423829e8a525a84833095ea877b56d1e04a1d4990308059f434b4b7df08",
    "0x6dc218b18a4fad1c8d57004625cfe6e36f031843a9b63eac86c165c338ecf2ca",
    "0xfe191406af908a10997f6c5236ff7d514f24daf4c98684a7c79b2bbbcde7e641",
    "0x457c3bf99d900ed277e58dfdc466ed67605ca6b7a4389eb3795242e0098c51ce",
    "0xc36ee06f107b7b5f11c76cf5317dc43be44211c98d35f8f6d2848937654cec8b",
    "0xbdf6a0151fa9bc798213c19396e4ae3aa8a5e395ab6d879f96c6a60d7d4bb3bb",
    "0x77de7e5f7dd19de487abd0e5917985e0e418cbaa3f7d8f1b1dd7bc66855e32be",
  ];

  for (const pk of list) {
    const account = privateKeyToAccount(pk);
    const isCandidate = await publicClient.readContract({
      ...validator,
      functionName: "isCandidate",
      args: [account.address],
    });
    if (isCandidate) {
      console.log(account.address + " is candidate");
      await walletClient.sendTransaction({
        to: account.address,
        value: parseEther("1"),
        account: onwer1,
      });

      await sleep(10000);
      await walletClient.writeContract({
        ...validator,
        functionName: "uploadKYC",
        args: ["hello"],
        account: account,
      });
    }
  }
}

run();
