const {
  walletClient,
  publicClient,
  validator,
  expect,
  onwer1,
} = require("./constant");
const { generatePrivateKey, privateKeyToAccount } = require("viem/accounts");

async function run() {
  const privateKey = generatePrivateKey();
  const newCandidate = privateKeyToAccount(privateKey);

  const minCandidateCap = 10000000000000000000000000n;
  const minVoterCap = 10000000000000000000000000n;

  await walletClient.writeContract({
    ...validator,
    functionName: "propose",
    args: [newCandidate.address],
    value: minCandidateCap,
    account: onwer1,
  });
  const candidates = await publicClient.readContract({
    ...validator,
    functionName: "getCandidates",
  });
  expect(
    candidates.include(newCandidate.address),
    "must include new candidate"
  );

  await walletClient.writeContract({
    ...validator,
    functionName: "resign",
    args: [newCandidate.address],
    account: onwer1,
  });

  expect(
    !candidates.include(newCandidate.address),
    "must dont include new candidate"
  );

  await walletClient.writeContract({
    ...validator,
    functionName: "propose",
    args: [newCandidate.address],
    value: minCandidateCap,
    account: onwer1,
  });

  await walletClient.writeContract({
    ...validator,
    functionName: "vote",
    args: [newCandidate.address],
    value: minVoterCap,
    account: onwer1,
  });

  const validatorsState = await publicClient.readContract({
    ...validator,
    functionName: "validatorsState",
    args: [newCandidate.address],
  });

  expect(validatorsState[2] == minVoterCap + minCandidateCap, "cap not equal");

  await walletClient.writeContract({
    ...validator,
    functionName: "unvote",
    args: [newCandidate.address, minVoterCap],
    account: onwer1,
  });

  const validatorsState2 = await publicClient.readContract({
    ...validator,
    functionName: "validatorsState",
    args: [newCandidate.address],
  });

  expect(validatorsState2[2] == minCandidateCap, "cap not equal");
}

run();
