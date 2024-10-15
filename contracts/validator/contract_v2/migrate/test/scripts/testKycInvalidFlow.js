const {
  walletClient,
  validator,
  publicClient,
  expect,
  onwer1,
  onwer2,
  onwer3,
  onwe4,
  onwe5,
} = require("./constant");
const { generatePrivateKey, privateKeyToAccount } = require("viem/accounts");

async function run() {
  const privateKey = generatePrivateKey();
  const newCandidate = privateKeyToAccount(privateKey);

  const minCandidateCap = 10000000000000000000000000n;

  await walletClient.writeContract({
    ...validator,
    functionName: "propose",
    args: [newCandidate.address],
    value: minCandidateCap,
    account: onwer1,
  });

  await walletClient.sendTransaction({
    to: newCandidate.address,
    value: minCandidateCap,
    account: onwer1,
  });

  await walletClient.writeContract({
    ...validator,
    functionName: "uploadKYC",
    args: ["hello"],
    account: newCandidate,
  });

  const pendingKYC = await publicClient.readContract({
    ...validator,
    functionName: "pendingKYC",
    args: [newCandidate.address],
  });

  expect(pendingKYC[1] == "hello", "kyc info is not correctly");

  const ownerCount = await publicClient.readContract({
    ...validator,
    functionName: "getOwnerCount",
    args: [],
  });

  console.log(
    "ownerCount ",
    ownerCount,
    " it need " +
      Math.ceil(0.75 * ownerCount?.toString()) +
      " owners to vote invalid kyc"
  );

  await walletClient.writeContract({
    ...validator,
    functionName: "voteInvalidKYC",
    args: [onwer1.address],
    account: onwer2,
  });
  await walletClient.writeContract({
    ...validator,
    functionName: "voteInvalidKYC",
    args: [onwer1.address],
    account: onwer3,
  });
  await walletClient.writeContract({
    ...validator,
    functionName: "voteInvalidKYC",
    args: [onwer1.address],
    account: onwe4,
  });
  await walletClient.writeContract({
    ...validator,
    functionName: "voteInvalidKYC",
    args: [onwer1.address],
    account: onwe5,
  });

  const pendingKYC2 = await publicClient.readContract({
    ...validator,
    functionName: "pendingKYC",
    args: [newCandidate.address],
  });

  expect(pendingKYC2[1] == "", "kyc info is not correctly");
}

run();
