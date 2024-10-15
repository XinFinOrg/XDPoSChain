const hre = require("hardhat");
const deploy = require("../deployment.json");

async function main() {
  const xdcValidatorFactory = await hre.ethers.getContractFactory(
    "XDCValidator"
  );

  const xdcValidator = await xdcValidatorFactory.deploy(
    deploy["candidates"],
    deploy["caps"].map((item) => {
      return hre.ethers.utils.parseUnits(item, 0);
    }),
    deploy["firstOwner"],
    hre.ethers.utils.parseUnits(deploy["minCandidateCap"], 0),
    hre.ethers.utils.parseUnits(deploy["minVoterCap"], 0),
    deploy["maxValidatorNumber"],
    deploy["candidateWithdrawDelay"],
    deploy["voterWithdrawDelay"],
  );

  await xdcValidator.deployed();

  console.log("xdcValidator deployed to:", xdcValidator.address);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
