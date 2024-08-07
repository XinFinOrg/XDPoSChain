const { expect } = require("chai");
const { ethers } = require("hardhat");
const deploy = {
  candidates: [
    "0xf0AbABbb043792D8cDAf1961c96758932189965D",
    "0xf43988206b1F23cBECe8EA835F31FA97EB1a73fd",
  ],
  caps: ["10000000000000000000000000", "10000000000000000000000000", "100"],
  minCandidateCap: "10000000000000000000000000",
  minVoterCap: "25000000000000000000000",
  maxValidatorNumber: 18,
  candidateWithdrawDelay: 1296000,
  voterWithdrawDelay: 432000,
  minCandidateNum: 2,
};
const {
  loadFixture,
  setBalance,
  time,
  mine,
} = require("@nomicfoundation/hardhat-toolbox/network-helpers");

describe("XDCValidator", () => {
  let xdcValidator;
  let master;
  const fixture = async () => {
    const factory = await ethers.getContractFactory("XDCValidator");
    const signer = await ethers.getSigner();
    const master = signer.address;
    deploy["candidates"].push(master);
    const xdcValidator = await factory.deploy(
      deploy["candidates"],
      deploy["caps"].map((item) => {
        return hre.ethers.utils.parseUnits(item, 0);
      }),
      master,
      hre.ethers.utils.parseUnits(deploy["minCandidateCap"], 0),
      hre.ethers.utils.parseUnits(deploy["minVoterCap"], 0),
      deploy["maxValidatorNumber"],
      deploy["candidateWithdrawDelay"],
      deploy["voterWithdrawDelay"]
    );

    return { xdcValidator, master };
  };

  beforeEach("deploy fixture", async () => {
    ({ xdcValidator, master } = await loadFixture(fixture));
  });

  describe("test xdc validator contract", () => {
    it("propose", async () => {
      await setBalance(master, 1e30);
      const candidate = await ethers.Wallet.createRandom().getAddress();
      const minCandidateCap = hre.ethers.utils.parseUnits(
        deploy["minCandidateCap"],
        0
      );
      await xdcValidator.propose(candidate, {
        value: minCandidateCap,
      });

      const candidates = await xdcValidator.getCandidates();
      const voters = await xdcValidator.getVoters(candidate);
      const ownerLength = await xdcValidator.getOwnerToCandidateLength(master);
      const ownerToCandidates = [];
      for (let i = 0; i < ownerLength; i++) {
        const ownerToCandidate = await xdcValidator.ownerToCandidate(master, i);
        ownerToCandidates.push(ownerToCandidate);
      }
      const validatorsState = await xdcValidator.validatorsState(candidate);
      const voterCap = await xdcValidator.getVoterCap(candidate, master);

      expect(candidates).to.include(candidate);
      expect(voters).to.include(master);
      expect(ownerToCandidates).to.include(candidate);
      expect(validatorsState["owner"]).to.eq(master);
      expect(validatorsState["isCandidate"]).to.eq(true);
      expect(validatorsState["cap"]).to.eq(minCandidateCap);
      expect(voterCap).to.eq(minCandidateCap);
    });

    it("resign", async () => {
      await setBalance(master, 1e30);
      const candidate = await ethers.Wallet.createRandom().getAddress();
      const minCandidateCap = hre.ethers.utils.parseUnits(
        deploy["minCandidateCap"],
        0
      );
      await xdcValidator.propose(candidate, {
        value: minCandidateCap,
      });
      const candidatesBefore = await xdcValidator.getCandidates();

      await xdcValidator.resign(candidate);
      const candidates = await xdcValidator.getCandidates();
      const voters = await xdcValidator.getVoters(candidate);
      const ownerLength = await xdcValidator.getOwnerToCandidateLength(master);
      const ownerToCandidates = [];
      for (let i = 0; i < ownerLength; i++) {
        const ownerToCandidate = await xdcValidator.ownerToCandidate(master, i);
        ownerToCandidates.push(ownerToCandidate);
      }
      const validatorsState = await xdcValidator.validatorsState(candidate);
      const voterCap = await xdcValidator.getVoterCap(candidate, master);

      const before = [...deploy["candidates"]];
      before.push(candidate);

      expect(candidatesBefore).to.deep.eq(before);
      expect(candidates).to.deep.eq(deploy["candidates"]);
      expect(voters).to.include(master);
      expect(ownerToCandidates).to.not.include(candidate);
      expect(validatorsState["owner"]).to.eq(master);
      expect(validatorsState["isCandidate"]).to.eq(false);
      expect(validatorsState["cap"]).to.eq(0);
      expect(voterCap).to.eq(0);
    });

    it("vote", async () => {
      await setBalance(master, 1e30);
      const candidate = await ethers.Wallet.createRandom().getAddress();
      const minCandidateCap = hre.ethers.utils.parseUnits(
        deploy["minCandidateCap"],
        0
      );
      await xdcValidator.propose(candidate, {
        value: minCandidateCap,
      });
      const minVoterCap = hre.ethers.utils.parseUnits(deploy["minVoterCap"], 0);
      await xdcValidator.vote(candidate, {
        value: minVoterCap,
      });
      const candidates = await xdcValidator.getCandidates();
      const voters = await xdcValidator.getVoters(candidate);
      const ownerLength = await xdcValidator.getOwnerToCandidateLength(master);
      const ownerToCandidates = [];
      for (let i = 0; i < ownerLength; i++) {
        const ownerToCandidate = await xdcValidator.ownerToCandidate(master, i);
        ownerToCandidates.push(ownerToCandidate);
      }
      const validatorsState = await xdcValidator.validatorsState(candidate);
      const voterCap = await xdcValidator.getVoterCap(candidate, master);

      expect(candidates).to.include(candidate);
      expect(voters).to.include(master);
      expect(ownerToCandidates).to.include(candidate);
      expect(validatorsState["owner"]).to.eq(master);
      expect(validatorsState["isCandidate"]).to.eq(true);
      expect(validatorsState["cap"]).to.eq(minCandidateCap.add(minVoterCap));
      expect(voterCap).to.eq(minCandidateCap.add(minVoterCap));
    });

    it("unvote", async () => {
      await setBalance(master, 1e30);
      const candidate = await ethers.Wallet.createRandom().getAddress();
      const minCandidateCap = hre.ethers.utils.parseUnits(
        deploy["minCandidateCap"],
        0
      );
      await xdcValidator.propose(candidate, {
        value: minCandidateCap,
      });
      const minVoterCap = hre.ethers.utils.parseUnits(deploy["minVoterCap"], 0);
      await xdcValidator.vote(candidate, {
        value: minVoterCap,
      });

      const block = await time.latestBlock();
      await xdcValidator.unvote(candidate, minVoterCap);

      const candidates = await xdcValidator.getCandidates();
      const voters = await xdcValidator.getVoters(candidate);
      const ownerLength = await xdcValidator.getOwnerToCandidateLength(master);
      const ownerToCandidates = [];
      for (let i = 0; i < ownerLength; i++) {
        const ownerToCandidate = await xdcValidator.ownerToCandidate(master, i);
        ownerToCandidates.push(ownerToCandidate);
      }
      const validatorsState = await xdcValidator.validatorsState(candidate);
      const voterCap = await xdcValidator.getVoterCap(candidate, master);
      const withdrawCap = await xdcValidator.getWithdrawCap(
        block + deploy["voterWithdrawDelay"] + 1
      );
      expect(candidates).to.include(candidate);
      expect(voters).to.include(master);
      expect(ownerToCandidates).to.include(candidate);
      expect(validatorsState["owner"]).to.eq(master);
      expect(validatorsState["isCandidate"]).to.eq(true);
      expect(validatorsState["cap"]).to.eq(minCandidateCap);
      expect(voterCap).to.eq(minCandidateCap);
      expect(withdrawCap).to.eq(minVoterCap);
    });

    it("withdraw", async () => {
      await setBalance(master, 1e30);
      const candidate = await ethers.Wallet.createRandom().getAddress();
      const minCandidateCap = hre.ethers.utils.parseUnits(
        deploy["minCandidateCap"],
        0
      );
      await xdcValidator.propose(candidate, {
        value: minCandidateCap,
      });
      const minVoterCap = hre.ethers.utils.parseUnits(deploy["minVoterCap"], 0);
      await xdcValidator.vote(candidate, {
        value: minVoterCap,
      });

      const block = await time.latestBlock();
      await xdcValidator.unvote(candidate, minVoterCap);
      mine(deploy["voterWithdrawDelay"] + 1);
      const beforeBalance = await ethers.provider.getBalance(
        xdcValidator.address
      );
      const withdrawCap = await xdcValidator.getWithdrawCap(
        block + deploy["voterWithdrawDelay"] + 1
      );

      await xdcValidator.withdraw(block + deploy["voterWithdrawDelay"] + 1, 0);
      const afterBalance = await ethers.provider.getBalance(
        xdcValidator.address
      );
      expect(afterBalance).to.eq(beforeBalance.sub(withdrawCap));
    });

    it("directly resign one candidate", async () => {
      const oldCandidates = await xdcValidator.getCandidates();

      await xdcValidator.resign("0xf43988206b1F23cBECe8EA835F31FA97EB1a73fd");
      const newCandidates = await xdcValidator.getCandidates();
      expect(oldCandidates).to.deep.eq(deploy["candidates"]);
      expect(newCandidates).to.deep.eq([
        "0xf0AbABbb043792D8cDAf1961c96758932189965D",
        master,
      ]);
    });
    
    it("kyc upload and claim", async () => {
      const kyc = "0x01";
      await xdcValidator.uploadKYC(kyc);
      const pendingKYC = await xdcValidator.pendingKYC(master);
      expect(pendingKYC?.kycHash).to.eq(kyc);
      await mine(10 * 43200);
      await xdcValidator.claimKYC();
      const kycString = await xdcValidator.KYCString(master, 0);
      expect(kycString).to.eq(kyc);
    });

    it("kyc invalid vote", async () => {
      const kyc = "0x01";
      await xdcValidator.uploadKYC(kyc);
      const pendingKYC = await xdcValidator.pendingKYC(master);
      expect(pendingKYC?.kycHash).to.eq(kyc);
      await xdcValidator.voteInvalidKYC(master);
      const pendingKYCAfter = await xdcValidator.pendingKYC(master);
      expect(pendingKYCAfter?.kycHash).to.eq("");
    });
  });
});
