require("@nomiclabs/hardhat-waffle");
require("hardhat-gas-reporter");
require("dotenv").config();
const deploy = require("./deployment.json");
/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  solidity: {
    version: "0.4.26",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    xdcdevnet: {
      url: deploy["xdcdevnet"],
      accounts: [
        process.env.PRIVATE_KEY ||
          "1234567890123456789012345678901234567890123456789012345678901234",
      ],
    },
    xdcsubnet: {
      url: deploy["xdcsubnet"],
      accounts: [
        process.env.PRIVATE_KEY ||
          "1234567890123456789012345678901234567890123456789012345678901234",
      ],
    },
  },
};
