// Minimal Hardhat project fixture for velvet adapter tests (original work).
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  paths: { sources: "./contracts" },
};
