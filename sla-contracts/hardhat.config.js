require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.28",
  networks: {
    test_network: {
      // Local test network (runs by default with `npx hardhat node`)
      url: "http://127.0.0.1:8545",
      chainId: 1337,
      // Optional: Specify accounts, gas, etc., if needed
       accounts: ["-"], // Uses default Hardhat accounts
    },
    hardhat: {
      // Local test network (runs by default with `npx hardhat node`)
      chainId: 31337,
      // Optional: Specify accounts, gas, etc., if needed
      // accounts: [], // Uses default Hardhat accounts
    },
  },
};