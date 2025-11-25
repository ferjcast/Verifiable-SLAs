const { ethers } = require("hardhat");

async function main() {
  // Get the contract factories
  const SLAConfiguration = await ethers.getContractFactory("SLAConfiguration");
  const SLAEvidenceRegistry = await ethers.getContractFactory("SLAEvidenceRegistry");

  // Deploy SLAConfiguration contract
  console.log("Deploying SLAConfiguration...");
  const slaConfiguration = await SLAConfiguration.deploy();
  await slaConfiguration.waitForDeployment();
  const slaConfigurationAddress = await slaConfiguration.getAddress();
  console.log(`SLAConfiguration deployed to: ${slaConfigurationAddress}`);

  // Deploy SLAEvidenceRegistry contract
  console.log("Deploying SLAEvidenceRegistry...");
  const slaEvidenceRegistry = await SLAEvidenceRegistry.deploy();
  await slaEvidenceRegistry.waitForDeployment();
  const slaEvidenceRegistryAddress = await slaEvidenceRegistry.getAddress();
  console.log(`SLAEvidenceRegistry deployed to: ${slaEvidenceRegistryAddress}`);
}

// Execute the deployment
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });