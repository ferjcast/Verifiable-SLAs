const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("SLA Evidence Registry", function () {
  let registry;
  let slaConfig;
  let monitor, provider, consumer, other;
  
  // Test data
  const attestationQuote = "0x1234567890abcdef";
  const publicKey = "0xabcdef1234567890";
  const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("test-merkle-root"));
  const ipfsCID = "QmTest123456789";
  
  beforeEach(async function () {
    [monitor, provider, consumer, other] = await ethers.getSigners();
    
    // Deploy contracts
    const Registry = await ethers.getContractFactory("SLAEvidenceRegistry");
    registry = await Registry.deploy();
    
    const SLAConfig = await ethers.getContractFactory("SLAConfiguration");
    slaConfig = await SLAConfig.deploy();
  });
  
  describe("Monitor Registration", function () {
    it("Should register a new monitor", async function () {
      await expect(registry.connect(monitor).registerMonitor(
        attestationQuote,
        publicKey,
        provider.address,
        consumer.address
      )).to.emit(registry, "MonitorRegistered")
        .withArgs(monitor.address, provider.address, consumer.address, attestationQuote);
      
      const monitorData = await registry.getMonitor(monitor.address);
      expect(monitorData.isActive).to.be.true;
      expect(monitorData.serviceProvider).to.equal(provider.address);
      expect(monitorData.serviceConsumer).to.equal(consumer.address);
    });
    
    it("Should not allow duplicate registration", async function () {
      await registry.connect(monitor).registerMonitor(
        attestationQuote,
        publicKey,
        provider.address,
        consumer.address
      );
      
      await expect(registry.connect(monitor).registerMonitor(
        attestationQuote,
        publicKey,
        provider.address,
        consumer.address
      )).to.be.revertedWith("Monitor already registered");
    });
  });
  
  describe("Evidence Batch Submission", function () {
    beforeEach(async function () {
      // Register monitor first
      await registry.connect(monitor).registerMonitor(
        attestationQuote,
        publicKey,
        provider.address,
        consumer.address
      );
    });
    
    it("Should submit evidence batch", async function () {
      const startTime = Math.floor(Date.now() / 1000);
      const endTime = startTime + 3600; // 1 hour later
      const batchSize = 1024;
      
      await expect(registry.connect(monitor).submitEvidenceBatch(
        merkleRoot,
        startTime,
        endTime,
        batchSize,
        ipfsCID
      )).to.emit(registry, "EvidenceBatchSubmitted")
        .withArgs(monitor.address, merkleRoot, 0, startTime, endTime);
      
      const batch = await registry.getEvidenceBatch(monitor.address, 0);
      expect(batch.merkleRoot).to.equal(merkleRoot);
      expect(batch.batchSize).to.equal(batchSize);
      expect(batch.ipfsCID).to.equal(ipfsCID);
    });
    
    it("Should track sequence numbers", async function () {
      const startTime = Math.floor(Date.now() / 1000);
      
      // Submit 3 batches
      for (let i = 0; i < 3; i++) {
        await registry.connect(monitor).submitEvidenceBatch(
          merkleRoot,
          startTime + i * 3600,
          startTime + (i + 1) * 3600,
          1024,
          `${ipfsCID}_${i}`
        );
      }
      
      const currentSeq = await registry.getCurrentSequence(monitor.address);
      expect(currentSeq).to.equal(3);
    });
    
    it("Should reject submission from non-registered monitor", async function () {
      await expect(registry.connect(other).submitEvidenceBatch(
        merkleRoot,
        0,
        3600,
        1024,
        ipfsCID
      )).to.be.revertedWith("Not a registered monitor");
    });
  });
  
  describe("Violation Claims", function () {
    const zkProof = "0xdeadbeef"; // Mock ZK proof
    
    it("Should submit violation claim", async function () {
      const tx = await registry.connect(provider).submitViolationClaim(
        merkleRoot,
        zkProof,
        ipfsCID
      );
      
      const receipt = await tx.wait();
      const event = receipt.logs.find(log => {
        try {
          const parsed = registry.interface.parseLog(log);
          return parsed.name === "ViolationClaimSubmitted";
        } catch (e) {
          return false;
        }
      });
      
      expect(event).to.not.be.undefined;
    });
  });
  
  describe("Merkle Proof Verification", function () {
    it("Should verify valid Merkle proof", async function () {
      // Simple two-leaf tree
      const leaf1 = ethers.keccak256(ethers.toUtf8Bytes("measurement1"));
      const leaf2 = ethers.keccak256(ethers.toUtf8Bytes("measurement2"));
      
      // Calculate root
      const root = ethers.keccak256(
        ethers.concat([
          leaf1 <= leaf2 ? leaf1 : leaf2,
          leaf1 <= leaf2 ? leaf2 : leaf1
        ])
      );
      
      // Verify proof for leaf1
      const isValid = await registry.verifyMerkleProof(root, leaf1, [leaf2]);
      expect(isValid).to.be.true;
    });
  });
  
  describe("Heartbeat Monitoring", function () {
    beforeEach(async function () {
      await registry.connect(monitor).registerMonitor(
        attestationQuote,
        publicKey,
        provider.address,
        consumer.address
      );
    });
    
    it("Should emit heartbeat alert for missed batches", async function () {
      // Submit one batch
      const startTime = Math.floor(Date.now() / 1000) - 7200; // 2 hours ago
      await registry.connect(monitor).submitEvidenceBatch(
        merkleRoot,
        startTime,
        startTime + 60,
        1024,
        ipfsCID
      );
      
      // Check heartbeat (expecting alert)
      await expect(registry.connect(provider).checkHeartbeat(
        monitor.address,
        2 // max 2 missed batches
      )).to.emit(registry, "HeartbeatAlert");
    });
  });
});

describe("SLA Configuration", function () {
  let slaConfig;
  let provider, consumer;
  
  beforeEach(async function () {
    [provider, consumer] = await ethers.getSigners();
    
    const SLAConfig = await ethers.getContractFactory("SLAConfiguration");
    slaConfig = await SLAConfig.deploy();
  });
  
  it("Should register SLA specification", async function () {
    const specURI = "ipfs://QmSLASpec123";
    const zkProgramHash = ethers.keccak256(ethers.toUtf8Bytes("zkvm-bytecode"));
    
    await expect(slaConfig.connect(provider).registerSLA(
      specURI,
      zkProgramHash,
      provider.address,
      consumer.address
    )).to.emit(slaConfig, "SLARegistered");
    
    // Check provider's SLAs
    const providerSLAs = await slaConfig.providerSLAs(provider.address, 0);
    expect(providerSLAs).to.not.equal(ethers.ZeroHash);
  });
});