// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SLAEvidenceRegistry
 * @dev Main contract for verifiable SLA monitoring with TEE attestation
 */
contract SLAEvidenceRegistry {
    
    // Monitor information
    struct Monitor {
        address teeAddress;
        bytes attestationQuote;
        bytes publicKey;
        bool isActive;
        uint256 registrationTime;
        address serviceProvider;
        address serviceConsumer;
    }
    
    // Evidence batch information
    struct EvidenceBatch {
        bytes32 merkleRoot;
        address submitter;
        uint256 startTimestamp;
        uint256 endTimestamp;
        uint256 batchSize;
        string ipfsCID;  // IPFS content identifier for full data
        uint256 sequenceNumber;
    }
    
    // Violation claim structure
    struct ViolationClaim {
        bytes32 evidenceBatchRoot;
        bytes zkProof;
        uint256 claimTimestamp;
        address claimant;
        string ipfsCID;
        bool isVerified;
    }
    
    // State variables
    mapping(address => Monitor) public monitorRegistry;
    mapping(address => mapping(uint256 => EvidenceBatch)) public evidenceBatches;
    mapping(address => uint256) public batchSequence;
    mapping(bytes32 => ViolationClaim) public violationClaims;
    
    address[] public registeredMonitors;
    
    // Events
    event MonitorRegistered(
        address indexed monitorAddress,
        address indexed provider,
        address indexed consumer,
        bytes attestationQuote
    );
    
    event EvidenceBatchSubmitted(
        address indexed monitor,
        bytes32 merkleRoot,
        uint256 sequenceNumber,
        uint256 startTime,
        uint256 endTime
    );
    
    event ViolationClaimSubmitted(
        bytes32 indexed claimId,
        address indexed claimant,
        bytes32 evidenceBatchRoot
    );
    
    event HeartbeatAlert(
        address indexed monitor,
        uint256 lastSequenceNumber,
        uint256 alertTime
    );
    
    // Modifiers
    modifier onlyRegisteredMonitor() {
        require(monitorRegistry[msg.sender].isActive, "Not a registered monitor");
        _;
    }
    
    modifier onlyAuthorizedParties(address monitor) {
        Monitor memory m = monitorRegistry[monitor];
        require(
            msg.sender == m.serviceProvider || 
            msg.sender == m.serviceConsumer ||
            msg.sender == monitor,
            "Not authorized"
        );
        _;
    }
    
    /**
     * @dev Register a new TEE-based monitor
     * @param attestationQuote TEE attestation quote binding the public key
     * @param publicKey Monitor's public key for signature verification
     * @param provider Service provider address
     * @param consumer Service consumer address
     */
    function registerMonitor(
        bytes calldata attestationQuote,
        bytes calldata publicKey,
        address provider,
        address consumer
    ) external {
        require(provider != address(0) && consumer != address(0), "Invalid addresses");
        require(!monitorRegistry[msg.sender].isActive, "Monitor already registered");
        
        monitorRegistry[msg.sender] = Monitor({
            teeAddress: msg.sender,
            attestationQuote: attestationQuote,
            publicKey: publicKey,
            isActive: true,
            registrationTime: block.timestamp,
            serviceProvider: provider,
            serviceConsumer: consumer
        });
        
        registeredMonitors.push(msg.sender);
        
        emit MonitorRegistered(msg.sender, provider, consumer, attestationQuote);
    }
    
    /**
     * @dev Submit evidence batch with Merkle root
     * @param merkleRoot Root of Merkle tree containing measurements
     * @param startTimestamp Start of measurement window
     * @param endTimestamp End of measurement window
     * @param batchSize Number of measurements in batch
     * @param ipfsCID IPFS content identifier for full batch data
     */
    function submitEvidenceBatch(
        bytes32 merkleRoot,
        uint256 startTimestamp,
        uint256 endTimestamp,
        uint256 batchSize,
        string calldata ipfsCID
    ) external onlyRegisteredMonitor {
        uint256 expectedSequence = batchSequence[msg.sender];
        
        evidenceBatches[msg.sender][expectedSequence] = EvidenceBatch({
            merkleRoot: merkleRoot,
            submitter: msg.sender,
            startTimestamp: startTimestamp,
            endTimestamp: endTimestamp,
            batchSize: batchSize,
            ipfsCID: ipfsCID,
            sequenceNumber: expectedSequence
        });
        
        batchSequence[msg.sender] = expectedSequence + 1;
        
        emit EvidenceBatchSubmitted(
            msg.sender,
            merkleRoot,
            expectedSequence,
            startTimestamp,
            endTimestamp
        );
    }
    
    /**
     * @dev Submit a violation claim with ZK proof
     * @param evidenceBatchRoot Merkle root of evidence batch
     * @param zkProof Zero-knowledge proof of violation
     * @param ipfsCID IPFS identifier for claim details
     */
    function submitViolationClaim(
        bytes32 evidenceBatchRoot,
        bytes calldata zkProof,
        string calldata ipfsCID
    ) external returns (bytes32) {
        bytes32 claimId = keccak256(
            abi.encodePacked(evidenceBatchRoot, zkProof, block.timestamp, msg.sender)
        );
        
        violationClaims[claimId] = ViolationClaim({
            evidenceBatchRoot: evidenceBatchRoot,
            zkProof: zkProof,
            claimTimestamp: block.timestamp,
            claimant: msg.sender,
            ipfsCID: ipfsCID,
            isVerified: false
        });
        
        emit ViolationClaimSubmitted(claimId, msg.sender, evidenceBatchRoot);
        
        return claimId;
    }
    
    /**
     * @dev Check monitor heartbeat and raise alert if needed
     * @param monitor Address of monitor to check
     * @param maxMissedBatches Maximum allowed missed batches
     */
    function checkHeartbeat(
        address monitor,
        uint256 maxMissedBatches
    ) external onlyAuthorizedParties(monitor) {
        uint256 lastSequence = batchSequence[monitor];
        if (lastSequence == 0) return;
        
        EvidenceBatch memory lastBatch = evidenceBatches[monitor][lastSequence - 1];
        uint256 timeSinceLastBatch = block.timestamp - lastBatch.endTimestamp;
        
        // Assuming 60 second intervals between batches
        uint256 expectedBatches = timeSinceLastBatch / 60;
        
        if (expectedBatches > maxMissedBatches) {
            emit HeartbeatAlert(monitor, lastSequence - 1, block.timestamp);
        }
    }
    
    /**
     * @dev Verify a Merkle proof for a specific measurement
     * @param root Merkle root
     * @param leaf Leaf value (measurement hash)
     * @param proof Merkle proof path
     */
    function verifyMerkleProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof
    ) external pure returns (bool) {
        bytes32 computedHash = leaf;
        
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        
        return computedHash == root;
    }
    
    /**
     * @dev Get monitor details
     */
    function getMonitor(address monitor) external view returns (Monitor memory) {
        return monitorRegistry[monitor];
    }
    
    /**
     * @dev Get evidence batch
     */
    function getEvidenceBatch(
        address monitor,
        uint256 sequenceNumber
    ) external view returns (EvidenceBatch memory) {
        return evidenceBatches[monitor][sequenceNumber];
    }
    
    /**
     * @dev Get current sequence number for a monitor
     */
    function getCurrentSequence(address monitor) external view returns (uint256) {
        return batchSequence[monitor];
    }
    
    /**
     * @dev Get all registered monitors
     */
    function getRegisteredMonitors() external view returns (address[] memory) {
        return registeredMonitors;
    }
}
