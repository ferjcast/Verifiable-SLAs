// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SLAConfiguration
 * @dev Stores SLA configurations and verification materials
 */
contract SLAConfiguration {
    
    struct SLASpec {
        string specificationURI;  // IPFS URI for full specification
        bytes32 zkProgramHash;    // Hash of zkVM bytecode
        address serviceProvider;
        address serviceConsumer;
        uint256 createdAt;
        bool isActive;
    }
    
    mapping(bytes32 => SLASpec) public slaSpecs;
    mapping(address => bytes32[]) public providerSLAs;
    mapping(address => bytes32[]) public consumerSLAs;
    
    event SLARegistered(
        bytes32 indexed slaId,
        address indexed provider,
        address indexed consumer,
        bytes32 zkProgramHash
    );
    
    /**
     * @dev Register a new SLA specification
     */
    function registerSLA(
        string calldata specificationURI,
        bytes32 zkProgramHash,
        address provider,
        address consumer
    ) external returns (bytes32) {
        require(
            msg.sender == provider || msg.sender == consumer,
            "Must be a party to the SLA"
        );
        
        bytes32 slaId = keccak256(
            abi.encodePacked(specificationURI, zkProgramHash, provider, consumer)
        );
        
        slaSpecs[slaId] = SLASpec({
            specificationURI: specificationURI,
            zkProgramHash: zkProgramHash,
            serviceProvider: provider,
            serviceConsumer: consumer,
            createdAt: block.timestamp,
            isActive: true
        });
        
        providerSLAs[provider].push(slaId);
        consumerSLAs[consumer].push(slaId);
        
        emit SLARegistered(slaId, provider, consumer, zkProgramHash);
        
        return slaId;
    }
}