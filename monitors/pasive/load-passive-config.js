// load-passive-config.js - Load configuration into passive monitor
const axios = require('axios');
const { ethers } = require('ethers');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

// Configuration file paths
const CONFIG_DIR = path.join(__dirname, 'monitor-configs');
const KEYS_FILE = path.join(CONFIG_DIR, 'keys.json');
const CONFIG_FILE = path.join(CONFIG_DIR, 'passive-monitor-config.json');

// Create or load keys
async function loadOrCreateKeys() {
  try {
    // Ensure config directory exists
    await fs.mkdir(CONFIG_DIR, { recursive: true });
    
    // Check if keys already exist
    try {
      const keysData = await fs.readFile(KEYS_FILE, 'utf8');
      const keys = JSON.parse(keysData);
      console.log('Loaded existing keys from file');
      return keys;
    } catch (error) {
      // Keys don't exist, create new ones
      console.log('Creating new keys...');
      
      // Generate provider wallet
      const providerWallet = ethers.Wallet.createRandom();
      
      // Generate consumer wallet  
      const consumerWallet = ethers.Wallet.createRandom();
      
      const keys = {
        provider: {
          address: providerWallet.address,
          privateKey: providerWallet.privateKey
        },
        consumer: {
          address: consumerWallet.address,
          privateKey: consumerWallet.privateKey
        },
        createdAt: new Date().toISOString()
      };
      
      // Save keys to file
      await fs.writeFile(KEYS_FILE, JSON.stringify(keys, null, 2));
      console.log(`Keys saved to ${KEYS_FILE}`);
      
      console.log('\n🔐 Generated Keys:');
      console.log(`Provider Address: ${keys.provider.address}`);
      console.log(`Consumer Address: ${keys.consumer.address}`);
      console.log('\n⚠️  IMPORTANT: Update the monitor startup config with these addresses!');
      console.log('In passive-monitor.js, set:');
      console.log(`  providerAddress: "${keys.provider.address}"`);
      console.log(`  consumerAddress: "${keys.consumer.address}"`);
      
      return keys;
    }
  } catch (error) {
    console.error('Error handling keys:', error);
    throw error;
  }
}

// Configuration for passive monitoring
const passiveConfig = {
  schemaVersion: '1.0.0',
  
  // Backend server to forward requests to
  backendUrl: process.env.BACKEND_URL || 'http://ec2-3-17-44-230.us-east-2.compute.amazonaws.com:3000',
  backendTimeout: 30000, // 30 seconds
  
  // Measurement settings
  measurementInterval: 600000, // Seal batches every minute
  
  // Encryption key for sealed batches (generated)
  aesKey: null,
  
  // Evidence retention
  ttlDays: 90,
  
  // Aggregator endpoint (if using external aggregation)
  aggregatorEndpoint: 'http://localhost:4000/aggregate',
  
  // SLA Definition
  slaDefinition: {
    maxLatencyMs: 300,  // P95 should be below 300ms
    acceptableStatusCodes: [200, 201, 202, 204, 301, 302, 304],
    errorThreshold: 0.01 // 1% error rate
  },
  
  // These will be filled by the signing process
  providerAddress: null,
  consumerAddress: null,
  providerSignature: null,
  consumerSignature: null,
  batchSizeSeal: 8192
};

// Sign configuration
async function signConfiguration(keys) {
  // Generate a random AES key for batch encryption
  passiveConfig.aesKey = crypto.randomBytes(32).toString('hex');
  console.log('Generated AES encryption key for batches');
  
  // Create wallet instances from keys
  const providerWallet = new ethers.Wallet(keys.provider.privateKey);
  const consumerWallet = new ethers.Wallet(keys.consumer.privateKey);
  
  // Update addresses
  passiveConfig.providerAddress = keys.provider.address;
  passiveConfig.consumerAddress = keys.consumer.address;
  
  // Extract data to sign (excluding signatures)
  const dataToSign = {
    schemaVersion: passiveConfig.schemaVersion,
    backendUrl: passiveConfig.backendUrl,
    backendTimeout: passiveConfig.backendTimeout,
    measurementInterval: passiveConfig.measurementInterval,
    aesKey: passiveConfig.aesKey,
    ttlDays: passiveConfig.ttlDays,
    aggregatorEndpoint: passiveConfig.aggregatorEndpoint,
    slaDefinition: passiveConfig.slaDefinition
  };
  
  const configJson = JSON.stringify(dataToSign);
  const configHash = ethers.keccak256(ethers.toUtf8Bytes(configJson));
  
  // Sign with both parties
  console.log('Signing configuration...');
  console.log(`Config hash: ${configHash}`);
  
  passiveConfig.providerSignature = await providerWallet.signMessage(configHash);
  passiveConfig.consumerSignature = await consumerWallet.signMessage(configHash);
  
  console.log('Configuration signed by both parties');
  console.log(`Provider signature: ${passiveConfig.providerSignature.substring(0, 20)}...`);
  console.log(`Consumer signature: ${passiveConfig.consumerSignature.substring(0, 20)}...`);
}

// Save configuration to file
async function saveConfiguration() {
  try {
    // Save the complete configuration
    await fs.writeFile(CONFIG_FILE, JSON.stringify(passiveConfig, null, 2));
    console.log(`\nConfiguration saved to ${CONFIG_FILE}`);
    
    // Also save a summary for reference
    const summary = {
      backendUrl: passiveConfig.backendUrl,
      slaDefinition: passiveConfig.slaDefinition,
      providerAddress: passiveConfig.providerAddress,
      consumerAddress: passiveConfig.consumerAddress,
      aesKey: passiveConfig.aesKey.substring(0, 16) + '...',
      configHash: ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(passiveConfig))),
      savedAt: new Date().toISOString()
    };
    
    await fs.writeFile(
      path.join(CONFIG_DIR, 'config-summary.json'), 
      JSON.stringify(summary, null, 2)
    );
    
    console.log('Configuration summary saved');
    return true;
  } catch (error) {
    console.error('Error saving configuration:', error);
    return false;
  }
}

// Load existing configuration from file
async function loadExistingConfiguration() {
  try {
    const configData = await fs.readFile(CONFIG_FILE, 'utf8');
    return JSON.parse(configData);
  } catch (error) {
    return null;
  }
}

// Load configuration into monitor
async function loadConfiguration() {
  const monitorUrl = process.env.MONITOR_URL || 'https://18ac4587313d2fa4f8af9dee2b1d8cadd43aa054-3003.dstack-prod8.phala.network'; // 'http://localhost:3003';
  
  try {
    // Check if we should use existing configuration
    if (process.env.USE_EXISTING_CONFIG === 'true') {
      const existingConfig = await loadExistingConfiguration();
      if (existingConfig) {
        console.log('Using existing configuration from file');
        Object.assign(passiveConfig, existingConfig);
      } else {
        console.error('No existing configuration found');
        process.exit(1);
      }
    } else {
      // Load or create keys
      const keys = await loadOrCreateKeys();
      
      // Sign the configuration
      await signConfiguration(keys);
      
      // Save configuration to file
      await saveConfiguration();
    }
    
    console.log('\nLoading configuration into passive monitor...');
    console.log(`Monitor URL: ${monitorUrl}`);
    console.log(`Backend URL: ${passiveConfig.backendUrl}`);
    console.log(`SLA Max Latency: ${passiveConfig.slaDefinition.maxLatencyMs}ms`);
    console.log(`Provider: ${passiveConfig.providerAddress}`);
    console.log(`Consumer: ${passiveConfig.consumerAddress}`);
    
    // Send configuration to monitor
    const response = await axios.post(`${monitorUrl}/_monitor/loadconfig`, passiveConfig, {
      headers: { 'Content-Type': 'application/json' }
    });
    
    console.log('\n✅ Configuration loaded successfully!');
    console.log(response.data);
    
    // Check monitor status
    const statusResponse = await axios.get(`${monitorUrl}/_monitor/status`);
    console.log('\nMonitor Status:');
    console.log(JSON.stringify(statusResponse.data, null, 2));
    
  } catch (error) {
    console.error('\n❌ Failed to load configuration:');
    if (error.response) {
      console.error(`Status: ${error.response.status}`);
      console.error(`Error: ${JSON.stringify(error.response.data, null, 2)}`);
    } else {
      console.error(error.message);
    }
    process.exit(1);
  }
}

// Run if executed directly
if (require.main === module) {
  console.log('Passive Monitor Configuration Loader');
  console.log('====================================\n');
  
  // Check for command line arguments
  if (process.argv.includes('--help')) {
    console.log('Usage: node load-passive-config.js [options]\n');
    console.log('Options:');
    console.log('  --help                Show this help');
    console.log('  --show-keys           Display current keys');
    console.log('  --regenerate-keys     Force regeneration of keys\n');
    console.log('Environment variables:');
    console.log('  BACKEND_URL           Backend server URL (default: http://ec2-3-17-44-230.us-east-2.compute.amazonaws.com:3000)');
    console.log('  MONITOR_URL           Monitor URL (default: http://localhost:3003)');
    console.log('  USE_EXISTING_CONFIG   Use existing config file (true/false)');
    process.exit(0);
  }
  
  if (process.argv.includes('--show-keys')) {
    loadOrCreateKeys().then(keys => {
      console.log('\nCurrent Keys:');
      console.log('Provider:');
      console.log(`  Address: ${keys.provider.address}`);
      console.log(`  Private Key: ${keys.provider.privateKey}`);
      console.log('\nConsumer:');
      console.log(`  Address: ${keys.consumer.address}`);
      console.log(`  Private Key: ${keys.consumer.privateKey}`);
      console.log(`\nCreated: ${keys.createdAt}`);
    }).catch(console.error);
    return;
  }
  
  if (process.argv.includes('--regenerate-keys')) {
    fs.unlink(KEYS_FILE).then(() => {
      console.log('Deleted existing keys. New keys will be generated.');
      loadConfiguration();
    }).catch(() => {
      loadConfiguration();
    });
    return;
  }
  
  loadConfiguration().then(() => {
    console.log('\nConfiguration complete!');
    console.log('The passive monitor is now intercepting and forwarding requests.');
    console.log('\nTo test:');
    console.log(`  curl http://localhost:3003/health`);
    console.log(`  curl http://localhost:3003/api/v1/service`);
    console.log('\nTo view metrics:');
    console.log(`  curl http://localhost:3003/_monitor/status`);
    console.log(`  curl http://localhost:3003/_monitor/metrics`);
    console.log('\nConfiguration files saved in:', CONFIG_DIR);
  }).catch(console.error);
}