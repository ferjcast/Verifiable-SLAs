// Active Monitor with One-Time Configuration Loading
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { TappdClient } = require('@phala/dstack-sdk');
const { toViemAccountSecure } = require('@phala/dstack-sdk/viem');
const { MerkleTree } = require('merkletreejs');
const { ethers } = require('ethers');
const axios = require('axios');
const FormData = require('form-data');

// Basic startup configuration
const STARTUP_CONFIG = {
  port: process.env.PORT || 3002,
  // These MUST match the addresses that signed the configuration
  providerAddress: "0xDaDF53ecC932e869c3b6307E95af851232d062e3",//process.env.PROVIDER_ADDRESS, // Required for signature verification
  consumerAddress: "0xbfAf1A45bc16166BC426d1231F18833fB98bB6C2",//process.env.CONSUMER_ADDRESS, // Required for signature verification
  rpcUrl: process.env.RPC_URL || 'http://localhost:8545',
  registryAddress:  "0x483B5a3A80c1b09c1b6DaAB71f5398ef163F270a",//process.env.REGISTRY_ADDRESS,
  evidenceStorageAddress:  "0x483B5a3A80c1b09c1b6DaAB71f5398ef163F270a",
  // IPFS configuration
  ipfsApi: process.env.IPFS_API || 'http://localhost:5001',
  ipfsGateway: process.env.IPFS_GATEWAY || 'http://localhost:8080',
  // Development mode flag
  useMockTEE: true//process.env.USE_MOCK_TEE === 'true' || process.env.NODE_ENV === 'development'
};

// Monitor state
const monitor = {
  // Initial state - waiting for configuration
  state: 'WAITING_FOR_CONFIG', // WAITING_FOR_CONFIG -> INITIALIZING -> ACTIVE
  configLoaded: false,
  configLoadedAt: null,
  
  // Configuration (loaded via endpoint)
  config: null,
  
  // TEE and crypto
  tappdClient: null,
  privateKey: null,
  publicKey: null,
  ethAccount: null, // Viem account for blockchain operations
  attestationQuote: null,
  
  // Monitoring data
  measurements: [],
  batchSequence: 0,
  probeInterval: null,
  probeHistory: [],
  batchHistory: [], // Store batch summaries for debugging
  startTime: Date.now(),
  
  // IPFS storage
  ipfsCids: [] // Store CIDs of batches
};

// IPFS helper function
async function ipfsAdd(data) {
  try {
    const formData = new FormData();
    const content = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    
    // In Node.js, append Buffer directly with options
    formData.append('file', Buffer.from(content), {
      filename: 'data.json',
      contentType: 'application/json'
    });
    
    const response = await axios.post(`${STARTUP_CONFIG.ipfsApi}/api/v0/add`, formData, {
      headers: {
        ...formData.getHeaders()
      }
    });
    
    return response.data.Hash;
  } catch (error) {
    console.error('IPFS add error:', error.message);
    throw error;
  }
}

// Verify IPFS is running
async function checkIPFS() {
  try {
    const response = await axios.post(`${STARTUP_CONFIG.ipfsApi}/api/v0/version`);
    console.log(`IPFS connected: version ${response.data.Version}`);
    return true;
  } catch (error) {
    console.warn('IPFS not available:', error.message);
    return false;
  }
}

// Remove IPFS initialization line
// monitor.ipfs = create({ url: CONFIG.ipfsUrl });

// Verify configuration signatures
async function verifyConfiguration(config) {
  if (!config.providerSignature || !config.consumerSignature) {
    throw new Error('Configuration missing required signatures');
  }
  
  // Check if we have addresses to verify against
  if (!STARTUP_CONFIG.providerAddress || !STARTUP_CONFIG.consumerAddress) {
    console.warn('WARNING: No provider/consumer addresses set in environment.');
    console.warn('Trusting addresses from configuration without verification.');
    console.warn('In production, always set PROVIDER_ADDRESS and CONSUMER_ADDRESS!');
    return true;
  }
  
  // Extract the data that should have been signed
  const signedData = {
    schemaVersion: config.schemaVersion,
    targetEndpoints: config.targetEndpoints,
    measurementInterval: config.measurementInterval,
    aesKey: config.aesKey,
    ttlDays: config.ttlDays,
    aggregatorEndpoint: config.aggregatorEndpoint,
    slaDefinition: config.slaDefinition
  };
  
  const configJson = JSON.stringify(signedData);
  const configHash = ethers.keccak256(ethers.toUtf8Bytes(configJson));
  
  // Verify provider signature
  const providerAddress = ethers.verifyMessage(configHash, config.providerSignature);
  if (providerAddress.toLowerCase() !== config.providerAddress.toLowerCase()) {
    throw new Error('Invalid provider signature');
  }
  
  // Verify provider is the expected one
  if (providerAddress.toLowerCase() !== STARTUP_CONFIG.providerAddress.toLowerCase()) {
    throw new Error(`Provider address mismatch. Expected: ${STARTUP_CONFIG.providerAddress}, Got: ${providerAddress}`);
  }
  
  // Verify consumer signature  
  const consumerAddress = ethers.verifyMessage(configHash, config.consumerSignature);
  if (consumerAddress.toLowerCase() !== config.consumerAddress.toLowerCase()) {
    throw new Error('Invalid consumer signature');
  }
  
  // Verify consumer is the expected one
  if (consumerAddress.toLowerCase() !== STARTUP_CONFIG.consumerAddress.toLowerCase()) {
    throw new Error(`Consumer address mismatch. Expected: ${STARTUP_CONFIG.consumerAddress}, Got: ${consumerAddress}`);
  }
  
  console.log('Configuration signatures verified successfully');
  console.log(`Provider: ${providerAddress}`);
  console.log(`Consumer: ${consumerAddress}`);
  return true;
}

// Initialize TEE after config is loaded
async function initializeTEE() {
  console.log('Initializing TEE environment...');
  
  // Check if we should use mock TEE
  if (STARTUP_CONFIG.useMockTEE) {
    console.log('Running in MOCK TEE mode (development)');
    
    // Skip real TEE initialization
    monitor.tappdClient = {
      isReachable: async () => true,
      info: async () => ({ version: 'mock-tee-1.0', mode: 'development' }),
      deriveKey: async (id) => {
        // Generate mock key result
        const { generateKeyPairSync } = require('crypto');
        const { privateKey, publicKey } = generateKeyPairSync('ec', {
          namedCurve: 'P-256',
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        
        return {
          key: privateKey,
          certificate_chain: [publicKey],
          asUint8Array: () => Buffer.from(privateKey)
        };
      },
      tdxQuote: async (data, hash) => ({
        quote: 'mock-quote-' + Date.now(),
        event_log: 'mock-event-log',
        replayRtmrs: () => ({ rtmr0: 'mock', rtmr1: 'mock', rtmr2: 'mock' })
      })
    };
    
    // Generate development keys
    const { generateKeyPairSync } = require('crypto');
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    
    monitor.privateKey = privateKey;
    monitor.publicKey = crypto.createPublicKey(publicKey);
    
    // Create mock keyResult for viem account
    const mockKeyResult = {
      key: privateKey,
      certificate_chain: [publicKey],
      asUint8Array: () => Buffer.from(privateKey)
    };
    
    // Create development eth account
    try {
      monitor.ethAccount = toViemAccountSecure(mockKeyResult);
    } catch (e) {
      // Fallback if toViemAccountSecure doesn't work with mock
      const { privateKeyToAccount } = require('viem/accounts');
      const devPrivateKey = '0x' + crypto.randomBytes(32).toString('hex');
      monitor.ethAccount = privateKeyToAccount(devPrivateKey);
    }
    
    console.log('Mock TEE initialized');
    console.log('Development Ethereum address:', monitor.ethAccount.address);
    
  } else {
    // Original TEE initialization code
    monitor.tappdClient = new TappdClient();
    
    // Get TEE info
    const info = await monitor.tappdClient.info();
    console.log('TEE Base Image Info:', info);
    
    // Check if we can reach the TEE service
    const isReachable = await monitor.tappdClient.isReachable();
    if (!isReachable) {
      console.warn('WARNING: TEE service not reachable, running in simulation mode');
    }
    
    try {
      // Generate keys in TEE
      const keyResult = await monitor.tappdClient.deriveKey('monitor-key');
      console.log('Key derivation successful');
      
      // Store the raw key result
      monitor.keyResult = keyResult;
      
      // The private key is directly available as PEM
      monitor.privateKey = keyResult.key;
      
      // Extract public key from the first certificate in the chain
      if (keyResult.certificate_chain && keyResult.certificate_chain.length > 0) {
        const certificate = keyResult.certificate_chain[0];
        monitor.publicKey = crypto.createPublicKey({
          key: certificate,
          format: 'pem'
        });
        console.log('Public key extracted from certificate');
      } else {
        // Fallback: derive public key from private key
        monitor.publicKey = crypto.createPublicKey(monitor.privateKey);
        console.log('Public key derived from private key');
      }
      
      // Create secure Ethereum account from TEE key
      monitor.ethAccount = toViemAccountSecure(keyResult);
      console.log('Monitor Ethereum address:', monitor.ethAccount.address);
      
    } catch (error) {
      console.error('TEE key derivation failed:', error);
      console.log('Running in development mode without TEE');
      
      // Fallback for development without TEE
      const { generateKeyPairSync } = require('crypto');
      const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      monitor.privateKey = privateKey;
      monitor.publicKey = crypto.createPublicKey(publicKey);
      
      // Create a development eth account
      const { privateKeyToAccount } = require('viem/accounts');
      const devPrivateKey = '0x' + crypto.randomBytes(32).toString('hex');
      monitor.ethAccount = privateKeyToAccount(devPrivateKey);
      console.log('Development Ethereum address:', monitor.ethAccount.address);
    }
  }
  
  // Generate attestation quote that includes the loaded configuration
  const attestationData = {
    timestamp: Date.now(),
    configHash: crypto.createHash('sha256').update(JSON.stringify(monitor.config)).digest('hex'),
    config: {
      targetEndpoints: monitor.config.targetEndpoints,
      measurementInterval: monitor.config.measurementInterval,
      slaDefinition: monitor.config.slaDefinition,
      providerAddress: monitor.config.providerAddress,
      consumerAddress: monitor.config.consumerAddress
    },
    monitorAddress: monitor.ethAccount.address
  };
  
  try {
    monitor.attestationQuote = await monitor.tappdClient.tdxQuote(
      JSON.stringify(attestationData),
      'sha256'
    );
    console.log('TDX attestation quote generated');
  } catch (error) {
    console.log('TDX quote generation failed, using mock attestation');
    monitor.attestationQuote = {
      quote: 'mock-quote-' + Date.now(),
      event_log: 'mock-event-log',
      replayRtmrs: () => ({})
    };
  }
  
  console.log('TEE initialization completed');
}

// Start monitoring (called after config is loaded and verified)
async function startMonitoring() {
  console.log('Starting active monitoring...');
  console.log(`Targets: ${monitor.config.targetEndpoints.join(', ')}`);
  console.log(`Interval: ${monitor.config.measurementInterval}ms`);
  
  // Start probe interval
  monitor.probeInterval = setInterval(performHealthChecks, monitor.config.measurementInterval);
  
  // Initial probe
  await performHealthChecks();
  
  // Start batch sealing timer
  setInterval(async () => {
    if (monitor.measurements.length > 0) {
      await sealAndPublishBatch();
    }
  }, 60000); // Every minute
  
  monitor.state = 'ACTIVE';
  console.log('Monitor is now ACTIVE');
}

// Probe endpoint
async function probeEndpoint(endpoint) {
  return new Promise((resolve) => {
    // For test endpoints, just probe the root path instead of /health
    const testEndpoints = ['httpbin.org', 'api.github.com', 'jsonplaceholder.typicode.com'];
    const isTestEndpoint = testEndpoints.some(test => endpoint.includes(test));
    
    const url = new URL(endpoint + (isTestEndpoint ? '' : '/health'));
    const startTime = Date.now();
    
    const client = url.protocol === 'https:' ? https : http;
    
    const req = client.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const latency = Date.now() - startTime;
        resolve({
          endpoint,
          method: 'GET',
          path: url.pathname,
          statusCode: res.statusCode,
          latency,
          timestamp: Date.now(),
          success: res.statusCode >= 200 && res.statusCode < 300
        });
      });
    });
    
    req.on('error', (error) => {
      resolve({
        endpoint,
        method: 'GET',
        path: url.pathname,
        statusCode: 0,
        latency: -1,
        timestamp: Date.now(),
        error: error.message,
        success: false
      });
    });
    
    req.setTimeout(5000, () => {
      req.destroy();
    });
  });
}

// Perform health checks
async function performHealthChecks() {
  console.log(`[${new Date().toISOString()}] Performing health checks...`);
  
  for (const endpoint of monitor.config.targetEndpoints) {
    const measurement = await probeEndpoint(endpoint);
    console.log(`  ${measurement.success ? '✓' : '✗'} ${endpoint}: ${measurement.statusCode} (${measurement.latency}ms)`);
    
    // Add hash
    measurement.hash = crypto.createHash('sha256')
      .update(JSON.stringify(measurement))
      .digest('hex');
    
    // Record measurement
    monitor.measurements.push(measurement);
    monitor.probeHistory.push(measurement);
    
    if (monitor.probeHistory.length > 100) {
      monitor.probeHistory.shift();
    }
    
    // Check if batch is full
    if (monitor.measurements.length >= 1024) {
      await sealAndPublishBatch();
    }
  }
}

// Seal and publish batch (with IPFS)
async function sealAndPublishBatch() {
  if (monitor.measurements.length === 0) return;
  
  console.log(`\n=== Sealing Batch ${monitor.batchSequence} ===`);
  console.log(`Measurements in batch: ${monitor.measurements.length}`);
  
  try {
    // Create Merkle tree from measurement hashes
    const leaves = monitor.measurements.map(m => Buffer.from(m.hash, 'hex'));
    
    // Define hash function for MerkleTree
    const hashFunction = (data) => {
      return crypto.createHash('sha256').update(data).digest();
    };
    
    const merkleTree = new MerkleTree(leaves, hashFunction);
    const merkleRoot = merkleTree.getRoot().toString('hex');
    
    console.log('\nMerkle Tree Details:');
    console.log(`  Root: ${merkleRoot}`);
    console.log(`  Leaves: ${leaves.length}`);
    console.log(`  First leaf: ${monitor.measurements[0].hash}`);
    console.log(`  Last leaf: ${monitor.measurements[monitor.measurements.length - 1].hash}`);
    
    // Sign merkle root
    const sign = crypto.createSign('SHA256');
    sign.update(merkleRoot);
    const signature = sign.sign(monitor.privateKey, 'hex');
    
    console.log(`  Signature: ${signature.substring(0, 64)}...`);
    
    // Encrypt batch
    const aesKey = Buffer.from(monitor.config.aesKey, 'hex');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    
    const plaintext = JSON.stringify(monitor.measurements);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag();
    
    // Create encrypted batch object
    const encryptedBatch = {
      version: '1.0.0',
      batchSequence: monitor.batchSequence,
      merkleRoot: merkleRoot,
      encrypted: {
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        data: encrypted.toString('hex')
      },
      metadata: {
        measurements: monitor.measurements.length,
        startTime: monitor.measurements[0].timestamp,
        endTime: monitor.measurements[monitor.measurements.length - 1].timestamp,
        endpoints: [...new Set(monitor.measurements.map(m => m.endpoint))]
      },
      signature: signature,
      timestamp: new Date().toISOString()
    };
    
    // Store in IPFS if available
    let batchCid = null;
    let manifestCid = null;
    
    const ipfsAvailable = await checkIPFS();
    if (ipfsAvailable) {
      console.log('\nStoring in IPFS...');
      
      // Store encrypted batch
      batchCid = await ipfsAdd(encryptedBatch);
      console.log(`  Batch CID: ${batchCid}`);
      
      // Create and store manifest
      const manifest = {
        type: 'monitor-batch-manifest',
        version: '1.0.0',
        batchCid: batchCid,
        merkleRoot: merkleRoot,
        batchSequence: monitor.batchSequence,
        signature: signature.substring(0, 128) + '...',
        monitorAddress: monitor.ethAccount ? monitor.ethAccount.address : 'not-initialized',
        timestamp: new Date().toISOString()
      };
      
      manifestCid = await ipfsAdd(manifest);
      console.log(`  Manifest CID: ${manifestCid}`);
      console.log(`  View at: ${STARTUP_CONFIG.ipfsGateway}/ipfs/${manifestCid}`);
      
      // Store CIDs
      monitor.ipfsCids.push({
        batchSequence: monitor.batchSequence,
        batchCid,
        manifestCid,
        timestamp: new Date().toISOString()
      });
    } else {
      console.log('\nIPFS not available - storing summary only');
    }
    
    // Create batch summary
    const batchSummary = {
      batchSequence: monitor.batchSequence,
      merkleRoot: merkleRoot,
      signature: signature,
      startTime: monitor.measurements[0].timestamp,
      endTime: monitor.measurements[monitor.measurements.length - 1].timestamp,
      measurements: monitor.measurements.length,
      endpoints: [...new Set(monitor.measurements.map(m => m.endpoint))],
      statistics: {
        successful: monitor.measurements.filter(m => m.success).length,
        failed: monitor.measurements.filter(m => !m.success).length,
        avgLatency: Math.round(
          monitor.measurements
            .filter(m => m.success && m.latency > 0)
            .reduce((sum, m) => sum + m.latency, 0) / 
          monitor.measurements.filter(m => m.success).length
        )
      },
      ipfs: ipfsAvailable ? {
        batchCid,
        manifestCid
      } : null
    };
    
    console.log('\nBatch Summary:');
    console.log(JSON.stringify(batchSummary, null, 2));
    
    // In production, would submit to blockchain here
    if (STARTUP_CONFIG.evidenceStorageAddress) {
      console.log('\nWould submit to blockchain at:', STARTUP_CONFIG.evidenceStorageAddress);
      if (batchCid) {
        console.log('  With IPFS CID:', batchCid);
      }
    }
    
    // Store batch summary in memory for debugging
    monitor.batchHistory.push(batchSummary);
    if (monitor.batchHistory.length > 10) monitor.batchHistory.shift(); // Keep last 10
    
    // Clear measurements for next batch
    monitor.measurements = [];
    monitor.batchSequence++;
    
    console.log('\nBatch sealed successfully!\n');
  } catch (error) {
    console.error('Error sealing batch:', error);
  }
}

// HTTP Server
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');
  
  console.log(`${req.method} ${req.url}`);
  
  try {
    // Load configuration endpoint (one-time use)
    if (req.url === '/loadconfig' && req.method === 'POST') {
      // Check if config already loaded
      if (monitor.configLoaded) {
        res.statusCode = 403;
        res.end(JSON.stringify({ 
          error: 'Configuration already loaded',
          loadedAt: monitor.configLoadedAt
        }));
        return;
      }
      
      // Read configuration from request body
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', async () => {
        try {
          const config = JSON.parse(body);
          
          // Verify configuration signatures
          await verifyConfiguration(config);
          
          // Store configuration
          monitor.config = config;
          monitor.configLoaded = true;
          monitor.configLoadedAt = new Date().toISOString();
          monitor.state = 'INITIALIZING';
          
          console.log('Configuration loaded and verified');
          
          // Initialize TEE with the configuration
          await initializeTEE();
          
          // Start monitoring
          await startMonitoring();
          
          res.statusCode = 200;
          res.end(JSON.stringify({ 
            success: true,
            message: 'Configuration loaded and monitoring started',
            configHash: crypto.createHash('sha256').update(JSON.stringify(config)).digest('hex')
          }));
        } catch (error) {
          console.error('Failed to load configuration:', error);
          res.statusCode = 400;
          res.end(JSON.stringify({ error: error.message }));
        }
      });
      
    // Status endpoint
    } else if (req.url === '/status' && req.method === 'GET') {
      const status = {
        state: monitor.state,
        uptime: Date.now() - monitor.startTime,
        configLoaded: monitor.configLoaded,
        configLoadedAt: monitor.configLoadedAt
      };
      
      if (monitor.state === 'ACTIVE') {
        status.monitoring = {
          endpoints: monitor.config.targetEndpoints,
          interval: monitor.config.measurementInterval,
          batchSequence: monitor.batchSequence,
          pendingMeasurements: monitor.measurements.length,
          totalProbes: monitor.probeHistory.length
        };
        
        // Calculate statistics
        const successCount = monitor.probeHistory.filter(p => p.success).length;
        status.statistics = {
          successRate: monitor.probeHistory.length > 0 ? 
            ((successCount / monitor.probeHistory.length) * 100).toFixed(2) : 0
        };
      }
      
      res.statusCode = 200;
      res.end(JSON.stringify(status, null, 2));
      
    // Attestation endpoint (only available after config loaded)
    } else if (req.url === '/attestation' && req.method === 'GET') {
      if (!monitor.configLoaded) {
        res.statusCode = 503;
        res.end(JSON.stringify({ error: 'Configuration not loaded yet' }));
        return;
      }
      
      const attestationData = {
        timestamp: Date.now(),
        state: monitor.state,
        configHash: crypto.createHash('sha256').update(JSON.stringify(monitor.config)).digest('hex'),
        config: {
          schemaVersion: monitor.config.schemaVersion,
          targetEndpoints: monitor.config.targetEndpoints,
          measurementInterval: monitor.config.measurementInterval,
          slaDefinition: monitor.config.slaDefinition,
          providerSignature: monitor.config.providerSignature,
          consumerSignature: monitor.config.consumerSignature,
          providerAddress: monitor.config.providerAddress,
          consumerAddress: monitor.config.consumerAddress
        }
      };
      
      const currentQuote = await monitor.tappdClient.tdxQuote(
        JSON.stringify(attestationData),
        'sha256'
      );
      
      res.statusCode = 200;
      res.end(JSON.stringify({
        quote: currentQuote.quote,
        eventLog: currentQuote.event_log,
        rtmrs: currentQuote.replayRtmrs(),
        publicKey: monitor.publicKey ? monitor.publicKey.export({ type: 'spki', format: 'pem' }) : 'not-available',
        attestationData: attestationData,
        initialQuote: monitor.attestationQuote
      }, null, 2));
      
    // Metrics endpoint
    } else if (req.url === '/metrics' && req.method === 'GET') {
      if (monitor.state !== 'ACTIVE') {
        res.statusCode = 503;
        res.end(JSON.stringify({ error: 'Monitor not active' }));
        return;
      }
      
      res.statusCode = 200;
      res.end(JSON.stringify({
        recentProbes: monitor.probeHistory.slice(-20)
      }, null, 2));
      
    // Batch history endpoint
    } else if (req.url === '/batches' && req.method === 'GET') {
      res.statusCode = 200;
      res.end(JSON.stringify({
        currentBatch: monitor.batchSequence,
        pendingMeasurements: monitor.measurements.length,
        batchHistory: monitor.batchHistory || [],
        ipfsCids: monitor.ipfsCids || []
      }, null, 2));
      
    // IPFS CIDs endpoint
    } else if (req.url === '/ipfs' && req.method === 'GET') {
      res.statusCode = 200;
      res.end(JSON.stringify({
        ipfsApi: STARTUP_CONFIG.ipfsApi,
        ipfsGateway: STARTUP_CONFIG.ipfsGateway,
        storedBatches: monitor.ipfsCids || [],
        latestManifest: monitor.ipfsCids.length > 0 ? 
          `${STARTUP_CONFIG.ipfsGateway}/ipfs/${monitor.ipfsCids[monitor.ipfsCids.length - 1].manifestCid}` : null
      }, null, 2));
      
    } else {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: 'Not Found' }));
    }
  } catch (error) {
    console.error('Server error:', error);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: error.message }));
  }
});

// Start server
server.listen(STARTUP_CONFIG.port, async () => {
  console.log(`\nActive Monitor Server Started`);
  console.log(`Port: ${STARTUP_CONFIG.port}`);
  console.log(`State: ${monitor.state}`);
  console.log(`Mode: ${STARTUP_CONFIG.useMockTEE ? 'MOCK TEE (Development)' : 'REAL TEE'}`);
  
  // Check IPFS availability
  const ipfsAvailable = await checkIPFS();
  if (ipfsAvailable) {
    console.log(`IPFS API: ${STARTUP_CONFIG.ipfsApi}`);
    console.log(`IPFS Gateway: ${STARTUP_CONFIG.ipfsGateway}`);
  } else {
    console.log('IPFS: Not available (batches will be stored locally only)');
  }
  
  console.log('\nEndpoints:');
  console.log('  POST /loadconfig - Load configuration (one-time use)');
  console.log('  GET  /status     - Monitor status');
  console.log('  GET  /attestation - TEE attestation (after config loaded)');
  console.log('  GET  /metrics    - Recent probe results (when active)');
  console.log('  GET  /batches    - View batch history');
  console.log('  GET  /ipfs       - View IPFS CIDs\n');
  
  if (STARTUP_CONFIG.useMockTEE) {
    console.log('⚠️  Running in MOCK TEE mode - for development only!');
    console.log('   Set USE_MOCK_TEE=false for production\n');
  }
  
  console.log('Waiting for configuration...');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down...');
  if (monitor.probeInterval) {
    clearInterval(monitor.probeInterval);
  }
  server.close();
  process.exit(0);
});