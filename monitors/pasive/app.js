// Passive Monitor - Intercepts and forwards requests while collecting SLA measurements
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { TappdClient } = require('@phala/dstack-sdk');
const { toViemAccountSecure } = require('@phala/dstack-sdk/viem');
const { MerkleTree } = require('merkletreejs');
const { ethers } = require('ethers');
const axios = require('axios');
const FormData = require('form-data');
const { URL } = require('url');

// Basic startup configuration
const STARTUP_CONFIG = {
  port: process.env.PORT || 3003,
  // These can be overridden by environment variables or will be validated from the loaded config
  providerAddress: "0x3750E62Cadf214A005B771252eE048EAdf72A4Ec",//process.env.PROVIDER_ADDRESS,
  consumerAddress: "0x1dCf74DAaB12e23D6f3016B45000bAb410636FCC",//process.env.CONSUMER_ADDRESS,
  rpcUrl: process.env.RPC_URL || 'http://ec2-xx-xx-xx-xx.us-east-2.compute.amazonaws.com:8545',
  registryAddress: process.env.REGISTRY_ADDRESS || "0x483B5a3A80c1b09c1b6DaAB71f5398ef163F270a",
  evidenceStorageAddress: process.env.EVIDENCE_STORAGE_ADDRESS || "0x483B5a3A80c1b09c1b6DaAB71f5398ef163F270a",
  // IPFS configuration
  ipfsApi: process.env.IPFS_API || 'http://ec2-3-xx-xx-xx.us-east-2.compute.amazonaws.com:5001',
  ipfsGateway: process.env.IPFS_GATEWAY || 'http://ec2-3-xx-xx-xx.us-east-2.compute.amazonaws.com:8080',
  // Development mode flag
  useMockTEE: false //process.env.USE_MOCK_TEE !== 'false' // Default to true for development
};

// Monitor state - OPTIMIZED VERSION
const monitor = {
  // Initial state - waiting for configuration
  state: 'WAITING_FOR_CONFIG',
  configLoaded: false,
  configLoadedAt: null,
  
  // Configuration (loaded via endpoint)
  config: null,
  
  // TEE and crypto
  tappdClient: null,
  privateKey: null,
  publicKey: null,
  ethAccount: null,
  attestationQuote: null,
  
  // Monitoring data - OPTIMIZED
  merkleLeaves: [],  // Only store hashes, not full measurements
  batchStats: {      // Accumulate statistics incrementally
    count: 0,
    successful: 0,
    failed: 0,
    slaViolations: 0,
    totalLatency: 0,
    successfulCount: 0,
    methods: {},
    startTime: null,
    endTime: null
  },
  
  batchSequence: 0,
  requestCount: 0,
  batchHistory: [],
  startTime: Date.now(),
  
  // IPFS storage
  ipfsCids: [],
  
  // Request tracking (for async operations)
  activeRequests: new Map(),
  
  // Optional: Store only recent measurements for debugging
  recentMeasurements: [], // Circular buffer
  maxRecentMeasurements: 100
};

// IPFS helper function
async function ipfsAdd(data) {
  try {
    const formData = new FormData();
    const content = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    
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

// Verify configuration signatures
async function verifyConfiguration(config) {
  if (!config.providerSignature || !config.consumerSignature) {
    throw new Error('Configuration missing required signatures');
  }
  
  // If addresses are provided in config, use them for validation
  if (config.providerAddress && config.consumerAddress) {
    // If startup config doesn't have addresses, use the ones from config
    if (!STARTUP_CONFIG.providerAddress) {
      STARTUP_CONFIG.providerAddress = config.providerAddress;
      console.log(`Using provider address from config: ${config.providerAddress}`);
    }
    if (!STARTUP_CONFIG.consumerAddress) {
      STARTUP_CONFIG.consumerAddress = config.consumerAddress;
      console.log(`Using consumer address from config: ${config.consumerAddress}`);
    }
  }
  
  // Check if we have addresses to verify against
  if (!STARTUP_CONFIG.providerAddress || !STARTUP_CONFIG.consumerAddress) {
    console.warn('WARNING: No provider/consumer addresses set.');
    console.warn('Trusting addresses from configuration without verification.');
    console.warn('In production, always set PROVIDER_ADDRESS and CONSUMER_ADDRESS!');
    
    // Trust the addresses from config
    STARTUP_CONFIG.providerAddress = config.providerAddress;
    STARTUP_CONFIG.consumerAddress = config.consumerAddress;
    return true;
  }
  
  // Extract the data that should have been signed
  const signedData = {
    schemaVersion: config.schemaVersion,
    backendUrl: config.backendUrl,
    backendTimeout: config.backendTimeout,
    measurementInterval: config.measurementInterval,
    aesKey: config.aesKey,
    ttlDays: config.ttlDays,
    aggregatorEndpoint: config.aggregatorEndpoint,
    slaDefinition: config.slaDefinition
  };
  
  const configJson = JSON.stringify(signedData);
  const configHash = ethers.keccak256(ethers.toUtf8Bytes(configJson));
  
  const providerAddress = ethers.verifyMessage(configHash, config.providerSignature);
  if (providerAddress.toLowerCase() !== config.providerAddress.toLowerCase()) {
    throw new Error('Invalid provider signature');
  }
  
  if (STARTUP_CONFIG.providerAddress.toLowerCase() !== providerAddress.toLowerCase()) {
    throw new Error(`Provider address mismatch. Expected: ${STARTUP_CONFIG.providerAddress}, Got: ${providerAddress}`);
  }
  
  const consumerAddress = ethers.verifyMessage(configHash, config.consumerSignature);
  if (consumerAddress.toLowerCase() !== config.consumerAddress.toLowerCase()) {
    throw new Error('Invalid consumer signature');
  }
  
  if (STARTUP_CONFIG.consumerAddress.toLowerCase() !== consumerAddress.toLowerCase()) {
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
  
  if (STARTUP_CONFIG.useMockTEE) {
    console.log('Running in MOCK TEE mode (development)');
    
    monitor.tappdClient = {
      isReachable: async () => true,
      info: async () => ({ version: 'mock-tee-1.0', mode: 'development' }),
      deriveKey: async (id) => {
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
    
    const { generateKeyPairSync } = require('crypto');
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    
    monitor.privateKey = privateKey;
    monitor.publicKey = crypto.createPublicKey(publicKey);
    
    const mockKeyResult = {
      key: privateKey,
      certificate_chain: [publicKey],
      asUint8Array: () => Buffer.from(privateKey)
    };
    
    try {
      monitor.ethAccount = toViemAccountSecure(mockKeyResult);
    } catch (e) {
      const { privateKeyToAccount } = require('viem/accounts');
      const devPrivateKey = '0x' + crypto.randomBytes(32).toString('hex');
      monitor.ethAccount = privateKeyToAccount(devPrivateKey);
    }
    
    console.log('Mock TEE initialized');
    console.log('Development Ethereum address:', monitor.ethAccount.address);
    
  } else {
    monitor.tappdClient = new TappdClient();
    const info = await monitor.tappdClient.info();
    console.log('TEE Base Image Info:', info);
    
    const isReachable = await monitor.tappdClient.isReachable();
    if (!isReachable) {
      console.warn('WARNING: TEE service not reachable, running in simulation mode');
    }
    
    try {
      const keyResult = await monitor.tappdClient.deriveKey('monitor-key');
      console.log('Key derivation successful');
      
      monitor.keyResult = keyResult;
      monitor.privateKey = keyResult.key;
      
      if (keyResult.certificate_chain && keyResult.certificate_chain.length > 0) {
        const certificate = keyResult.certificate_chain[0];
        monitor.publicKey = crypto.createPublicKey({
          key: certificate,
          format: 'pem'
        });
        console.log('Public key extracted from certificate');
      } else {
        monitor.publicKey = crypto.createPublicKey(monitor.privateKey);
        console.log('Public key derived from private key');
      }
      
      monitor.ethAccount = toViemAccountSecure(keyResult);
      console.log('Monitor Ethereum address:', monitor.ethAccount.address);
      
    } catch (error) {
      console.error('TEE key derivation failed:', error);
      console.log('Running in development mode without TEE');
      
      const { generateKeyPairSync } = require('crypto');
      const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      monitor.privateKey = privateKey;
      monitor.publicKey = crypto.createPublicKey(publicKey);
      
      const { privateKeyToAccount } = require('viem/accounts');
      const devPrivateKey = '0x' + crypto.randomBytes(32).toString('hex');
      monitor.ethAccount = privateKeyToAccount(devPrivateKey);
      console.log('Development Ethereum address:', monitor.ethAccount.address);
    }
  }
  
  const attestationData = {
    timestamp: Date.now(),
    configHash: crypto.createHash('sha256').update(JSON.stringify(monitor.config)).digest('hex'),
    config: {
      backendUrl: monitor.config.backendUrl,
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

// Start passive monitoring
async function startPassiveMonitoring() {
  console.log('Starting passive monitoring...');
  console.log(`Backend: ${monitor.config.backendUrl}`);
  console.log(`Timeout: ${monitor.config.backendTimeout}ms`);
  
  // Start batch sealing timer
  setInterval(async () => {
    if (monitor.merkleLeaves.length > 0) {
      await sealAndPublishBatch();
    }
  }, monitor.config.measurementInterval || 60000); // Default 1 minute
  
  monitor.state = 'ACTIVE';
  console.log('Passive monitor is now ACTIVE');
}

// OPTIMIZED: Record measurement without storing full object
function recordMeasurement(measurement) {
  // Update statistics incrementally (no need to store full measurement)
  if (monitor.batchStats.count === 0) {
    monitor.batchStats.startTime = measurement.timestamp;
  }
  monitor.batchStats.endTime = measurement.timestamp;
  monitor.batchStats.count++;
  
  if (measurement.success) {
    monitor.batchStats.successful++;
    if (measurement.latency > 0) {
      monitor.batchStats.totalLatency += measurement.latency;
      monitor.batchStats.successfulCount++;
    }
  } else {
    monitor.batchStats.failed++;
  }
  
  if (!measurement.slaCompliant) {
    monitor.batchStats.slaViolations++;
  }
  
  monitor.batchStats.methods[measurement.method] = 
    (monitor.batchStats.methods[measurement.method] || 0) + 1;
  
  // Only store the hash for Merkle tree
  monitor.merkleLeaves.push(Buffer.from(measurement.hash, 'hex'));
  
  // Optional: Keep recent measurements for debugging
  monitor.recentMeasurements.push({
    timestamp: measurement.timestamp,
    method: measurement.method,
    path: measurement.path,
    statusCode: measurement.statusCode,
    latency: measurement.latency,
    slaCompliant: measurement.slaCompliant
  });
  
  if (monitor.recentMeasurements.length > monitor.maxRecentMeasurements) {
    monitor.recentMeasurements.shift(); // Remove oldest
  }
  
  // Log without storing
  console.log(`[${new Date().toISOString()}] ${measurement.method} ${measurement.path}: ${measurement.statusCode} (${measurement.latency}ms) ${measurement.slaCompliant ? '✓' : '✗ SLA VIOLATION'}`);
}

// Forward request to backend and measure
async function forwardRequest(req, res) {
  const requestId = crypto.randomBytes(16).toString('hex');
  const startTime = Date.now();
  
  // Parse backend URL
  const backendUrl = new URL(monitor.config.backendUrl);
  const isHttps = backendUrl.protocol === 'https:';
  
  // Build target URL
  const targetUrl = new URL(req.url, monitor.config.backendUrl);
  
  // Prepare measurement
  const measurement = {
    timestamp: startTime,
    requestId: requestId,
    method: req.method,
    path: req.url,
    endpoint: targetUrl.href,
    headers: req.headers,
    clientIp: req.connection.remoteAddress
  };
  
  // Track active request
  monitor.activeRequests.set(requestId, measurement);
  monitor.requestCount++;
  
  // Forward request options
  const proxyOptions = {
    hostname: backendUrl.hostname,
    port: backendUrl.port || (isHttps ? 443 : 80),
    path: targetUrl.pathname + targetUrl.search,
    method: req.method,
    headers: {
      ...req.headers,
      'X-Forwarded-For': req.connection.remoteAddress,
      'X-Monitor-Request-ID': requestId,
      'X-Monitor-Timestamp': startTime.toString(),
      host: backendUrl.host // Override host header
    },
    timeout: monitor.config.backendTimeout || 30000
  };
  
  // Create proxy request
  const proxyModule = isHttps ? https : http;
  const proxyReq = proxyModule.request(proxyOptions, (proxyRes) => {
    const responseTime = Date.now() - startTime;
    
    // Update measurement with response
    measurement.statusCode = proxyRes.statusCode;
    measurement.latency = responseTime;
    measurement.success = proxyRes.statusCode >= 200 && proxyRes.statusCode < 400;
    measurement.responseHeaders = proxyRes.headers;
    
    // Check SLA compliance
    measurement.slaCompliant = checkSLACompliance(measurement);
    
    // Add hash
    measurement.hash = crypto.createHash('sha256')
      .update(JSON.stringify(measurement))
      .digest('hex');
    
    // OPTIMIZED: Record measurement without storing full object
    recordMeasurement(measurement);
    monitor.activeRequests.delete(requestId);
    
    // Check if batch is full
    if (monitor.merkleLeaves.length >= (monitor.config.batchSizeSeal || 1024)) {
      setImmediate(() => sealAndPublishBatch());
    }
    
    // Forward response to client
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });
  
  // Handle proxy errors
  proxyReq.on('error', (error) => {
    const responseTime = Date.now() - startTime;
    
    measurement.statusCode = 502;
    measurement.latency = responseTime;
    measurement.success = false;
    measurement.error = error.message;
    measurement.slaCompliant = false;
    
    measurement.hash = crypto.createHash('sha256')
      .update(JSON.stringify(measurement))
      .digest('hex');
    
    recordMeasurement(measurement);
    monitor.activeRequests.delete(requestId);
    
    // Return error to client
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      error: 'Bad Gateway', 
      message: 'Backend server error',
      requestId: requestId 
    }));
  });
  
  // Handle timeout
  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    const responseTime = Date.now() - startTime;
    
    measurement.statusCode = 504;
    measurement.latency = responseTime;
    measurement.success = false;
    measurement.error = 'Gateway timeout';
    measurement.slaCompliant = false;
    
    measurement.hash = crypto.createHash('sha256')
      .update(JSON.stringify(measurement))
      .digest('hex');
    
    recordMeasurement(measurement);
    monitor.activeRequests.delete(requestId);
    
    res.writeHead(504, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      error: 'Gateway Timeout',
      requestId: requestId 
    }));
  });
  
  // Forward request body if present
  req.pipe(proxyReq);
}

// Check SLA compliance based on configuration
function checkSLACompliance(measurement) {
  if (!monitor.config.slaDefinition) return true;
  
  const sla = monitor.config.slaDefinition;
  
  // Check latency SLA
  if (sla.maxLatencyMs && measurement.latency > sla.maxLatencyMs) {
    return false;
  }
  
  // Check availability SLA (non-5xx errors)
  if (measurement.statusCode >= 500) {
    return false;
  }
  
  // Check specific status codes if defined
  if (sla.acceptableStatusCodes && !sla.acceptableStatusCodes.includes(measurement.statusCode)) {
    return false;
  }
  
  return true;
}

// OPTIMIZED: Seal and publish batch without storing full measurements
async function sealAndPublishBatch() {
  if (monitor.merkleLeaves.length === 0) return;
  
  console.log(`\n=== Sealing Batch ${monitor.batchSequence} ===`);
  console.log(`Measurements in batch: ${monitor.merkleLeaves.length}`);
  
  try {
    // Use the already-created leaf hashes
    const hashFunction = (data) => {
      return crypto.createHash('sha256').update(data).digest();
    };
    
    const merkleTree = new MerkleTree(monitor.merkleLeaves, hashFunction);
    const merkleRoot = merkleTree.getRoot().toString('hex');
    
    console.log('\nMerkle Tree Details:');
    console.log(`  Root: ${merkleRoot}`);
    console.log(`  Leaves: ${monitor.merkleLeaves.length}`);
    
    // Sign the root
    const sign = crypto.createSign('SHA256');
    sign.update(merkleRoot);
    const signature = sign.sign(monitor.privateKey, 'hex');
    
    console.log(`  Signature: ${signature.substring(0, 64)}...`);
    
    // Calculate final statistics
    const avgLatency = monitor.batchStats.successfulCount > 0 
      ? Math.round(monitor.batchStats.totalLatency / monitor.batchStats.successfulCount)
      : 0;
    
    const slaComplianceRate = monitor.batchStats.count > 0
      ? ((monitor.batchStats.count - monitor.batchStats.slaViolations) / monitor.batchStats.count * 100).toFixed(2) + '%'
      : '100%';
    
    // Create batch summary (no full measurements or encrypted data)
    const batchSummary = {
      version: '1.0.0',
      batchSequence: monitor.batchSequence,
      merkleRoot: merkleRoot,
      signature: signature,
      metadata: {
        measurements: monitor.batchStats.count,
        startTime: monitor.batchStats.startTime,
        endTime: monitor.batchStats.endTime,
        statistics: {
          successful: monitor.batchStats.successful,
          failed: monitor.batchStats.failed,
          slaViolations: monitor.batchStats.slaViolations,
          slaComplianceRate: slaComplianceRate,
          avgLatency: avgLatency,
          methods: monitor.batchStats.methods
        }
      },
      monitorAddress: monitor.ethAccount ? monitor.ethAccount.address : 'not-initialized',
      timestamp: new Date().toISOString()
    };
    
    console.log('\nBatch Statistics:');
    console.log(JSON.stringify(batchSummary.metadata.statistics, null, 2));
    
    // Store to IPFS if available
    let manifestCid = null;
    const ipfsAvailable = await checkIPFS();
    
    if (ipfsAvailable) {
      console.log('\nStoring summary in IPFS...');
      manifestCid = await ipfsAdd(batchSummary);
      console.log(`  Manifest CID: ${manifestCid}`);
      console.log(`  View at: ${STARTUP_CONFIG.ipfsGateway}/ipfs/${manifestCid}`);
      
      monitor.ipfsCids.push({
        batchSequence: monitor.batchSequence,
        manifestCid,
        timestamp: new Date().toISOString()
      });
    } else {
      console.log('\nIPFS not available - storing summary locally only');
    }
    
    // Store batch summary in history
    monitor.batchHistory.push({
      ...batchSummary.metadata,
      batchSequence: monitor.batchSequence,
      merkleRoot: merkleRoot,
      signature: signature.substring(0, 64) + '...',
      ipfsCid: manifestCid
    });
    
    if (monitor.batchHistory.length > 10) {
      monitor.batchHistory.shift();
    }
    
    if (STARTUP_CONFIG.evidenceStorageAddress && manifestCid) {
      console.log('\nWould submit to blockchain at:', STARTUP_CONFIG.evidenceStorageAddress);
      console.log('  With IPFS CID:', manifestCid);
    }
    
    // IMPORTANT: Clear arrays to free memory
    monitor.merkleLeaves = [];
    monitor.batchStats = {
      count: 0,
      successful: 0,
      failed: 0,
      slaViolations: 0,
      totalLatency: 0,
      successfulCount: 0,
      methods: {},
      startTime: null,
      endTime: null
    };
    
    monitor.batchSequence++;
    
    // Force garbage collection if available (run with node --expose-gc)
    if (global.gc) {
      global.gc();
      console.log('\nMemory garbage collected');
    }
    
    console.log('\nBatch sealed successfully!\n');
    
  } catch (error) {
    console.error('Error sealing batch:', error);
    
    // Still clear arrays on error to prevent memory buildup
    monitor.merkleLeaves = [];
    monitor.batchStats = {
      count: 0,
      successful: 0,
      failed: 0,
      slaViolations: 0,
      totalLatency: 0,
      successfulCount: 0,
      methods: {},
      startTime: null,
      endTime: null
    };
  }
}

// HTTP Server
const server = http.createServer(async (req, res) => {
  // Handle monitor endpoints
  if (req.url.startsWith('/_monitor/')) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'application/json');
    
    console.log(`[Monitor] ${req.method} ${req.url}`);
    
    try {
      // Load configuration endpoint
      if (req.url === '/_monitor/loadconfig' && req.method === 'POST') {
        if (monitor.configLoaded) {
          res.statusCode = 403;
          res.end(JSON.stringify({ 
            error: 'Configuration already loaded',
            loadedAt: monitor.configLoadedAt
          }));
          return;
        }
        
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
          try {
            const config = JSON.parse(body);
            
            await verifyConfiguration(config);

            console.log("Config Loaded:")
            console.log(config)
            
            monitor.config = config;
            monitor.configLoaded = true;
            monitor.configLoadedAt = new Date().toISOString();
            monitor.state = 'INITIALIZING';
            
            console.log('Configuration loaded and verified');
            
            await initializeTEE();
            await startPassiveMonitoring();
            
            res.statusCode = 200;
            res.end(JSON.stringify({ 
              success: true,
              message: 'Configuration loaded and passive monitoring started',
              configHash: crypto.createHash('sha256').update(JSON.stringify(config)).digest('hex'),
              backendUrl: config.backendUrl
            }));
          } catch (error) {
            console.error('Failed to load configuration:', error);
            res.statusCode = 400;
            res.end(JSON.stringify({ error: error.message }));
          }
        });
        
      // Status endpoint
      } else if (req.url === '/_monitor/status' && req.method === 'GET') {
        const status = {
          state: monitor.state,
          uptime: Date.now() - monitor.startTime,
          configLoaded: monitor.configLoaded,
          configLoadedAt: monitor.configLoadedAt
        };
        
        if (monitor.state === 'ACTIVE') {
          status.monitoring = {
            backendUrl: monitor.config.backendUrl,
            totalRequests: monitor.requestCount,
            activeRequests: monitor.activeRequests.size,
            batchSequence: monitor.batchSequence,
            pendingMeasurements: monitor.merkleLeaves.length,
            currentBatchStats: monitor.batchStats
          };
          
          // Calculate statistics from batch history
          if (monitor.batchHistory.length > 0) {
            const latestBatch = monitor.batchHistory[monitor.batchHistory.length - 1];
            status.latestBatchStats = latestBatch.statistics;
          }
        }
        
        res.statusCode = 200;
        res.end(JSON.stringify(status, null, 2));
        
      // Attestation endpoint
      } else if (req.url === '/_monitor/attestation' && req.method === 'GET') {
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
            backendUrl: monitor.config.backendUrl,
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
      } else if (req.url === '/_monitor/metrics' && req.method === 'GET') {
        if (monitor.state !== 'ACTIVE') {
          res.statusCode = 503;
          res.end(JSON.stringify({ error: 'Monitor not active' }));
          return;
        }
        
        res.statusCode = 200;
        res.end(JSON.stringify({
          totalRequests: monitor.requestCount,
          activeRequests: monitor.activeRequests.size,
          currentBatchSize: monitor.merkleLeaves.length,
          currentBatchStats: monitor.batchStats,
          batchHistory: monitor.batchHistory,
          recentMeasurements: monitor.recentMeasurements
        }, null, 2));
        
      // Batch history endpoint
      } else if (req.url === '/_monitor/batches' && req.method === 'GET') {
        res.statusCode = 200;
        res.end(JSON.stringify({
          currentBatch: monitor.batchSequence,
          pendingMeasurements: monitor.merkleLeaves.length,
          currentStats: monitor.batchStats,
          batchHistory: monitor.batchHistory || [],
          ipfsCids: monitor.ipfsCids || []
        }, null, 2));
        
      // IPFS CIDs endpoint
      } else if (req.url === '/_monitor/ipfs' && req.method === 'GET') {
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
      console.error('Monitor endpoint error:', error);
      res.statusCode = 500;
      res.end(JSON.stringify({ error: error.message }));
    }
  } else {
    // Forward all other requests to backend (when configured and active)
    if (monitor.state === 'ACTIVE') {
      await forwardRequest(req, res);
    } else {
      res.statusCode = 503;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ 
        error: 'Service Unavailable',
        message: 'Passive monitor not yet configured',
        state: monitor.state
      }));
    }
  }
});

// Start server
server.listen(STARTUP_CONFIG.port, async () => {
  console.log(`\nPassive Monitor Server Started (OPTIMIZED VERSION)`);
  console.log(`Port: ${STARTUP_CONFIG.port}`);
  console.log(`State: ${monitor.state}`);
  console.log(`Mode: ${STARTUP_CONFIG.useMockTEE ? 'MOCK TEE (Development)' : 'REAL TEE'}`);
  
  const ipfsAvailable = await checkIPFS();
  if (ipfsAvailable) {
    console.log(`IPFS API: ${STARTUP_CONFIG.ipfsApi}`);
    console.log(`IPFS Gateway: ${STARTUP_CONFIG.ipfsGateway}`);
  } else {
    console.log('IPFS: Not available (batches will be stored locally only)');
  }
  
  console.log('\nMonitor Endpoints:');
  console.log('  POST /_monitor/loadconfig  - Load configuration (one-time use)');
  console.log('  GET  /_monitor/status      - Monitor status');
  console.log('  GET  /_monitor/attestation - TEE attestation');
  console.log('  GET  /_monitor/metrics     - Request metrics');
  console.log('  GET  /_monitor/batches     - View batch history');
  console.log('  GET  /_monitor/ipfs        - View IPFS CIDs\n');
  
  console.log('All other requests will be forwarded to the configured backend');
  console.log('after configuration is loaded.\n');
  
  if (STARTUP_CONFIG.useMockTEE) {
    console.log('⚠️  Running in MOCK TEE mode - for development only!');
    console.log('   Set USE_MOCK_TEE=false for production\n');
  }
  
  console.log('Memory optimization: Only storing hashes, not full measurements');
  console.log('Run with: node --expose-gc passive-monitor.js for manual GC\n');
  
  console.log('Waiting for configuration...');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down...');
  server.close();
  process.exit(0);
});