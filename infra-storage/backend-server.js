// minimal-backend.js - Minimal backend with consistent behavior for monitor testing

const http = require('http');
const crypto = require('crypto');

// Configuration
const PORT = process.env.PORT || 3000;
const HOSTNAME = process.env.HOSTNAME || '0.0.0.0';

// Server start time for uptime calculation
const startTime = Date.now();
let requestCount = 0;

// Generate consistent payload (1KB of structured data)
function generatePayload(requestId) {
  // Create a consistent structure with some real data
  const payload = {
    status: 'success',
    timestamp: Date.now(),
    requestId: requestId,
    server: {
      name: 'minimal-backend',
      version: '1.0.0',
      uptime: Date.now() - startTime,
      processed: requestCount
    },
    data: {
      // Add some structured data to reach ~1KB
      items: [],
      metadata: {
        generated: new Date().toISOString(),
        hash: null
      }
    }
  };
  
  // Fill with consistent data structure (not random, but deterministic)
  for (let i = 0; i < 20; i++) {
    payload.data.items.push({
      id: i,
      value: `item-${i}`,
      attributes: {
        created: Date.now() - (i * 1000),
        status: 'active',
        category: `cat-${i % 5}`
      }
    });
  }
  
  // Add a hash of the content (real computation, but minimal)
  const contentHash = crypto.createHash('sha256')
    .update(JSON.stringify(payload.data.items))
    .digest('hex');
  
  payload.data.metadata.hash = contentHash;
  
  return payload;
}

// Parse request body if needed
async function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        resolve({});
      }
    });
    req.on('error', () => resolve({}));
  });
}

// Create server
const server = http.createServer(async (req, res) => {
  const requestId = crypto.randomBytes(8).toString('hex');
  requestCount++;
  
  // Minimal logging
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - Request #${requestCount}`);
  
  // Standard headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('X-Request-ID', requestId);
  
  // Handle OPTIONS for CORS
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }
  
  // Small computation to create consistent minimal latency (5-10ms)
  // This is real work, not artificial delay
  const iterations = 100;
  let hash = requestId;
  for (let i = 0; i < iterations; i++) {
    hash = crypto.createHash('md5').update(hash).digest('hex');
  }
  
  // All endpoints return similar payload
  let responsePayload;
  
  if (req.url === '/health') {
    // Minimal health check
    responsePayload = {
      status: 'healthy',
      timestamp: Date.now(),
      uptime: Date.now() - startTime
    };
    
  } else if (req.method === 'POST') {
    // For POST requests, echo back some of the body
    const body = await parseBody(req);
    responsePayload = generatePayload(requestId);
    responsePayload.echo = {
      received: Object.keys(body).length > 0,
      keys: Object.keys(body)
    };
    
  } else {
    // Default response for all other requests
    responsePayload = generatePayload(requestId);
  }
  
  // Always return 200 OK with consistent payload
  res.statusCode = 200;
  const responseBody = JSON.stringify(responsePayload, null, 2);
  
  // Set content length header
  res.setHeader('Content-Length', Buffer.byteLength(responseBody));
  
  // Send response
  res.end(responseBody);
});

// Start server
server.listen(PORT, HOSTNAME, () => {
  console.log(`\n✅ Minimal Backend Server Started`);
  console.log(`📍 Listening on: http://${HOSTNAME}:${PORT}`);
  console.log(`📊 Behavior:`);
  console.log(`   - Consistent ~1KB JSON responses`);
  console.log(`   - Minimal processing (5-10ms natural latency)`);
  console.log(`   - No artificial delays or failures`);
  console.log(`   - Always returns 200 OK`);
  console.log(`\n🎯 Purpose: Testing monitor performance, not backend\n`);
});

// Basic error handling
server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`❌ Port ${PORT} is already in use`);
  } else {
    console.error('❌ Server error:', error);
  }
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log(`\n📊 Shutting down... Served ${requestCount} requests`);
  server.close(() => {
    process.exit(0);
  });
});