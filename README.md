# Verifiable SLA Monitoring

TEE-based monitors + zkVM proofs for verifiable SLA compliance.

## Components

### `/monitors` - TEE-based Measurement Collection
- **`/active`** - Probes service endpoints at intervals
- **`/passive`** - Proxies traffic between client and service

### `/infra-storage` - Evidence Storage
- Backend server for EVM-based blockchain + IPFS storage

### `/sla-contracts` - Smart Contracts
- `SLAEvidenceRegistry.sol` - On-chain evidence commits
- `SLAConfiguration.sol` - SLA parameters

### `/slo-engine` - Zero-Knowledge Proof Generation
- **`/batch-sli`** - Batch verification strategy
- **`/individual-sli`** - Individual violation proofs

## Setup

### 1. Start Storage
```bash
cd infra-storage
docker-compose up -d
```

### 2. Deploy Contracts
```bash
cd sla-contracts
npm install
npx hardhat test
npx hardhat deploy --network test-network
```

### 3. Run Monitor
```bash
npm install -g phala #install phala network CLI
phala auth login phak_1234

cd monitors/active  # or /passive

phala docker build -i app -t new -f ./Dockerfile
phala docker push -i userx/app:new #userx is the dockerhub user, also update the user in the docker-compose.yml file
phala cvms create -n tee-monitor -c ./docker-compose.yml --vcpu 2 --memory 4096 --disk-size 10 --skip-env
```

### 4. Generate Proofs
```bash
cd slo-engine/batch-sli #for batch measurements /individual-sli for individual violations
cargo run --release
```



## Test Data

Example measurements in: `slo-engine/*/res/`

## Requirements

- Docker
- Node.js 20+
- Rust 1.80+