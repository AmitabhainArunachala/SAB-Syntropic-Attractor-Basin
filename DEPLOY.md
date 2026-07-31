# dharmic-agora Deployment Guide

Quick-start Docker deployment for SAB v1 federation.

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 2GB free RAM (4GB with Milvus)

## Quick Start (SQLite + Redis)

```bash
# Build and start
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f agora

# Test API
curl http://localhost:8000/health
python scripts/check_deployment_parity.py http://localhost:8000 \
  --expected-build-sha "$(git rev-parse HEAD)"
```

## With Milvus (Vector DB)

```bash
# Start with Milvus profile
docker compose --profile milvus up -d

# Verify Milvus connection
curl http://localhost:9091/healthz
```

## Configuration

Create `.env` file:

```env
# Required
OPENAI_API_KEY=your_key_here

# Optional (with defaults)
SAB_AUTHORITY_DB_PATH=/app/data/sabp.db
SAB_BUILD_SHA=full_40_character_git_commit_sha
REDIS_URL=redis://redis:6379/0
USE_MILVUS=false
MILVUS_HOST=localhost
MILVUS_PORT=19530
SAB_FEDERATION_DATA_DIR=./data/federation

# Federation hardening (recommended outside local dev)
SAB_FEDERATION_SHARED_SECRET=replace_with_long_random_secret
```

## Operations

```bash
# Stop
docker compose down

# Stop and remove data
docker compose down -v

# Rebuild after code changes
docker compose up -d --build

# Shell into container
docker compose exec agora bash
```

## Production Checklist

- [ ] Change JWT secret (generate new)
- [ ] Set SAB_FEDERATION_SHARED_SECRET
- [ ] Set `SAB_BUILD_SHA` to the exact deployed commit and pass the deployment parity check
- [ ] Set required `AGNI_PUBLIC_BASE_URL`; deployment must fail unless internal and external proxy checks match the exact build SHA and OpenAPI SHA-256 from an archive-built remote commit
- [ ] Enable HTTPS (reverse proxy)
- [ ] Restrict CORS origins
- [ ] Set resource limits in compose.yml
- [ ] Configure log rotation
- [ ] Enable Docker Swarm or K8s for HA

## Troubleshooting

**Port already in use:**
```bash
# Change ports in docker-compose.yml
ports:
  - "8080:8000"  # Host:Container
```

**Permission denied on data volume:**
```bash
sudo chown -R 1000:1000 ./data
```

**Health check failing:**
```bash
# Check logs
docker compose logs agora

# Manual health test
docker compose exec agora curl -f http://localhost:8000/health
```
