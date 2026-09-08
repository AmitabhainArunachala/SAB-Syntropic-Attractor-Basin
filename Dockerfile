FROM python:3.11-slim AS runtime

WORKDIR /app

ARG SAB_BUILD_SHA=unknown
ENV SAB_BUILD_SHA=${SAB_BUILD_SHA}
LABEL org.opencontainers.image.revision=${SAB_BUILD_SHA}

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY agora/ agora/
COPY site/*.md site/
COPY site/data/seed_claims.json site/data/seed_claims.json
COPY nodes/schemas/ nodes/schemas/

# Create data directory for SQLite
RUN mkdir -p /app/data

# Non-root user for security
RUN useradd -m -u 1000 agora && chown -R agora:agora /app
USER agora

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

FROM runtime AS public
ENV SAB_PUBLIC_MODE=public_readonly PYTHONDONTWRITEBYTECODE=1
CMD ["uvicorn", "agora.app:app", "--host", "0.0.0.0", "--port", "8000"]

# Keep the existing protocol/admin image as the default target. Public website
# deployments select --target public explicitly.
FROM runtime AS protocol
CMD ["uvicorn", "agora.api_server:app", "--host", "0.0.0.0", "--port", "8000"]
