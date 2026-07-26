FROM python:3.11-slim

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

# Create data directory for SQLite
RUN mkdir -p /app/data

# Non-root user for security
RUN useradd -m -u 1000 agora && chown -R agora:agora /app
USER agora

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["uvicorn", "agora.api_server:app", "--host", "0.0.0.0", "--port", "8000"]
