# Production-grade, lightweight Dockerfile
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered log streaming
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install security updates and curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install runtime dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and test suite
COPY . .

# Run as non-privileged non-root user (security best practice)
RUN useradd -u 10001 -m appuser && chown -R appuser:appuser /app
USER appuser

# Container Healthcheck verifying core modules load cleanly
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "from url_analyzer import URLAnalyzer; sys.exit(0)" || exit 1

# Default entrypoint
CMD ["python", "main.py"]
