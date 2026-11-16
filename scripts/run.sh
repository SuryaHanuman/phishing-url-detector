#!/usr/bin/env bash
# ==============================================================================
# Application Execution & Docker Helper Script
# ==============================================================================
set -euo pipefail

MODE="${1:-scan}"

case "$MODE" in
    scan)
        echo "==> Running Phishing URL Detection System..."
        python3 main.py
        ;;
    test)
        echo "==> Running Pytest test suite..."
        pytest tests/ -v
        ;;
    docker-build)
        echo "==> Building Docker container image..."
        docker build -t suryahanuman/phishing-url-detector:latest .
        ;;
    docker-run)
        echo "==> Running container in interactive mode..."
        docker run -it --rm suryahanuman/phishing-url-detector:latest
        ;;
    *)
        echo "Usage: $0 {scan|test|docker-build|docker-run}"
        exit 1
        ;;
esac
