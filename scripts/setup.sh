#!/usr/bin/env bash
# ==============================================================================
# Development Environment Setup Script
# Automates Python virtualenv creation, dependency installation, and verification.
# ==============================================================================
set -euo pipefail

echo "==> Setting up environment for Phishing URL Detection System..."

# Verify Python 3 presence
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed or not in PATH. Please install Python 3.10+." >&2
    exit 1
fi

# Create virtual environment if missing
if [ ! -d "venv" ]; then
    echo "==> Creating virtual environment in ./venv..."
    python3 -m venv venv
fi

# Activate virtual environment
# shellcheck source=/dev/null
source venv/bin/activate

echo "==> Upgrading pip and installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt

echo "==> Running automated lint checks and unit tests..."
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics || true
pytest tests/ -v

echo "==> Setup complete! To activate your environment, run: source venv/bin/activate"
