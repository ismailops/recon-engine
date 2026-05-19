#!/usr/bin/env bash
# scripts/setup.sh
# Sets up the development environment for recon-engine.
# Run once after cloning the repository.

set -euo pipefail

PYTHON_MIN_VERSION="3.11"

check_python_version() {
    local version
    version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"; then
        echo "Python ${version} — OK"
    else
        echo "ERROR: Python ${PYTHON_MIN_VERSION}+ required, found ${version}"
        exit 1
    fi
}

create_virtualenv() {
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
        echo "Virtual environment created at .venv"
    else
        echo "Virtual environment already exists"
    fi
}

install_dependencies() {
    source .venv/bin/activate
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    echo "Dependencies installed"
}

configure_env() {
    if [ ! -f ".env" ]; then
        cp .env.example .env
        echo ".env created from .env.example"
    else
        echo ".env already exists"
    fi
}

create_output_dirs() {
    mkdir -p outputs
    echo "Output directories ready"
}

run_tests() {
    source .venv/bin/activate
    echo "Running test suite..."
    python -m pytest tests/ -v --tb=short
}

echo "=== recon-engine setup ==="
check_python_version
create_virtualenv
install_dependencies
configure_env
create_output_dirs
echo ""
echo "Setup complete. Activate your environment with:"
echo "  source .venv/bin/activate"
echo ""
echo "Run the test suite with:"
echo "  pytest tests/ -v"
echo ""
echo "Start a scan with:"
echo "  python main.py scan example.com"
