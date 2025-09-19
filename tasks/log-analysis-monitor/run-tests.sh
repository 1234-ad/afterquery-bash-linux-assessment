#!/bin/bash

# Test runner script for log analysis task
# This script sets up the test environment and runs the test suite

set -euo pipefail

# Source the test environment setup
source $TEST_DIR/setup-uv-pytest.sh

# Run the pytest test suite
bash $TEST_DIR/run-uv-pytest.sh