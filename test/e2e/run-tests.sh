#!/bin/bash
# B16 E2E Test Runner
#
# Usage:
#   ./run-tests.sh           Run all E2E tests against docker-compose stack
#   ./run-tests.sh health    Run only health check tests
#   ./run-tests.sh -v        Verbose output
#
# Prerequisites:
#   1. Docker running
#   2. Stack started: cd ../.. && make test
#   3. Services healthy: make health

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== B16 E2E Test Runner ===${NC}"

# Check Docker
if ! docker ps >/dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running${NC}"
    echo "Please start Docker and run: make test"
    exit 1
fi

# Check stack is running
if ! curl -sk https://localhost:8443/health >/dev/null 2>&1; then
    echo -e "${RED}❌ Sigil server not reachable${NC}"
    echo "Please run: cd $SERVER_DIR && make test"
    exit 1
fi

if ! curl -s http://localhost:8080/health >/dev/null 2>&1; then
    echo -e "${RED}❌ Relay not reachable${NC}"
    echo "Please run: cd $SERVER_DIR && make test"
    exit 1
fi

echo -e "${GREEN}✅ Stack is healthy${NC}"
echo ""

# Set environment
export SIGIL_E2E_ENABLED=true
export SIGIL_SERVER_URL=https://localhost:8443
export SIGIL_RELAY_URL=http://localhost:8080

# Parse args
VERBOSE=""
TEST_PATTERN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE="-v"
            shift
            ;;
        health)
            TEST_PATTERN="-run 'Health|Info'"
            shift
            ;;
        *)
            TEST_PATTERN="-run $1"
            shift
            ;;
    esac
done

# Run tests
echo "Running E2E tests..."
cd "$SCRIPT_DIR"

if [ -n "$TEST_PATTERN" ]; then
    eval "go test $VERBOSE $TEST_PATTERN ./..."
else
    go test $VERBOSE ./...
fi

echo ""
echo -e "${GREEN}✅ E2E tests complete${NC}"
