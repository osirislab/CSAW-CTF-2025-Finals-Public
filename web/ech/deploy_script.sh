#!/bin/bash

# ECH DNS CTF Challenge Deployment Script
# Claude Sonnet 4.5 used to generate code comments (human read and validated)

set -e

echo "========================================"
echo "ECH DNS CTF Challenge Deployment"
echo "========================================"
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker is not installed${NC}"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✓ Docker found${NC}"

# Check for Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}✗ Docker Compose is not installed${NC}"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose found${NC}"

echo ""
echo "Building Docker container..."
docker-compose build

echo ""
echo "Starting services..."
docker-compose up -d

echo ""
echo "Waiting for server to be ready..."
sleep 3

# Health check
if curl -s http://localhost:8053/health > /dev/null; then
    echo -e "${GREEN}✓ Server is running!${NC}"
else
    echo -e "${RED}✗ Server health check failed${NC}"
    echo "Check logs with: docker-compose logs"
    exit 1
fi

echo ""
echo "========================================"
echo "Deployment Successful!"
echo "========================================"
echo ""
echo "Challenge URL: http://localhost:8053"
echo ""
echo "Quick Test Commands:"
echo "  Public domain:  curl 'http://localhost:8053/dns-query?name=nyu.edu'"
echo "  Private domain: curl 'http://localhost:8053/dns-query?name=csaw.io'"
echo ""
echo "To view logs:     docker-compose logs -f"
echo "To stop:          docker-compose down"
echo ""
echo -e "${YELLOW}Happy hacking!${NC} 🚀"
