#!/bin/bash
# Security scanning script

set -e

echo "🔒 Running security scans..."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Install security tools if not present
pip install safety bandit trivy || true

echo -e "${YELLOW}🔍 Scanning Python dependencies for vulnerabilities...${NC}"
if safety check; then
    echo -e "${GREEN}✅ No known vulnerabilities in dependencies${NC}"
else
    echo -e "${RED}⚠️  Vulnerabilities found in dependencies${NC}"
fi

echo -e "${YELLOW}🔍 Scanning code for security issues...${NC}"
if bandit -r easylic/ -f txt; then
    echo -e "${GREEN}✅ No security issues found in code${NC}"
else
    echo -e "${YELLOW}⚠️  Security issues found - review bandit output${NC}"
fi

echo -e "${YELLOW}🔍 Scanning Docker image for vulnerabilities...${NC}"
if command -v trivy &> /dev/null; then
    if trivy image easylic:latest --exit-code 1; then
        echo -e "${GREEN}✅ No vulnerabilities in Docker image${NC}"
    else
        echo -e "${RED}⚠️  Vulnerabilities found in Docker image${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Trivy not installed - skipping Docker image scan${NC}"
fi

echo -e "${GREEN}🎉 Security scanning completed${NC}"