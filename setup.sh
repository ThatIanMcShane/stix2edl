#!/bin/bash

# TAXII Threat Intelligence Collector - Setup and Run Script for macOS

echo "================================================"
echo "TAXII Threat Intelligence Collector Setup"
echo "================================================"
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed."
    echo "Please install Python 3 from https://www.python.org/downloads/"
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"
echo ""

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed."
    echo "Please install pip3"
    exit 1
fi

echo "✅ pip3 found"
echo ""

# Install dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt --user

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo ""
echo "================================================"
echo "Setup Complete!"
echo "================================================"
echo ""
echo "Next steps:"
echo "1. Edit config.yaml with your TAXII collection URL"
echo "2. Run: python3 taxii_threat_intel.py"
echo ""
echo "Configuration Format:"
echo "  collection_url: https://server.com/taxii2/collections/{id}/objects/"
echo ""
echo "Authentication Options:"
echo "  Bearer Token:"
echo "    auth_type: bearer"
echo "    auth_token: your-token"
echo ""
echo "  Basic HTTP Auth:"
echo "    auth_type: basic"
echo "    username: your-username"
echo "    password: your-password"
echo ""
echo "For testing with MITRE ATT&CK Enterprise collection:"
echo "  collection_url: https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/objects/"
echo "  auth_type: none"
echo ""
