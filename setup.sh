#!/bin/bash

# STIX2EDL v1.1 - Setup Script for Linux/macOS

echo "================================================"
echo "STIX2EDL v1.1 - Setup"
echo "================================================"
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed."
    echo "Please install Python 3.10 or higher"
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
pip3 install -r requirements.txt

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
echo "1. Create or edit config.yaml with your TAXII collections"
echo "2. Run: python3 taxii_threat_intel.py"
echo "3. Access the web UI at http://localhost:5000"
echo "4. Set your login password on first access"
echo ""
echo "Example config.yaml:"
echo "---"
echo "username: your-taxii-username"
echo "password: your-taxii-password"
echo "max_pages: 50"
echo "collections:"
echo "  - name: My Collection"
echo "    url: https://server.com/taxii2/collections/{id}/objects/"
echo "    enabled: true"
echo ""
echo "EDL Feeds (for firewalls):"
echo "  All indicators: http://localhost:5000/api/edl/all"
echo "  Per collection: http://localhost:5000/api/edl/collection/0"
echo ""
