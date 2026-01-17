#!/bin/bash

# APT Detection System - Quick Setup Script
# This script automates the setup process

echo "=================================================="
echo "APT Detection System - Automated Setup"
echo "=================================================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Found Python $python_version"

if ! python3 -c 'import sys; assert sys.version_info >= (3,8)' 2>/dev/null; then
    echo "❌ Error: Python 3.8 or higher is required"
    exit 1
fi

echo "✅ Python version OK"
echo ""

# Create virtual environment
echo "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "⚠️  Virtual environment already exists, skipping..."
fi
echo ""

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate
echo "✅ Virtual environment activated"
echo ""

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1
echo "✅ pip upgraded"
echo ""

# Install dependencies
echo "Installing dependencies (this may take a few minutes)..."
pip install -r requirements.txt
echo "✅ Dependencies installed"
echo ""

# Create necessary directories
echo "Creating project directories..."
mkdir -p data/raw data/processed data/threat_intelligence
mkdir -p results/models results/metrics results/reports
mkdir -p logs

echo "✅ Directories created"
echo ""

# Download sample dataset
echo "Downloading NSL-KDD dataset..."
python3 << EOF
from src.data_preprocessing.data_loader import DataLoader
loader = DataLoader()
try:
    loader.download_nsl_kdd()
    print("✅ Dataset downloaded successfully")
except Exception as e:
    print(f"⚠️  Could not download dataset: {e}")
    print("   You can train with synthetic data instead")
EOF

echo ""
echo "=================================================="
echo "Setup Complete! 🎉"
echo "=================================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Train the models:"
echo "   python train.py"
echo ""
echo "2. Launch the dashboard:"
echo "   cd dashboard && streamlit run app.py"
echo ""
echo "3. View documentation:"
echo "   cat README.md"
echo ""
echo "=================================================="
