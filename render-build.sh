#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# Update package lists
apt-get update

# Install Tesseract OCR and other required packages
apt-get install -y --no-install-recommends \
    tesseract-ocr \
    libtesseract-dev \
    libleptonica-dev \
    poppler-utils \
    libsm6 \
    libxext6 \
    libxrender-dev

# Clean up apt cache to reduce image size
rm -rf /var/lib/apt/lists/*

# Proceed with the Python app setup
pip install -r requirements.txt

# Any additional build steps can be added here
