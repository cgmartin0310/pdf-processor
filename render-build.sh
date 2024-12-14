#!/usr/bin/env bash

# Install Tesseract OCR
apt-get update && apt-get install -y tesseract-ocr

# Proceed with the Python app setup
pip install -r requirements.txt

