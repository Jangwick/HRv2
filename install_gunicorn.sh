#!/bin/bash

# Install gunicorn
pip install gunicorn

# Verify installation
echo "Verifying gunicorn installation:"
gunicorn --version

echo "Installation complete. You can now use gunicorn."
