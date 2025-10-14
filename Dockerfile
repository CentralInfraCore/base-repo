# Use a slim, modern Python image
FROM python:3.11-slim

# Set a working directory
WORKDIR /app

# Install system dependencies that might be needed for cryptographic libraries
# and pip-tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install pip-tools globally in the container for the setup service to use
RUN pip install --no-cache-dir pip-tools
