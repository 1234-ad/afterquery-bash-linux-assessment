FROM ubuntu:22.04

# Install required packages
RUN apt-get update && apt-get install -y \
    tmux \
    asciinema \
    apache2-utils \
    gzip \
    jq \
    curl \
    vim \
    less \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /var/log/apache /var/log/auth /app

# Set working directory
WORKDIR /app

# Create log directories with proper permissions
RUN chmod 755 /var/log/apache /var/log/auth