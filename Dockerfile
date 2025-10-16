# Use official Node.js LTS image
FROM node:20-alpine AS node-stage

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install Node.js dependencies
RUN npm install

# Copy Node.js application files
COPY api.js ./
COPY helpers*.js ./
COPY server.js ./

# Install Python and dependencies
FROM python:3.11-slim

WORKDIR /app

# Install Node.js in Python image
RUN apt-get update && apt-get install -y \
    curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy Node.js app from previous stage
COPY --from=node-stage /app /app/node

# Copy Python bot
COPY bot.py ./

# Install Python dependencies
RUN pip install --no-cache-dir \
    python-telegram-bot==20.7 \
    aiohttp \
    aiofiles

# Create startup script
RUN echo '#!/bin/sh\n\
cd /app/node && node server.js &\n\
cd /app && python bot.py' > /app/start.sh && \
    chmod +x /app/start.sh

# Expose API port
EXPOSE 5000

# Start both services
CMD ["/app/start.sh"]
