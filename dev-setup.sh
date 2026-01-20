#!/bin/bash
# EasyLic Development Setup Script

set -e

echo "=== EasyLic Development Setup ==="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if docker-compose is available
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    echo "docker-compose is not available. Please install docker-compose."
    exit 1
fi

# Create .env file if it doesn't exist
if [[ ! -f .env ]]; then
    cp .env.example .env
    echo "Created .env file from .env.example"
    echo "Please edit .env to set your configuration"
fi

# Build and start services
echo "Building and starting services..."
$COMPOSE_CMD up --build -d

# Wait for services to be healthy
echo "Waiting for services to start..."
sleep 10

# Check service health
if $COMPOSE_CMD ps | grep -q "Up"; then
    echo "=== Services started successfully ==="
    $COMPOSE_CMD ps
    echo ""
    echo "Web interface: http://localhost"
    echo "API documentation: http://localhost/docs"
    echo "Health check: http://localhost/health"
    echo ""
    echo "To view logs: $COMPOSE_CMD logs -f"
    echo "To stop: $COMPOSE_CMD down"
else
    echo "=== Service startup failed ==="
    $COMPOSE_CMD logs
    exit 1
fi