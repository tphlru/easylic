#!/bin/bash
# Production deployment script

set -e

echo "🚀 Starting EasyLic production deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DOCKER_IMAGE="${DOCKER_IMAGE:-easylic:latest}"
CONTAINER_NAME="${CONTAINER_NAME:-easylic-server}"
HOST_PORT="${HOST_PORT:-8000}"
CONTAINER_PORT="${CONTAINER_PORT:-8000}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running. Please start Docker first.${NC}"
    exit 1
fi

# Build the image if it doesn't exist
if ! docker image inspect "$DOCKER_IMAGE" > /dev/null 2>&1; then
    echo -e "${YELLOW}🔨 Building Docker image...${NC}"
    docker build -t "$DOCKER_IMAGE" .
fi

# Stop and remove existing container
if docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
    echo -e "${YELLOW}🛑 Stopping existing container...${NC}"
    docker stop "$CONTAINER_NAME"
fi

if docker ps -a -q -f name="$CONTAINER_NAME" | grep -q .; then
    echo -e "${YELLOW}🗑️  Removing existing container...${NC}"
    docker rm "$CONTAINER_NAME"
fi

# Run the new container
echo -e "${GREEN}🚀 Starting new container...${NC}"
docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p "$HOST_PORT:$CONTAINER_PORT" \
    -v "$(pwd)/logs:/home/app/logs" \
    -v "$(pwd)/keys:/home/app/easylic/server" \
    --env-file .env \
    "$DOCKER_IMAGE"

# Wait for health check
echo -e "${YELLOW}⏳ Waiting for service to be healthy...${NC}"
for i in {1..30}; do
    if curl -f http://localhost:"$HOST_PORT"/health > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Service is healthy!${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

if [ $i -eq 30 ]; then
    echo -e "${RED}❌ Service failed to start properly${NC}"
    docker logs "$CONTAINER_NAME"
    exit 1
fi

echo -e "${GREEN}🎉 Deployment completed successfully!${NC}"
echo -e "${GREEN}🌐 Service available at: http://localhost:$HOST_PORT${NC}"
echo -e "${GREEN}📊 Health check: http://localhost:$HOST_PORT/health${NC}"