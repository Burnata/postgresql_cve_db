#!/bin/bash

# Exit on error
set -e

# Variables
IMAGE_NAME="burnata/postgres-db-cve-forms"
IMAGE_TAG="latest"

# Make sure Docker Buildx is available and create a new builder instance if needed
docker buildx create --name multiarch-builder --use || true

# Build and push multi-architecture image
echo "Building and pushing multi-architecture image..."
docker buildx build --platform linux/amd64,linux/arm64 \
  -t ${IMAGE_NAME}:${IMAGE_TAG} \
  --push \
  .

echo "Multi-architecture image built and pushed successfully!"
echo "You can verify the supported platforms with:"
echo "docker buildx imagetools inspect ${IMAGE_NAME}:${IMAGE_TAG}"