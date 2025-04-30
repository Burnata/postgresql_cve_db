# PowerShell script for building multi-architecture Docker image

# Variables
$IMAGE_NAME = "burnata/postgres-db-cve-forms"
$IMAGE_TAG = "latest"

# Make sure Docker Buildx is available and create a new builder instance if needed
try {
    docker buildx create --name multiarch-builder --use
} catch {
    Write-Host "Builder already exists or couldn't be created. Continuing..."
}

# Build and push multi-architecture image
Write-Host "Building and pushing multi-architecture image..."
docker buildx build --platform linux/amd64,linux/arm64 `
  -t ${IMAGE_NAME}:${IMAGE_TAG} `
  --push `
  .

Write-Host "Multi-architecture image built and pushed successfully!"
Write-Host "You can verify the supported platforms with:"
Write-Host "docker buildx imagetools inspect ${IMAGE_NAME}:${IMAGE_TAG}"