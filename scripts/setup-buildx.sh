#!/bin/bash
# Setup Docker buildx for multi-platform builds

set -e

BUILDER_NAME="yamldap-builder"

echo "Setting up Docker buildx for multi-platform builds..."

# Check if buildx is available
if ! docker buildx version &> /dev/null; then
    echo "Error: Docker buildx is not available. Please update Docker."
    exit 1
fi

# Check if builder already exists
if docker buildx ls | grep -q "$BUILDER_NAME"; then
    echo "Builder '$BUILDER_NAME' already exists"
else
    echo "Creating new buildx builder: $BUILDER_NAME"
    docker buildx create --name "$BUILDER_NAME" \
        --driver docker-container \
        --platform linux/amd64,linux/arm64,linux/arm/v7 \
        --bootstrap
fi

# Use the builder
echo "Switching to builder: $BUILDER_NAME"
docker buildx use "$BUILDER_NAME"

# Verify the builder
echo "Verifying builder configuration..."
docker buildx inspect --bootstrap

echo "✓ Docker buildx is ready for multi-platform builds!"
echo ""
echo "You can now use:"
echo "  make docker-buildx     - Build multi-platform image"
echo "  make docker-push       - Build and push multi-platform image"