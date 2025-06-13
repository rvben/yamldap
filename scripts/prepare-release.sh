#!/bin/bash

# Prepare a new release by updating version numbers and creating a tag

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get current version from Cargo.toml
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/')

echo -e "${GREEN}Current version:${NC} $CURRENT_VERSION"
echo ""

# Ask for new version
read -p "Enter new version (e.g., 0.0.2): " NEW_VERSION

if [ -z "$NEW_VERSION" ]; then
    echo -e "${RED}Error: Version cannot be empty${NC}"
    exit 1
fi

# Validate version format
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}Error: Invalid version format. Use X.Y.Z (e.g., 0.0.2)${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}This will:${NC}"
echo "1. Update version in Cargo.toml to $NEW_VERSION"
echo "2. Update Cargo.lock"
echo "3. Ensure CHANGELOG.md has an entry for [$NEW_VERSION]"
echo "4. Commit these changes"
echo "5. Create and push tag v$NEW_VERSION"
echo ""

read -p "Continue? (y/N) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted"
    exit 1
fi

# Update version in Cargo.toml
echo -e "${GREEN}Updating Cargo.toml...${NC}"
sed -i.bak "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml
rm Cargo.toml.bak

# Update Cargo.lock
echo -e "${GREEN}Updating Cargo.lock...${NC}"
cargo update -p yamldap

# Check if CHANGELOG.md has entry for new version
if ! grep -q "## \[$NEW_VERSION\]" CHANGELOG.md; then
    echo -e "${YELLOW}Warning: No entry found for version $NEW_VERSION in CHANGELOG.md${NC}"
    echo "Please add a changelog entry before continuing."
    echo ""
    echo "Example entry:"
    echo "## [$NEW_VERSION] - $(date +%Y-%m-%d)"
    echo ""
    echo "### Added"
    echo "- New features..."
    echo ""
    echo "### Changed"
    echo "- Changes..."
    echo ""
    echo "### Fixed"
    echo "- Bug fixes..."
    echo ""
    read -p "Press Enter after updating CHANGELOG.md..."
fi

# Stage changes
echo -e "${GREEN}Staging changes...${NC}"
git add Cargo.toml Cargo.lock CHANGELOG.md

# Show diff
echo -e "${GREEN}Changes to be committed:${NC}"
git diff --cached

echo ""
read -p "Commit these changes? (y/N) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Reverting changes..."
    git checkout Cargo.toml Cargo.lock
    exit 1
fi

# Commit
echo -e "${GREEN}Committing...${NC}"
git commit -m "chore: prepare release v$NEW_VERSION"

# Create tag
echo -e "${GREEN}Creating tag v$NEW_VERSION...${NC}"
git tag -a "v$NEW_VERSION" -m "Release v$NEW_VERSION"

echo ""
echo -e "${GREEN}Release prepared successfully!${NC}"
echo ""
echo "To push the release:"
echo "  git push origin main"
echo "  git push origin v$NEW_VERSION"
echo ""
echo "This will trigger the GitHub Actions release workflow."