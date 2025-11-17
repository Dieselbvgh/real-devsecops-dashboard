#!/bin/bash
echo "🔧 Installing Real Security Tools..."

# Installer Trivy
echo "📦 Installing Trivy..."
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
trivy --version

# Installer Grype
echo "📦 Installing Grype..."
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
grype version

# Vérifier Docker
echo "🐳 Checking Docker..."
docker --version

echo "✅ All security tools installed!"
