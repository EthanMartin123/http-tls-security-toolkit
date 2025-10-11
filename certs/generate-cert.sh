#!/bin/bash

set -e

echo "🔐 Generating self-signed SSL certificate..."

if ! command -v openssl &>/dev/null; then
  echo "❌ Error: OpenSSL is not installed"
  echo "Install it with: sudo apt-get install openssl"
  exit 1
fi

if [ -f "cert.pem" ] || [ -f "key.pem" ]; then
  echo "⚠️ Warning: Certificate files already exist"
  echo "Delete them first? (y/n)"
  read answer
  if [ "$answer" = "y" ]; then
    rm -f cert.pem key.pem
    echo "✅ Old files deleted"
  else
    echo "❌ Aborted - keep existing files"
    exit 0
  fi
fi

openssl req -x509 \
  -newkey rsa:4096 \
  -keyout key.pem \
  -out cert.pem \
  -days 365 \
  -nodes \
  -subj "/C=US/ST=California/L=Thousand Oaks/O=Ethan Martin/OU=Security Research/CN=localhost"

if [ -f "cert.pem" ] && [ -f "key.pem" ]; then
  echo ""
  echo "✅ Certificate generated successfully!"
  echo "  📄 cert.pem - SSL certificate"
  echo "  🔑 key.pem = Private key"
  echo ""

  echo "📅 Certificate expires:"
  openssl x509 -in cert.pem -noout -enddate
else
  echo "❌ Error: Certificate generation failed"
  exit 1
fi
