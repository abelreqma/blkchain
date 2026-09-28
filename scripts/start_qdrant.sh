#!/bin/sh
# Start the Qdrant vector store (hardened image, localhost-only, persistent volume).
# Idempotent: starts the existing container if present, else creates it.
set -e
NAME=blkchain-qdrant
if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  docker start "$NAME"
else
  docker run -d --name "$NAME" --restart unless-stopped \
    -p 127.0.0.1:6333:6333 -p 127.0.0.1:6334:6334 \
    -v "$(cd "$(dirname "$0")/.." && pwd)/data/qdrant_storage:/qdrant/storage" \
    dhi.io/qdrant:1
fi
echo "Qdrant on http://127.0.0.1:6333 (collections: $(curl -s http://127.0.0.1:6333/collections))"
