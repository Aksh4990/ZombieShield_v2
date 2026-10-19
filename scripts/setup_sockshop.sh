#!/usr/bin/env sh
# Clones the Sock Shop service repositories (with full history) for Git discovery.
set -e
root="$(dirname "$0")/../discovery-repositories"
for repo in front-end catalogue user carts orders payment shipping; do
  [ -d "$root/$repo" ] && { echo "$repo already present"; continue; }
  git clone "https://github.com/microservices-demo/$repo" "$root/$repo"
done
echo "Done. Start everything with: docker compose --profile sockshop up --build"
