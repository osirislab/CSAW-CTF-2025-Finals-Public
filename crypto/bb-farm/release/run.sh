#!/usr/bin/env bash
set -euo pipefail

# Run the release image with port 5000 exposed
docker run --rm -p 5000:5000 --privileged -it "$(docker build -q .)"
