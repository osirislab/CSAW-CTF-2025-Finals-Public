#!/usr/bin/env bash

docker build -f Dockerfile.test .
docker run --rm -it --net=host "$(docker build -q -f Dockerfile.test .)" /bin/bash -c "cd starter && uv run main.py"
