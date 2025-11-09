SHELL := /bin/bash

RELEASE_DIR := release
BUILDER_IMAGE := bb-farm-builder
DEST := ../CSAW-CTF-2025-Finals/crypto/bb-farm

.PHONY: release sync run test
release:
	docker build -f Dockerfile.build -t $(BUILDER_IMAGE) .
	rm -rf $(RELEASE_DIR)
	container=$$(docker create $(BUILDER_IMAGE)); \
		mkdir -p $(RELEASE_DIR); \
		docker cp $$container:/app/target/release/bb-farm $(RELEASE_DIR)/; \
		docker cp $$container:/app/artifacts $(RELEASE_DIR)/; \
		docker cp $$container:/app/program.so $(RELEASE_DIR)/; \
		docker rm $$container
	cp -R starter $(RELEASE_DIR)/
	cp -a scripts/. $(RELEASE_DIR)/
	rm -rf $(RELEASE_DIR)/starter/.venv $(RELEASE_DIR)/starter/target \
		$(RELEASE_DIR)/starter/__pycache__

test:
	cd release && ./test.sh

run:
	cd release && ./run.sh

sync:
	rm -rf $(DEST)
	mkdir $(DEST)
	rsync -av --files-from=<(git ls-files) . $(DEST)

