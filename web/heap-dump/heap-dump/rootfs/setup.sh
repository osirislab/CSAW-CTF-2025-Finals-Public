#!/bin/bash -e
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get upgrade -y
apt-get install -y supervisor default-jre-headless bash
cp /init-users.sql /docker-entrypoint-initdb.d/01-init-users.sql

cp /post-migration.sh /usr/local/bin/post-migration.sh
chmod +x /usr/local/bin/post-migration.sh