#!/bin/bash -e
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get upgrade -y
apt-get install -y tar wget libfontconfig1 libfreetype6 curl
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs
# Install Chromium and dependencies
apt-get install -y chromium

a2enmod headers


npm install puppeteer
ln -s /var/www/html/node_modules /node_modules