#!/bin/sh
set -eu
# always start fresh
rm -f instance/database.sqlite
rm -f uploads/*

exec python app.py
