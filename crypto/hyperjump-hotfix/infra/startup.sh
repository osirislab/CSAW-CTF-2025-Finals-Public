#!/bin/bash
echo "[STARTUP] Running startup.sh at $(date)"

if [ "$(id -u)" -ne 0 ]; then
	echo "[ERROR] startup.sh must be run as root for setup tasks."
	echo "[STARTUP] Exiting process"
	exit 1
fi


export TERM=xterm-256color

echo "[STARTUP] Moved to SHIP CORE"
cd /ship-core

./gen_keys && echo "[STARTUP] Keys generated" || echo "[ERROR] gen_keys failed"
chown root:comnavcent private.key
chmod 640 private.key

mkdir logs && echo "[STARTUP] Logs directory created"

./initial_jump && echo "[STARTUP] Initial jump complete" || echo "[ERROR] initial_jump failed"

echo "[STARTUP] Dropping to shell and switching to pilot"
exec su -s /bin/bash pilot
