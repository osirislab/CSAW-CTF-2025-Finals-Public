#!/bin/bash
set -euo pipefail

DB="totallyhidden"
PRODUSER="produser"
ADMIN="prodadminsecretusername"
MAX_WAIT=120
SLEEP=3

echo "post-migration: waiting for tables to be created by $PRODUSER..."

# Wait for tables created by produser
t=0
while ! psql -U prodadminsecretusername -d "$DB" -tAc "SELECT 1 FROM pg_tables WHERE schemaname='public' AND tableowner='$PRODUSER' LIMIT 1" | grep -q 1; do
  if [ $t -ge $MAX_WAIT ]; then
    echo "post-migration: timeout waiting for tables; proceeding anyway"
    break
  fi
  sleep $SLEEP
  t=$((t+SLEEP))
done

if [ $t -lt $MAX_WAIT ]; then
  echo "post-migration: tables detected after ${t}s"
else
  echo "post-migration: no tables found after ${MAX_WAIT}s timeout"
fi

echo "post-migration: running ownership & privilege changes..."

psql -U prodadminsecretusername -d "$DB" -c "REASSIGN OWNED BY $PRODUSER TO $ADMIN;"
psql -U prodadminsecretusername -d "$DB" -c "REVOKE CREATE ON SCHEMA public FROM PUBLIC;"
psql -U prodadminsecretusername -d "$DB" -c "REVOKE CREATE ON SCHEMA public FROM $PRODUSER;"
psql -U prodadminsecretusername -d "$DB" -c "GRANT USAGE ON SCHEMA public TO $PRODUSER;"
psql -U prodadminsecretusername -d "$DB" -c "GRANT SELECT ON ALL TABLES IN SCHEMA public TO $PRODUSER;"
psql -U prodadminsecretusername -d "$DB" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO $PRODUSER;"
psql -U prodadminsecretusername -d totallyhidden -c "insert into secret (id, flag) values ('1', 'CSAWCTF{how_do_i_debug_my_app_if_i_dont_have_full_access_to_its_entire_memory_ahhhhhhhh}');"

echo "post-migration: done."