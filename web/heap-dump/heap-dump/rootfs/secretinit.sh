#!/bin/sh -e
until pg_isready -h 127.0.0.1 -p 5432 -U prodadminsecretusername; do
  sleep 1
done

bash post-migration.sh
#psql -U prodadminsecretusername -d totallyhidden -c "insert into secret (id, flag) values ('1', 'CSAWCTF{how_do_i_debug_my_app_if_i_dont_have_full_access_to_its_entire_memory_ahhhhhhhh}');"
