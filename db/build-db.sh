#!/bin/sh

echo "Generating db...";

#cat data/gen-db.sql | sqlite3 db/db

echo "Creating fingerprints...";

for f in data/*.sql;
do
	echo "$f"
	cat "$f" | sqlite3 db/db
done

echo "Done."

