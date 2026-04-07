default:
	$(error pick a target)

DB = vulns.ddb

db:
	rm -f $(DB)
	duckdb $(DB) < sql/schema.sql

nuke-db:
	rm -f $(DB) $(DB).wal

ingest: nuke-db
	go run . -ingest

search:
	go run . 'what are the three most common causes of errors in HTTP?'
