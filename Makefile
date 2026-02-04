default:
	$(error pick a target)

DB = vulns.ddb

db:
	rm -f $(DB)
	duckdb $(DB) < sql/schema.sql
