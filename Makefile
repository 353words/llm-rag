default:
	$(error pick a target)

DB = vulns.db

db:
	rm -f $(DB)
	duckdb $(DB) < sql/schema.sql
