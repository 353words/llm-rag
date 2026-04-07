package main

import (
	"archive/zip"
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
)

type Vuln struct {
	ID        string
	Published time.Time
	Aliases   []string
	Summary   string
	Details   string
	Affected  []json.RawMessage
}

func (v Vuln) Package() string {
	for _, a := range v.Affected {
		var p struct {
			Package struct {
				Name string
			}
		}
		if err := json.Unmarshal(a, &p); err != nil {
			continue
		}

		return p.Package.Name
	}

	return ""
}

func (v Vuln) Content(full bool) string {
	var buf strings.Builder

	if full {
		fmt.Fprintln(&buf, "ID:", v.ID)
		fmt.Fprintln(&buf, "Aliases:", strings.Join(v.Aliases, ","))
		fmt.Fprintln(&buf, "Published:", v.Published)
	}

	fmt.Fprintln(&buf, "Summary:", v.Summary)
	fmt.Fprintln(&buf, "Details:", v.Details)
	fmt.Fprintln(&buf, "Package:", v.Package())

	return buf.String()
}

func decodeEntry(zf *zip.File) (Vuln, error) {
	r, err := zf.Open()
	if err != nil {
		return Vuln{}, err
	}
	defer r.Close()

	dec := json.NewDecoder(r)

	var v Vuln
	if err := dec.Decode(&v); err != nil {
		return Vuln{}, err
	}

	return v, nil
}

var (
	//go:embed sql/schema.sql
	schemaSQL string

	//go:embed sql/insert.sql
	insertSQL string
)

func ingest(ctx context.Context, db *sql.DB) error {
	// https://vuln.go.dev/vulndb.zip
	r, err := zip.OpenReader("vulndb.zip")
	if err != nil {
		return err
	}
	defer r.Close()

	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		return err
	}

	em, err := NewEmbedder()
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	count, total, nErr := 0, len(r.File), 0

	for i, f := range r.File {
		fmt.Printf("%d/%d\r", i+1, total)
		if !strings.HasPrefix(f.Name, "ID/") {
			continue
		}

		count++
		v, err := decodeEntry(f)
		if err != nil {
			slog.Error("decode", "error", err)
			return err
		}

		slog.Debug("ingest document", "id", v.ID)

		vec, err := em.EmbedQuery(ctx, v.Content(false))
		if err != nil {
			slog.Warn("embed", "id", v.ID, "error", err)
			nErr++
			continue
		}

		if _, err := tx.ExecContext(ctx, insertSQL, v.ID, v.Content(true), vec); err != nil {
			return err
		}
	}

	slog.Info("ingest", "total", total, "errors", nErr)
	return tx.Commit()
}
