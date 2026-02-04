package main

import (
	"archive/zip"
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
	"github.com/ollama/ollama/api"

	"rag/embed"
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

func (v Vuln) String() string {
	var buf strings.Builder

	fmt.Fprintln(&buf, "ID:", v.ID)
	fmt.Fprintln(&buf, "Aliases:", strings.Join(v.Aliases, ","))
	fmt.Fprintln(&buf, "Published:", v.Published)
	fmt.Fprintln(&buf, "Package:", v.Package())
	fmt.Fprintln(&buf, "Summary:", v.Summary)
	fmt.Fprintln(&buf, "Destails:", v.Details)

	return buf.String()
}

var (
	//go:embed sql/insert.sql
	insertSQL string
)

func ingest(r *zip.ReadCloser, c *api.Client, db *sql.DB) (int, error) {
	ctx := context.TODO()
	count := 0
	total := len(r.File)

	for i, f := range r.File {
		fmt.Printf("%d/%d\r", i, total)
		if !strings.HasPrefix(f.Name, "ID/") {
			continue
		}

		count++
		rc, err := f.Open()
		if err != nil {
			return 0, err
		}

		dec := json.NewDecoder(rc)
		var v Vuln

		if err := dec.Decode(&v); err != nil {
			return 0, err
		}

		content := v.String()
		em, err := embed.Embed(ctx, c, content)
		if err != nil {
			return 0, err
		}

		if _, err := db.ExecContext(ctx, insertSQL, v.ID, content, em); err != nil {
			return 0, err
		}
	}

	return count, nil
}

func main() {
	c, err := api.ClientFromEnvironment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	// https://vuln.go.dev/vulndb.zip
	db, err := sql.Open("duckdb", "vulns.db")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	defer db.Close()

	r, err := zip.OpenReader("vulndb.zip")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	defer r.Close()

	count, err := ingest(r, c, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("ingested %d documents\n", count)
}
