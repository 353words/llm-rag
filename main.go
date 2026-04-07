package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path"
)

var options struct {
	ingest bool
}

func main() {
	flag.BoolVar(&options.ingest, "ingest", false, "populate database from vulndb.zip")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [options] QUERY\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()

	if os.Getenv("DEBUG") != "" {
		h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})
		log := slog.New(h)
		slog.SetDefault(log)
	}

	db, err := sql.Open("duckdb", "vulns.ddb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx := context.TODO()

	if options.ingest {
		if err := ingest(ctx, db); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
		return
	}

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "error: wrong number of arguments")
		os.Exit(1)
	}

	query := flag.Arg(0)
	if err := search(ctx, db, query); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
