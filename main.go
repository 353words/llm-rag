package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/ollama/ollama/api"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s ingest|search QUERY\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "error: wrong number of arguments")
		os.Exit(1)
	}

	c, err := api.ClientFromEnvironment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	db, err := sql.Open("duckdb", "vulns.db")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	defer db.Close()

	switch flag.Arg(0) {
	case "ingest":
		err = ingest(c, db)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
