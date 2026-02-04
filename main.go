package main

import (
	"context"
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

	/*
		if flag.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "error: wrong number of arguments")
			os.Exit(1)
		}
	*/

	c, err := api.ClientFromEnvironment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	db, err := sql.Open("duckdb", "vulns.ddb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx := context.TODO()

	switch flag.Arg(0) {
	case "ingest":
		err = ingest(ctx, c, db)
	case "search":
		if flag.NArg() != 2 {
			fmt.Fprintln(os.Stderr, "error: wrong number of arguments")
			os.Exit(1)
		}
		err = search(ctx, c, db, flag.Arg(1))
	default:
		err = search(ctx, c, db, "crypto")
		/*
			fmt.Fprintf(os.Stderr, "error: unknown command - %q\n", flag.Arg(0))
			os.Exit(1)
		*/
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
