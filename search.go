package main

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ollama/ollama/api"
)

func init() {
	if os.Getenv("DEBUG") == "" {
		return
	}

	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	log := slog.New(h)
	slog.SetDefault(log)
}

//go:embed sql/search.sql
var searchSQL string

func queryDB(ctx context.Context, c *api.Client, db *sql.DB, query string, count int) ([]string, error) {
	em, err := Embed(ctx, c, query)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, searchSQL, em, count)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var (
		content    string
		similarity float32
		results    []string
	)

	for rows.Next() {
		if err := rows.Scan(&content, &similarity); err != nil {
			return nil, err
		}

		if similarity < 0.5 {
			continue
		}

		results = append(results, content)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

func chat(ctx context.Context, client *api.Client, req *api.ChatRequest) (string, error) {
	var buf strings.Builder

	err := client.Chat(ctx, req, func(resp api.ChatResponse) error {
		buf.WriteString(resp.Message.Content)
		return nil
	})

	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

const model = "ministral-3"

//go:embed prompts/improve.txt
var improvePrompt string

func imporve(ctx context.Context, c *api.Client, query string) (string, error) {
	req := api.ChatRequest{
		Model: model,
		Messages: []api.Message{
			{Role: "system", Content: improvePrompt},
			{Role: "user", Content: query},
		},
	}

	return chat(ctx, c, &req)
}

//go:embed prompts/search.txt
var searchPrompt string

func search(ctx context.Context, c *api.Client, db *sql.DB, query string) error {
	dbQuery, err := imporve(ctx, c, query)
	if err != nil {
		return err
	}
	slog.Debug("improve", "query", dbQuery)

	docs, err := queryDB(ctx, c, db, dbQuery, 5)
	if err != nil {
		return err
	}

	var buf strings.Builder
	for _, doc := range docs {
		slog.Debug("db query", "content", doc)
		fmt.Fprintln(&buf, doc)
		fmt.Fprintln(&buf)
	}

	req := api.ChatRequest{
		Model: model,
		Messages: []api.Message{
			{Role: "system", Content: searchPrompt},
			{Role: "system", Content: "CVEs:\n" + buf.String()},
			{Role: "user", Content: "QUERY:" + query},
		},
	}

	response, err := chat(ctx, c, &req)
	if err != nil {
		return err
	}

	fmt.Println(response)
	return nil
}
