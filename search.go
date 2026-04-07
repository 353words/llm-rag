package main

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"log/slog"
	"strings"

	"github.com/tmc/langchaingo/llms"
)

//go:embed sql/search.sql
var searchSQL string

func queryDB(ctx context.Context, db *sql.DB, query string, count int) ([]string, error) {
	em, err := NewEmbedder()
	if err != nil {
		return nil, err
	}

	vec, err := em.EmbedQuery(ctx, query)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, searchSQL, vec, count)
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

func search(ctx context.Context, db *sql.DB, query string) error {
	docs, err := queryDB(ctx, db, query, 20)
	if err != nil {
		return err
	}

	if len(docs) == 0 {
		return fmt.Errorf("search: %q - no relevant documents found", query)
	}

	var buf strings.Builder
	for _, doc := range docs {
		slog.Debug("db query", "content", doc)
		fmt.Fprintln(&buf, doc)
		fmt.Fprintln(&buf)
	}

	llm, err := NewLLM("Qwen3-0.6B-Q8_0")
	if err != nil {
		return err
	}

	systemPrompt := `
You are an expert cybersecurity researcher answering questions with retrieved vulnerability records.

Use only the information in the provided context. Treat the context as the source of truth.
Do not invent CVE IDs, products, versions, impact, fixes, timelines, or mitigations.
If the context is incomplete or does not support a conclusion, say that plainly.

Focus on directly answering the user's question.
Prefer a concise response.
When helpful, summarize the matching CVEs, affected components, impact, and mitigations grounded in the context.
Do not ask follow-up questions.
`
	systemPrompt += "\n## Context\n" + buf.String()

	messages := []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeSystem, systemPrompt),
		llms.TextParts(llms.ChatMessageTypeHuman, query),
	}

	resp, err := llm.GenerateContent(ctx, messages)
	if err != nil {
		return err
	}

	fmt.Println(resp.Choices[0].Content)
	return nil
}
