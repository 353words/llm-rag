package main

import (
	"os"

	"github.com/tmc/langchaingo/embeddings"
	"github.com/tmc/langchaingo/llms/openai"
)

var baseURL string

func init() {
	baseURL = "http://localhost:8080/v1"
	if host := os.Getenv("KRONK_WEB_API_HOST"); host != "" {
		baseURL = host + "/v1"
	}
}

// NewLLM returns a connection to new LLM
func NewLLM(model string) (*openai.LLM, error) {
	return openai.New(
		openai.WithBaseURL(baseURL),
		openai.WithToken("x"),
		openai.WithModel(model),
	)
}

// NewEmbedder returns a new embedder.
func NewEmbedder() (embeddings.Embedder, error) {
	llm, err := openai.New(
		openai.WithBaseURL(baseURL),
		openai.WithToken("x"),
		openai.WithEmbeddingModel("Qwen3-Embedding-0.6B-Q8_0"),
	)
	if err != nil {
		return nil, err
	}

	return embeddings.NewEmbedder(llm)
}
