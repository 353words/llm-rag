package embed

import (
	"context"

	"github.com/ollama/ollama/api"
)

func Embed(ctx context.Context, c *api.Client, s string) ([]float32, error) {
	req := &api.EmbedRequest{
		Model: "bge-m3",
		Input: []string{s},
	}

	resp, err := c.Embed(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.Embeddings[0], nil
}
