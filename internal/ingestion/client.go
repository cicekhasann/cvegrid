package ingestion

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	DefaultFeedURL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultUserAgent = "cvegrid/1.0 (+https://github.com/cicekhasann/cvegrid)"
	DefaultTimeout   = 35 * time.Second
	MaxRetries       = 3
)

// HTTPClient defines the client interface used for fetching threat intelligence feeds.
type HTTPClient struct {
	client    *http.Client
	userAgent string
}

// NewHTTPClient creates a resilient HTTPClient with timeout and User-Agent headers.
func NewHTTPClient(timeout time.Duration) *HTTPClient {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
		},
		userAgent: DefaultUserAgent,
	}
}

// FetchStream retrieves an io.ReadCloser for the given URL, applying retry backoff on failures.
func (c *HTTPClient) FetchStream(ctx context.Context, url string) (io.ReadCloser, error) {
	if url == "" {
		url = DefaultFeedURL
	}

	var lastErr error
	backoff := 500 * time.Millisecond

	for attempt := 1; attempt <= MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept", "application/json")

		resp, err := c.client.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				return resp.Body, nil
			}
			resp.Body.Close()
			lastErr = fmt.Errorf("server returned non-200 status: %d %s", resp.StatusCode, resp.Status)
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
		}
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", MaxRetries, lastErr)
}
