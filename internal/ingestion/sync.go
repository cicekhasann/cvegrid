package ingestion

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cicekhasann/cvegrid/internal/database"
	"github.com/cicekhasann/cvegrid/internal/model"
)

// Typed messages for Bubbletea event loop communication.
type SyncStartedMsg struct{}

type SyncProgressMsg struct {
	Count int
}

type SyncFinishedMsg struct {
	Count    int
	Duration time.Duration
	Err      error
}

// Synchronizer orchestrates the threat intelligence feed ingestion pipeline.
type Synchronizer struct {
	client *HTTPClient
	repo   *database.Repository
	url    string
}

// NewSynchronizer returns an initialized Synchronizer.
func NewSynchronizer(client *HTTPClient, repo *database.Repository, url string) *Synchronizer {
	if client == nil {
		client = NewHTTPClient(DefaultTimeout)
	}
	if url == "" {
		url = DefaultFeedURL
	}
	return &Synchronizer{
		client: client,
		repo:   repo,
		url:    url,
	}
}

// Run performs a full synchronous fetch and ingest cycle.
func (s *Synchronizer) Run(ctx context.Context, progressFn func(int)) (int, error) {
	stream, err := s.client.FetchStream(ctx, s.url)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch threat intelligence stream: %w", err)
	}
	defer stream.Close()

	const batchSize = 500
	batch := make([]model.Vulnerability, 0, batchSize)
	totalProcessed := 0

	count, err := ParseKEVStream(stream, func(item model.Vulnerability) error {
		batch = append(batch, item)
		totalProcessed++

		if len(batch) >= batchSize {
			if err := s.repo.UpsertBatch(ctx, batch); err != nil {
				return err
			}
			batch = batch[:0]
			if progressFn != nil {
				progressFn(totalProcessed)
			}
		}
		return nil
	})

	if err != nil {
		return totalProcessed, fmt.Errorf("stream parsing failed: %w", err)
	}

	if len(batch) > 0 {
		if err := s.repo.UpsertBatch(ctx, batch); err != nil {
			return totalProcessed, fmt.Errorf("final batch flush failed: %w", err)
		}
		if progressFn != nil {
			progressFn(totalProcessed)
		}
	}

	// Update last sync timestamp
	nowStr := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	_ = s.repo.SetLastSync(ctx, nowStr)

	return count, nil
}

// SyncCmd returns a tea.Cmd that executes the sync asynchronously in a goroutine,
// returning a SyncFinishedMsg to the Bubbletea event loop without blocking the UI.
func (s *Synchronizer) SyncCmd() tea.Cmd {
	return func() tea.Msg {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		count, err := s.Run(ctx, nil)
		return SyncFinishedMsg{
			Count:    count,
			Duration: time.Since(start),
			Err:      err,
		}
	}
}
