// Package feedrun records content-feed sync attempts in content_feeds /
// feed_sync_runs (0007), so every MSRC/KEV/... sync leaves a durable trace
// whether it succeeds or fails.
package feedrun

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Feed struct {
	Name      string // content_feeds.name, e.g. 'microsoft_cvrf', 'cisa_kev'
	Type      string // content_feeds.feed_type: patch_metadata | cve | kev | epss | third_party_apps
	SourceURL string
}

// Track ensures the content_feeds row, opens a feed_sync_runs row ('running'),
// runs fn, then records the outcome. On success it also sets
// content_feeds.last_success_at and sync_cursor (returned by fn, since it is
// usually only known after fetching). fn should include the network fetch, so
// an unreachable source is recorded as a failed run too. The run row is written
// outside fn's own transaction on purpose: a failed sync must still leave its
// record.
func Track(ctx context.Context, pool *pgxpool.Pool, feed Feed, fn func() (cursor string, added, updated int, err error)) error {
	var feedID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO content_feeds (name, feed_type, source_mode, source_url)
		VALUES ($1, $2, 'online', $3)
		ON CONFLICT (name) DO UPDATE SET source_url = EXCLUDED.source_url
		RETURNING id`, feed.Name, feed.Type, feed.SourceURL).Scan(&feedID); err != nil {
		return fmt.Errorf("ensure content_feeds row: %w", err)
	}

	var runID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO feed_sync_runs (feed_id, status) VALUES ($1, 'running') RETURNING id`, feedID,
	).Scan(&runID); err != nil {
		return fmt.Errorf("start feed_sync_runs row: %w", err)
	}

	cursor, added, updated, err := fn()

	status := "succeeded"
	var errMsg *string
	if err != nil {
		status = "failed"
		msg := err.Error()
		errMsg = &msg
	}
	// If ctx was cancelled mid-sync (server shutdown), still record the outcome
	// rather than leaving the run stuck at 'running'.
	finCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, finErr := pool.Exec(finCtx, `
		UPDATE feed_sync_runs
		SET status = $2, items_added = $3, items_updated = $4, completed_at = now(), error_message = $5
		WHERE id = $1`, runID, status, added, updated, errMsg); finErr != nil {
		return fmt.Errorf("sync error (%v) AND could not record feed_sync_runs: %w", err, finErr)
	}
	if err != nil {
		return err
	}
	if _, err := pool.Exec(ctx,
		`UPDATE content_feeds SET last_success_at = now(), sync_cursor = $2 WHERE id = $1`, feedID, cursor); err != nil {
		return fmt.Errorf("update content_feeds.last_success_at: %w", err)
	}
	return nil
}
