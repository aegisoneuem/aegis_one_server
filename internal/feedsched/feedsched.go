// Package feedsched runs the content-feed syncs (MSRC CVRF, CISA KEV) inside the
// server on the schedule configured in content_feeds, instead of by hand.
//
// A feed is due when it is enabled, online (offline_bundle import is a separate,
// still-open item), and its last success is older than sync_interval_hours - or
// it has never succeeded. After a failed run it waits RetryAfterFailure before
// trying again. Each run holds a Postgres advisory lock keyed on the feed name, so
// with several server replicas only one runs a given feed; the due check happens
// after taking the lock so a replica can't re-run what another just finished.
package feedsched

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	CheckEvery        = 15 * time.Minute
	RetryAfterFailure = 1 * time.Hour
	RunTimeout        = 10 * time.Minute
)

// Job is one feed: Name must match the content_feeds.name its sync writes.
// Run returns a short human-readable result for the log.
type Job struct {
	Name string
	Run  func(ctx context.Context, pool *pgxpool.Pool) (string, error)
}

type Scheduler struct {
	pool *pgxpool.Pool
	log  *slog.Logger
	jobs []Job
}

func New(pool *pgxpool.Pool, log *slog.Logger, jobs ...Job) *Scheduler {
	return &Scheduler{pool: pool, log: log, jobs: jobs}
}

// Run checks every job once immediately, then every CheckEvery, until ctx ends.
// Jobs run one after another, never concurrently within one server.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(CheckEvery)
	defer ticker.Stop()
	for {
		for _, job := range s.jobs {
			if ctx.Err() != nil {
				return
			}
			s.runIfDue(ctx, job)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Scheduler) runIfDue(ctx context.Context, job Job) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		s.log.Error("feed scheduler: acquire connection", "feed", job.Name, "error", err.Error())
		return
	}
	defer conn.Release()

	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext('aegis-feed:' || $1))`, job.Name).Scan(&locked); err != nil {
		s.log.Error("feed scheduler: advisory lock", "feed", job.Name, "error", err.Error())
		return
	}
	if !locked {
		s.log.Debug("feed scheduler: another instance is syncing this feed, skipping", "feed", job.Name)
		return
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, `SELECT pg_advisory_unlock(hashtext('aegis-feed:' || $1))`, job.Name); err != nil {
			s.log.Warn("feed scheduler: advisory unlock", "feed", job.Name, "error", err.Error())
		}
	}()

	due, reason, err := s.due(ctx, job.Name)
	if err != nil {
		s.log.Error("feed scheduler: due check", "feed", job.Name, "error", err.Error())
		return
	}
	if !due {
		s.log.Debug("feed scheduler: not due", "feed", job.Name, "reason", reason)
		return
	}

	s.log.Info("feed sync starting", "feed", job.Name, "reason", reason)
	runCtx, cancel := context.WithTimeout(ctx, RunTimeout)
	defer cancel()
	started := time.Now()
	result, err := job.Run(runCtx, s.pool)
	if err != nil {
		s.log.Error("feed sync failed", "feed", job.Name, "duration", time.Since(started).Round(time.Second).String(), "error", err.Error())
		return
	}
	s.log.Info("feed sync succeeded", "feed", job.Name, "duration", time.Since(started).Round(time.Second).String(), "result", result)
}

func (s *Scheduler) due(ctx context.Context, name string) (bool, string, error) {
	var (
		enabled     bool
		sourceMode  string
		interval    int
		lastSuccess *time.Time
		lastStatus  *string
		lastStarted *time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT f.is_enabled, f.source_mode, f.sync_interval_hours, f.last_success_at, r.status, r.started_at
		FROM content_feeds f
		LEFT JOIN LATERAL (
			SELECT status, started_at FROM feed_sync_runs WHERE feed_id = f.id ORDER BY id DESC LIMIT 1
		) r ON true
		WHERE f.name = $1`, name,
	).Scan(&enabled, &sourceMode, &interval, &lastSuccess, &lastStatus, &lastStarted)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, "never synced", nil
	}
	if err != nil {
		return false, "", err
	}

	switch {
	case !enabled:
		return false, "disabled in content_feeds", nil
	case sourceMode != "online":
		return false, "source_mode " + sourceMode + " is not scheduled", nil
	case lastStatus != nil && *lastStatus == "failed" && lastStarted != nil && time.Since(*lastStarted) < RetryAfterFailure:
		return false, "last run failed less than " + RetryAfterFailure.String() + " ago", nil
	case lastSuccess == nil:
		return true, "never succeeded", nil
	case time.Since(*lastSuccess) >= time.Duration(interval)*time.Hour:
		return true, fmt.Sprintf("last success %s ago, interval %dh", time.Since(*lastSuccess).Round(time.Minute), interval), nil
	default:
		return false, "synced recently", nil
	}
}
