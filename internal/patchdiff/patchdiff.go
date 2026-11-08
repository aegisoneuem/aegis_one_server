// Package patchdiff decides on the server what a device is missing (agent
// repo: docs/server-spec-patch-detection.md). The endpoint never needs the
// wsusscn2.cab: it reports its build + UBR, architecture and installed KBs
// (DeviceStateReport), and the diff runs here against the catalog.
//
// What it decides: the Windows cumulative update, where the build is
// authoritative. From the fixed-build index (patchbaseline, MSRC
// os_fixed_builds) the newest KB for the device's (client|server, arch, build)
// family is
//   - installed       when the device's UBR is at or past that KB's UBR,
//   - pending_reboot  when the KB is in the device's installed set but the UBR
//     hasn't moved yet and the device reports a pending reboot,
//   - missing         otherwise.
//
// Older cumulative KBs are superseded by the newest one, so only that one is
// kept. Standalone / .NET / Office updates need product signals the agent
// doesn't send yet; they come only from an optional agent cab scan
// (agent_wua rows), which is kept while fresh.
//
// Feedback: an install_patch the agent answers NOT_APPLICABLE stops the diff
// offering that patch for as long as the device stays on that build.
//
// Rows it writes have detection_source 'server_diff'; it never touches an
// agent scan's rows except to drop them once stale.
package patchdiff

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"aegis-one/internal/ingest"
	"aegis-one/internal/patchbaseline"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// rediffWorkers is how many devices are diffed at once after a catalog change.
const rediffWorkers = 4

type Differ struct {
	pool *pgxpool.Pool
	log  *slog.Logger

	mu    sync.RWMutex
	index patchbaseline.Index // nil until the first Reload
	key   string              // index.Fingerprint()
}

func New(pool *pgxpool.Pool, log *slog.Logger) *Differ {
	return &Differ{pool: pool, log: log}
}

// Result is what one device's diff decided.
type Result struct {
	KB      string // the cumulative KB evaluated; "" when the build family is unknown
	State   string // missing | pending_reboot | installed | not_applicable | ""
	Catalog string
}

// ErrNotLoaded means the catalog index hasn't been loaded yet (Reload).
var ErrNotLoaded = errors.New("patch diff: catalog not loaded yet")

// Reload reads the fixed-build index and reports whether it changed.
func (df *Differ) Reload(ctx context.Context) (bool, error) {
	ix, err := patchbaseline.Load(ctx, df.pool)
	if err != nil {
		return false, err
	}
	key := ix.Fingerprint()
	df.mu.Lock()
	defer df.mu.Unlock()
	changed := df.index == nil || key != df.key
	df.index, df.key = ix, key
	return changed, nil
}

func (df *Differ) current() (patchbaseline.Index, string) {
	df.mu.RLock()
	defer df.mu.RUnlock()
	return df.index, df.key
}

// Watch reloads the catalog every interval and re-diffs every device when it
// changed (a new cumulative KB arrived from the MSRC feed).
func (df *Differ) Watch(ctx context.Context, interval time.Duration) {
	check := func() {
		changed, err := df.Reload(ctx)
		if err != nil {
			if ctx.Err() == nil {
				df.log.Warn("patch diff: reload catalog", "error", err.Error())
			}
			return
		}
		if !changed {
			return
		}
		_, key := df.current()
		start := time.Now()
		n, failed, err := df.All(ctx)
		if err != nil && ctx.Err() == nil {
			df.log.Warn("patch diff: re-diff fleet", "error", err.Error())
		}
		df.log.Info("patch diff: fleet re-diffed for catalog", "catalog", key, "devices", n, "failed", failed,
			"duration", time.Since(start).Round(time.Millisecond).String())
	}
	check()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}

// All diffs every device that has reported a build. It doesn't refresh
// last_patch_scan_at: the device data is no newer than before.
func (df *Differ) All(ctx context.Context) (devices, failed int, err error) {
	rows, err := df.pool.Query(ctx, `SELECT id::text FROM devices WHERE os_build IS NOT NULL AND status = 'active'`)
	if err != nil {
		return 0, 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	jobs := make(chan string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for w := 0; w < rediffWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				if _, err := df.Device(ctx, id, false); err != nil {
					mu.Lock()
					failed++
					mu.Unlock()
					if ctx.Err() == nil {
						df.log.Warn("patch diff: device", "device_uuid", id, "error", err.Error())
					}
				}
			}
		}()
	}
	for _, id := range ids {
		select {
		case jobs <- id:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(jobs)
	wg.Wait()
	return len(ids), failed, ctx.Err()
}

// Device diffs one device. fresh means the device just reported its state,
// so its patch data counts as current (last_patch_scan_at); a re-diff after a
// catalog change passes false.
func (df *Differ) Device(ctx context.Context, deviceUUID string, fresh bool) (Result, error) {
	ix, key := df.current()
	if ix == nil {
		return Result{}, ErrNotLoaded
	}
	res := Result{Catalog: key}
	tx, err := df.pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	// One diff per device at a time (the stream and a fleet re-diff can race).
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('patchdiff:' || $1))`, deviceUUID); err != nil {
		return res, err
	}

	var edition, build, arch *string
	var ubr *int
	var pendingReboot bool
	err = tx.QueryRow(ctx, `SELECT os_edition, os_build, os_ubr, architecture, pending_reboot FROM devices WHERE id = $1`,
		deviceUUID).Scan(&edition, &build, &ubr, &arch, &pendingReboot)
	if errors.Is(err, pgx.ErrNoRows) {
		return res, fmt.Errorf("unknown device %s", deviceUUID)
	}
	if err != nil {
		return res, err
	}
	dev := patchbaseline.DeviceFrom(deref(edition), deref(build), ubr, deref(arch))

	keep := []string{}
	latest, known := ix.LatestFor(dev)
	if known {
		res.KB = latest.KB
		var na bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM device_patch_not_applicable
			               WHERE device_id = $1 AND patch_id = $2 AND full_build = $3)`,
			deviceUUID, latest.PatchID, dev.FullBuild()).Scan(&na); err != nil {
			return res, err
		}
		if na {
			res.State = "not_applicable"
		} else {
			var inSet bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM device_installed_kbs WHERE device_id = $1 AND kb = $2)`,
				deviceUUID, latest.KB).Scan(&inSet); err != nil {
				return res, err
			}
			res.State = Decide(dev.UBR, latest.UBR, inSet, pendingReboot)
			if err := upsert(ctx, tx, deviceUUID, latest.PatchID, res.State); err != nil {
				return res, err
			}
			keep = append(keep, latest.PatchID)
		}
	}

	// The diff's own rows for anything it no longer decides (an older
	// cumulative KB, a build it no longer knows) go.
	if _, err := tx.Exec(ctx, `
		DELETE FROM device_patch_state
		WHERE device_id = $1 AND detection_source = 'server_diff' AND NOT (patch_id = ANY($2))`,
		deviceUUID, keep); err != nil {
		return res, fmt.Errorf("remove stale diff rows: %w", err)
	}
	// An optional agent cab scan's rows count only while fresh; without a
	// newer scan they would read as missing forever.
	if _, err := tx.Exec(ctx, `
		DELETE FROM device_patch_state
		WHERE device_id = $1 AND detection_source = 'agent_wua' AND NOT (patch_id = ANY($2))
		  AND last_evaluated_at < now() - make_interval(days => setting_int('compliance.scan_freshness_days', 7))`,
		deviceUUID, keep); err != nil {
		return res, fmt.Errorf("remove stale scan rows: %w", err)
	}
	if _, err := ingest.AssignSLA(ctx, tx, deviceUUID); err != nil {
		return res, fmt.Errorf("assign SLA: %w", err)
	}
	// A build the catalog doesn't know yet can't be called compliant: leave
	// last_patch_scan_at alone so compliance goes 'unknown' once it is stale.
	if _, err := tx.Exec(ctx, `
		UPDATE devices SET patch_diff_catalog = $2, patch_diff_at = now(),
		    last_patch_scan_at     = CASE WHEN $3 THEN now() ELSE last_patch_scan_at END,
		    last_patch_scan_status = CASE WHEN $3 THEN 'succeeded' ELSE last_patch_scan_status END
		WHERE id = $1`, deviceUUID, key, fresh && known); err != nil {
		return res, err
	}
	return res, tx.Commit(ctx)
}

// Decide is the cumulative-update rule: the build (UBR) is authoritative.
func Decide(deviceUBR, latestUBR int, kbInstalled, pendingReboot bool) string {
	switch {
	case deviceUBR >= latestUBR:
		return "installed"
	case kbInstalled && pendingReboot:
		return "pending_reboot"
	default:
		return "missing"
	}
}

// upsert writes one diff row. The SLA clock rules match the scan ingest: a
// patch missing again after being installed starts a fresh clock; a 'failed'
// row (an install attempt failed) stays failed while still missing.
func upsert(ctx context.Context, tx pgx.Tx, deviceUUID, patchID, state string) error {
	var err error
	switch state {
	case "installed":
		_, err = tx.Exec(ctx, `
			INSERT INTO device_patch_state (device_id, patch_id, state, detection_source, installed_at, last_evaluated_at)
			VALUES ($1, $2, 'installed', 'server_diff', now(), now())
			ON CONFLICT (device_id, patch_id) DO UPDATE SET
				installed_at = CASE WHEN device_patch_state.state = 'installed' AND device_patch_state.installed_at IS NOT NULL
				                    THEN device_patch_state.installed_at ELSE now() END,
				state = 'installed', detection_source = 'server_diff', last_evaluated_at = now(), last_error = NULL`,
			deviceUUID, patchID)
	case "pending_reboot":
		_, err = tx.Exec(ctx, `
			INSERT INTO device_patch_state (device_id, patch_id, state, detection_source, first_detected_missing_at, last_evaluated_at)
			VALUES ($1, $2, 'pending_reboot', 'server_diff', now(), now())
			ON CONFLICT (device_id, patch_id) DO UPDATE SET
				state = 'pending_reboot', detection_source = 'server_diff', last_evaluated_at = now()`,
			deviceUUID, patchID)
	case "missing":
		_, err = tx.Exec(ctx, `
			INSERT INTO device_patch_state (device_id, patch_id, state, detection_source, first_detected_missing_at, last_evaluated_at)
			VALUES ($1, $2, 'missing', 'server_diff', now(), now())
			ON CONFLICT (device_id, patch_id) DO UPDATE SET
				detection_source = 'server_diff',
				last_evaluated_at = now(),
				first_detected_missing_at = CASE WHEN device_patch_state.state IN ('installed', 'superseded') THEN now()
				                                 ELSE COALESCE(device_patch_state.first_detected_missing_at, now()) END,
				sla_due_at = CASE WHEN device_patch_state.state IN ('installed', 'superseded') THEN NULL ELSE device_patch_state.sla_due_at END,
				policy_id  = CASE WHEN device_patch_state.state IN ('installed', 'superseded') THEN NULL ELSE device_patch_state.policy_id END,
				state = CASE WHEN device_patch_state.state = 'failed' THEN 'failed' ELSE 'missing' END`,
			deviceUUID, patchID)
	default:
		return fmt.Errorf("patch diff: unknown state %q", state)
	}
	if err != nil {
		return fmt.Errorf("upsert device_patch_state (%s): %w", state, err)
	}
	return nil
}

// NotApplicable records the agent's NOT_APPLICABLE answer to an install_patch
// for kb: the diff stops offering it while the device stays on its current
// build, and the open row for it goes. Only an answer to an install_patch we
// issued to this agent for this KB counts - otherwise an endpoint could hide a
// missing patch just by claiming it doesn't apply. Returns false when nothing
// was recorded.
func (df *Differ) NotApplicable(ctx context.Context, deviceUUID, agentUUID, kb, commandID, reason string) (bool, error) {
	kb = ingest.NormalizeKB(kb)
	if kb == "" || commandID == "" {
		return false, nil
	}
	tx, err := df.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	var patchID string
	err = tx.QueryRow(ctx, `SELECT id FROM patch_catalog WHERE vendor = 'microsoft' AND kb_or_advisory_id = $1`, kb).Scan(&patchID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var ours bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM agent_commands
		               WHERE id::text = $1 AND agent_id = $2 AND command_type = 'install_patch'
		                 AND upper(payload->>'kb') IN ($3, substr($3, 3)))`, commandID, agentUUID, kb).Scan(&ours); err != nil {
		return false, err
	}
	if !ours {
		return false, nil
	}
	var build *string
	var ubr *int
	if err := tx.QueryRow(ctx, `SELECT os_build, os_ubr FROM devices WHERE id = $1`, deviceUUID).Scan(&build, &ubr); err != nil {
		return false, err
	}
	full := deref(build)
	if ubr != nil {
		full = fmt.Sprintf("%s.%d", full, *ubr)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_patch_not_applicable (device_id, patch_id, full_build, command_id, reason)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''))
		ON CONFLICT (device_id, patch_id) DO UPDATE SET
			full_build = EXCLUDED.full_build, command_id = EXCLUDED.command_id, reason = EXCLUDED.reason, reported_at = now()`,
		deviceUUID, patchID, full, commandID, clip(reason, 500)); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM device_patch_state
		WHERE device_id = $1 AND patch_id = $2 AND state IN ('missing', 'failed', 'pending_reboot', 'superseded')`,
		deviceUUID, patchID); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
