package ingest

// DEX ingest (migration 0024):
//   - DexTelemetry arrives every 5 minutes from every agent. At 50k agents that is
//     ~170 messages/s, so rows go through DexWriter: an in-memory queue flushed with
//     COPY in batches, never one INSERT per message.
//   - FullInventoryReport.identity and .dex_health are applied inside the inventory
//     transaction (identityInfo, dexHealth below).

import (
	"context"
	"log/slog"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/identity"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxAppFaults = 500

	dexQueueSize    = 20000           // ~2 minutes of a 50k fleet; full queue = drop + count
	dexBatchSize    = 1000            // rows per COPY
	dexFlushEvery   = 2 * time.Second // upper bound on how long a row waits
	dexMaxAge       = 35 * 24 * time.Hour
	dexMaxClockSkew = 10 * time.Minute
)

// DexRow is one validated DexTelemetry window for device_dex_metrics.
type DexRow struct {
	DeviceUUID             string
	Time                   time.Time
	CPUAvg, CPUMin, CPUMax *float32
	RAMAvg, RAMMin, RAMMax *float32
	WindowSeconds          *int32
	SampleCount            *int32
}

// DexRowFrom validates one report. ok is false for a report with nothing in it.
// A timestamp outside [now-35d, now+10m] (a wrong endpoint clock) is replaced by
// the receive time rather than dropping the data.
func DexRowFrom(deviceUUID string, t *aegisonev1.DexTelemetry, now time.Time) (DexRow, bool) {
	r := DexRow{
		DeviceUUID: deviceUUID,
		CPUAvg:     pct(t.GetCpuAvg()), CPUMin: pct(t.GetCpuMin()), CPUMax: pct(t.GetCpuMax()),
		RAMAvg: pct(t.GetMemUsedAvg()), RAMMin: pct(t.GetMemUsedMin()), RAMMax: pct(t.GetMemUsedMax()),
	}
	if t.GetSampleCount() <= 0 && t.GetCpuAvg() == 0 && t.GetMemUsedAvg() == 0 {
		return r, false
	}
	if n := t.GetSampleCount(); n > 0 {
		r.SampleCount = &n
	}
	if w := t.GetWindowSeconds(); w > 0 && w <= 86400 {
		r.WindowSeconds = &w
	}
	r.Time = reportTime(t.GetCollectedAt(), now)
	return r, true
}

// pct keeps a percentage in 0..100; NaN / Inf become NULL.
func pct(v float64) *float32 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	f := float32(math.Max(0, math.Min(100, v)))
	return &f
}

// DexWriter batches DexTelemetry rows into device_dex_metrics.
//
// Durability: the agent drops a report from its buffer once stream.Send
// succeeds (this contract has no ack), so a row still queued here when the
// process dies is lost. That is at most a few seconds of 5-minute averages;
// shutdown drains the queue.
type DexWriter struct {
	pool    *pgxpool.Pool
	log     *slog.Logger
	ch      chan DexRow
	dropped atomic.Int64
	written atomic.Int64

	mu     sync.RWMutex
	closed bool
}

func NewDexWriter(pool *pgxpool.Pool, log *slog.Logger) *DexWriter {
	return &DexWriter{pool: pool, log: log, ch: make(chan DexRow, dexQueueSize)}
}

// Add queues one report without blocking the agent stream. It returns false
// when the report is empty or the queue is full (counted as dropped).
func (w *DexWriter) Add(known *identity.Known, t *aegisonev1.DexTelemetry) bool {
	row, ok := DexRowFrom(known.DeviceUUID, t, time.Now())
	if !ok {
		return false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		w.dropped.Add(1)
		return false
	}
	select {
	case w.ch <- row:
		return true
	default:
		w.dropped.Add(1)
		return false
	}
}

// Stats returns rows written and dropped since start.
func (w *DexWriter) Stats() (written, dropped int64) { return w.written.Load(), w.dropped.Load() }

// Run flushes until ctx is cancelled, then drains what is queued. Cancel ctx
// only after the gRPC server has stopped, so no report arrives after the drain.
func (w *DexWriter) Run(ctx context.Context) {
	tick := time.NewTicker(dexFlushEvery)
	defer tick.Stop()
	batch := make([]DexRow, 0, dexBatchSize)
	var lastDropped int64
	flush := func(fctx context.Context) {
		if len(batch) > 0 {
			w.flush(fctx, batch)
			batch = batch[:0]
		}
		if d := w.dropped.Load(); d != lastDropped {
			w.log.Warn("dex telemetry dropped (queue full)", "dropped_total", d, "since_last", d-lastDropped)
			lastDropped = d
		}
	}
	for {
		select {
		case r := <-w.ch:
			batch = append(batch, r)
			if len(batch) >= dexBatchSize {
				flush(ctx)
			}
		case <-tick.C:
			flush(ctx)
		case <-ctx.Done():
			w.mu.Lock()
			w.closed = true
			w.mu.Unlock()
			dctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			for {
				select {
				case r := <-w.ch:
					batch = append(batch, r)
					if len(batch) >= dexBatchSize {
						flush(dctx)
					}
					continue
				default:
				}
				break
			}
			flush(dctx)
			cancel()
			return
		}
	}
}

var dexColumns = []string{"time", "device_id", "cpu_pct", "cpu_min_pct", "cpu_max_pct",
	"ram_pct", "ram_min_pct", "ram_max_pct", "window_seconds", "sample_count"}

func (r DexRow) values() []any {
	return []any{r.Time, r.DeviceUUID, r.CPUAvg, r.CPUMin, r.CPUMax, r.RAMAvg, r.RAMMin, r.RAMMax, r.WindowSeconds, r.SampleCount}
}

// flush COPYs one batch. A batch fails as a whole (e.g. one device row was
// deleted meanwhile), so on error it falls back to row-by-row inserts to keep
// the good rows.
func (w *DexWriter) flush(ctx context.Context, batch []DexRow) {
	rows := dedupDex(batch)
	src := make([][]any, len(rows))
	for i, r := range rows {
		src[i] = r.values()
	}
	n, err := w.pool.CopyFrom(ctx, pgx.Identifier{"device_dex_metrics"}, dexColumns, pgx.CopyFromRows(src))
	if err == nil {
		w.written.Add(n)
		return
	}
	w.log.Warn("dex telemetry COPY failed; inserting row by row", "rows", len(rows), "error", err.Error())
	var ok, failed int
	for _, r := range rows {
		if _, err := w.pool.Exec(ctx, `
			INSERT INTO device_dex_metrics (time, device_id, cpu_pct, cpu_min_pct, cpu_max_pct,
			    ram_pct, ram_min_pct, ram_max_pct, window_seconds, sample_count)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, r.values()...); err != nil {
			failed++
			continue
		}
		ok++
	}
	w.written.Add(int64(ok))
	if failed > 0 {
		w.log.Error("dex telemetry rows not saved", "failed", failed, "saved", ok)
	}
}

// dedupDex drops repeats of the same (device, time) inside one batch: the agent
// resends a report if its send succeeded but the buffer delete did not.
func dedupDex(batch []DexRow) []DexRow {
	type key struct {
		dev string
		t   int64
	}
	seen := make(map[key]bool, len(batch))
	out := make([]DexRow, 0, len(batch))
	for _, r := range batch {
		k := key{r.DeviceUUID, r.Time.Unix()}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}

// identityInfo saves who is on the machine and its domain state on the device
// row. Empty values keep what is stored: the agent leaves logged_on_user empty
// when nobody is logged on (the column is the LAST logged-on user), and both
// domain fields empty when it could not read the join state.
func identityInfo(ctx context.Context, tx pgx.Tx, dev string, id *aegisonev1.IdentityInfo, now time.Time) error {
	var joined *bool
	domain := nullableN(id.GetMachineDomain(), 255)
	if domain != nil {
		j := id.GetDomainJoined()
		joined = &j
	}
	var boot *time.Time
	if s := id.GetBootTime(); s > 0 {
		if ts := time.Unix(s, 0); ts.Before(now.Add(dexMaxClockSkew)) && ts.Year() >= 2000 {
			boot = &ts
		}
	}
	_, err := tx.Exec(ctx, `
		UPDATE devices SET
		    last_logged_on_user = coalesce($2, last_logged_on_user),
		    domain_name         = coalesce($3, domain_name),
		    is_domain_joined    = coalesce($4, is_domain_joined),
		    last_boot_at        = coalesce($5, last_boot_at)
		WHERE id = $1`, dev, nullableN(id.GetLoggedOnUser(), 255), domain, joined, boot)
	return err
}

// dexHealth replaces the device's stability snapshot and per-app faults. A
// report with window_days 0 carries nothing (non-Windows builds send an empty
// message) and is ignored.
func dexHealth(ctx context.Context, tx pgx.Tx, dev string, h *aegisonev1.DexHealth, collectedAt time.Time) (int, error) {
	if h.GetWindowDays() <= 0 {
		return 0, nil
	}
	var boot *int64
	if ms := h.GetBootDurationMs(); ms > 0 {
		boot = &ms
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_dex_health (device_id, window_days, unexpected_shutdowns, bugchecks, dirty_power_events,
		    app_crashes, app_hangs, boot_duration_ms, collected_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (device_id) DO UPDATE SET
		    window_days = EXCLUDED.window_days, unexpected_shutdowns = EXCLUDED.unexpected_shutdowns,
		    bugchecks = EXCLUDED.bugchecks, dirty_power_events = EXCLUDED.dirty_power_events,
		    app_crashes = EXCLUDED.app_crashes, app_hangs = EXCLUDED.app_hangs,
		    boot_duration_ms = EXCLUDED.boot_duration_ms, collected_at = EXCLUDED.collected_at, updated_at = now()`,
		dev, h.GetWindowDays(), nonNeg(h.GetUnexpectedShutdowns()), nonNeg(h.GetBugchecks()),
		nonNeg(h.GetDirtyPowerEvents()), nonNeg(h.GetAppCrashes()), nonNeg(h.GetAppHangs()), boot, collectedAt); err != nil {
		return 0, err
	}

	// Same app reported twice: keep the larger counts.
	faults := map[string][2]int32{}
	for _, f := range h.GetAppFaults() {
		name := clipN(f.GetName(), 255)
		if name == "" {
			continue
		}
		c := faults[name]
		faults[name] = [2]int32{max(c[0], nonNeg(f.GetCrashes())), max(c[1], nonNeg(f.GetHangs()))}
	}
	names := make([]string, 0, len(faults))
	for n := range faults {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { // keep the worst offenders if over the cap
		a, b := faults[names[i]], faults[names[j]]
		if a[0]+a[1] != b[0]+b[1] {
			return a[0]+a[1] > b[0]+b[1]
		}
		return names[i] < names[j]
	})
	if len(names) > maxAppFaults {
		names = names[:maxAppFaults]
	}
	if _, err := tx.Exec(ctx, `DELETE FROM device_app_faults WHERE device_id = $1`, dev); err != nil {
		return 0, err
	}
	rows := make([][]any, len(names))
	for i, n := range names {
		rows[i] = []any{dev, n, faults[n][0], faults[n][1]}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"device_app_faults"},
		[]string{"device_id", "app_name", "crashes", "hangs"}, pgx.CopyFromRows(rows)); err != nil {
		return 0, err
	}
	return len(rows), nil
}

func nonNeg(n int32) int32 { return max(n, 0) }

// reportTime is the agent's collected_at (unix seconds) when it is plausible,
// otherwise now.
func reportTime(sec int64, now time.Time) time.Time {
	if sec > 0 {
		if ts := time.Unix(sec, 0); ts.After(now.Add(-dexMaxAge)) && ts.Before(now.Add(dexMaxClockSkew)) {
			return ts
		}
	}
	return now
}
