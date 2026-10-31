package grpcserver

// PatchBaseline push (see internal/patchbaseline). Each connected agent gets
// the baseline for its own build: on connect (build from the devices row), when
// its DeviceStateReport shows a new build, and when the MSRC feed brings a newer
// KB (WatchBaseline). What was last sent is kept per connection so an
// unchanged baseline is not re-sent. Like CabManifest, the agent contract has
// no signature field for it; it is only a hint, never an install trigger.

import (
	"context"
	"sync"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/identity"
	"aegis-one/internal/patchbaseline"

	"github.com/jackc/pgx/v5/pgxpool"
)

type baselineStore struct {
	pool *pgxpool.Pool

	mu      sync.Mutex
	index   patchbaseline.Index // nil until the first WatchBaseline load
	devices map[string]*baselineDevice
}

type baselineDevice struct {
	ch   chan *aegisonev1.ServerMessage
	dev  patchbaseline.Device
	sent string // patchbaseline.Key of the last baseline queued
}

// EnableBaseline turns on PatchBaseline push. Call before serving; then run
// WatchBaseline.
func (s *Server) EnableBaseline(pool *pgxpool.Pool) {
	s.baseline = &baselineStore{pool: pool, devices: make(map[string]*baselineDevice)}
}

// WatchBaseline reloads the fixed-build index every interval and queues a new
// baseline to every connected agent whose baseline changed. It also retries
// agents whose queue was full last time.
func (s *Server) WatchBaseline(ctx context.Context, interval time.Duration) {
	check := func() {
		ix, err := patchbaseline.Load(ctx, s.baseline.pool)
		if err != nil {
			if ctx.Err() == nil {
				s.log.Warn("baseline watch: load fixed builds", "error", err.Error())
			}
			return
		}
		b := s.baseline
		b.mu.Lock()
		first := b.index == nil
		b.index = ix
		sent := 0
		for deviceID, d := range b.devices {
			if s.queueBaselineLocked(deviceID, d) {
				sent++
			}
		}
		b.mu.Unlock()
		if first {
			s.log.Info("patch baseline: index loaded", "build_families", len(ix))
		}
		if sent > 0 {
			s.log.Info("patch baseline: updated baselines sent", "agents", sent)
		}
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

// baselineConnected starts tracking a newly registered connection, using the
// build saved from the device's last report.
func (s *Server) baselineConnected(ctx context.Context, known *identity.Known, ch chan *aegisonev1.ServerMessage) {
	if s.baseline == nil || known == nil {
		return
	}
	dev, err := patchbaseline.LoadDevice(ctx, s.baseline.pool, known.DeviceUUID)
	if err != nil {
		s.log.Warn("patch baseline: load device", "device_id", known.DeviceID, "error", err.Error())
		return
	}
	b := s.baseline
	b.mu.Lock()
	defer b.mu.Unlock()
	// The stream may have ended while the device was loading; its unregister
	// already ran, so don't track a dead queue.
	s.mu.Lock()
	live := s.clients[known.DeviceID] == ch
	s.mu.Unlock()
	if !live {
		return
	}
	d := &baselineDevice{ch: ch, dev: dev}
	b.devices[known.DeviceID] = d
	if s.queueBaselineLocked(known.DeviceID, d) {
		s.log.Info("patch baseline sent on connect", "device_id", known.DeviceID, "build", dev.FullBuild())
	}
}

// baselineDeviceState updates the tracked build from a DeviceStateReport and
// sends a new baseline if that changes it.
func (s *Server) baselineDeviceState(deviceID string, dev patchbaseline.Device) {
	if s.baseline == nil {
		return
	}
	b := s.baseline
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.devices[deviceID]
	if !ok {
		return
	}
	d.dev = dev
	if s.queueBaselineLocked(deviceID, d) {
		s.log.Info("patch baseline sent for new build", "device_id", deviceID, "build", dev.FullBuild())
	}
}

// baselineDisconnected stops tracking ch (only if it is still the device's
// current connection; see unregister).
func (s *Server) baselineDisconnected(deviceID string, ch chan *aegisonev1.ServerMessage) {
	if s.baseline == nil {
		return
	}
	b := s.baseline
	b.mu.Lock()
	if d, ok := b.devices[deviceID]; ok && d.ch == ch {
		delete(b.devices, deviceID)
	}
	b.mu.Unlock()
}

// queueBaselineLocked queues d's baseline if it differs from the last one
// sent. It never blocks: on a full queue it leaves d.sent alone so the next
// WatchBaseline tick retries. Callers hold b.mu.
func (s *Server) queueBaselineLocked(deviceID string, d *baselineDevice) bool {
	if s.baseline.index == nil {
		return false
	}
	bl, ok := s.baseline.index.For(d.dev)
	if !ok {
		return false
	}
	key := patchbaseline.Key(bl)
	if key == d.sent {
		return false
	}
	bl.IssuedAt = time.Now().Unix()
	select {
	case d.ch <- &aegisonev1.ServerMessage{Payload: &aegisonev1.ServerMessage_PatchBaseline{PatchBaseline: bl}}:
		d.sent = key
		s.log.Debug("patch baseline queued", "device_id", deviceID, "build", bl.GetBuild(), "latest_kbs", bl.GetLatestKbs())
		return true
	default:
		return false
	}
}
