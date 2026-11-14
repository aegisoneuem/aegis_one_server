package ingest

import (
	"math"
	"testing"
	"time"

	aegisonev1 "aegis-one/gen/aegisone/v1"
)

func TestDexRowFrom(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	f := func(p *float32) float32 {
		if p == nil {
			return -1
		}
		return *p
	}

	r, ok := DexRowFrom("dev", &aegisonev1.DexTelemetry{CollectedAt: now.Add(-time.Hour).Unix(), WindowSeconds: 300, SampleCount: 20,
		CpuAvg: 12.5, CpuMin: -3, CpuMax: 140, MemUsedAvg: 55, MemUsedMin: math.NaN(), MemUsedMax: math.Inf(1)}, now)
	if !ok || !r.Time.Equal(now.Add(-time.Hour)) || *r.WindowSeconds != 300 || *r.SampleCount != 20 {
		t.Fatalf("row %+v ok=%v", r, ok)
	}
	if f(r.CPUAvg) != 12.5 || f(r.CPUMin) != 0 || f(r.CPUMax) != 100 || f(r.RAMAvg) != 55 || r.RAMMin != nil || r.RAMMax != nil {
		t.Errorf("clamping: cpu %v/%v/%v ram %v/%v/%v", f(r.CPUAvg), f(r.CPUMin), f(r.CPUMax), f(r.RAMAvg), f(r.RAMMin), f(r.RAMMax))
	}

	// Wrong endpoint clock: receive time instead.
	for _, ts := range []int64{0, now.Add(-40 * 24 * time.Hour).Unix(), now.Add(time.Hour).Unix()} {
		r, _ := DexRowFrom("dev", &aegisonev1.DexTelemetry{CollectedAt: ts, SampleCount: 1, CpuAvg: 1}, now)
		if !r.Time.Equal(now) {
			t.Errorf("collected_at %d -> %v, want now", ts, r.Time)
		}
	}
	// Bad window ignored.
	if r, _ := DexRowFrom("dev", &aegisonev1.DexTelemetry{SampleCount: 1, WindowSeconds: 90000}, now); r.WindowSeconds != nil {
		t.Error("window over a day kept")
	}
	// Empty report dropped.
	if _, ok := DexRowFrom("dev", &aegisonev1.DexTelemetry{CollectedAt: now.Unix()}, now); ok {
		t.Error("empty report accepted")
	}
}

func TestDedupDex(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	in := []DexRow{{DeviceUUID: "a", Time: t0}, {DeviceUUID: "a", Time: t0}, {DeviceUUID: "b", Time: t0}, {DeviceUUID: "a", Time: t0.Add(time.Minute)}}
	if got := dedupDex(in); len(got) != 3 {
		t.Errorf("dedup kept %d, want 3", len(got))
	}
}
