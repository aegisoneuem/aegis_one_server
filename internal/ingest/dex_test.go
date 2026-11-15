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
		CpuAvg: 12.5, CpuMin: -3, CpuMax: 140, MemUsedAvg: 55, MemUsedMin: math.NaN(), MemUsedMax: math.Inf(1)}, now, false)
	if !ok || !r.Time.Equal(now.Add(-time.Hour)) || *r.WindowSeconds != 300 || *r.SampleCount != 20 {
		t.Fatalf("row %+v ok=%v", r, ok)
	}
	if f(r.CPUAvg) != 12.5 || f(r.CPUMin) != 0 || f(r.CPUMax) != 100 || f(r.RAMAvg) != 55 || r.RAMMin != nil || r.RAMMax != nil {
		t.Errorf("clamping: cpu %v/%v/%v ram %v/%v/%v", f(r.CPUAvg), f(r.CPUMin), f(r.CPUMax), f(r.RAMAvg), f(r.RAMMin), f(r.RAMMax))
	}

	// Wrong endpoint clock: receive time instead.
	for _, ts := range []int64{0, now.Add(-40 * 24 * time.Hour).Unix(), now.Add(time.Hour).Unix()} {
		r, _ := DexRowFrom("dev", &aegisonev1.DexTelemetry{CollectedAt: ts, SampleCount: 1, CpuAvg: 1}, now, false)
		if !r.Time.Equal(now) {
			t.Errorf("collected_at %d -> %v, want now", ts, r.Time)
		}
	}
	// Bad window ignored.
	if r, _ := DexRowFrom("dev", &aegisonev1.DexTelemetry{SampleCount: 1, WindowSeconds: 90000}, now, false); r.WindowSeconds != nil {
		t.Error("window over a day kept")
	}
	// Empty report dropped.
	if _, ok := DexRowFrom("dev", &aegisonev1.DexTelemetry{CollectedAt: now.Unix()}, now, false); ok {
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

func TestExtendedDex(t *testing.T) {
	now := time.Now()
	base := func() *aegisonev1.DexTelemetry {
		return &aegisonev1.DexTelemetry{CollectedAt: now.Unix(), SampleCount: 20, CpuAvg: 10, MemUsedAvg: 40}
	}
	b := func(p *bool) string {
		if p == nil {
			return "nil"
		}
		if *p {
			return "true"
		}
		return "false"
	}

	// Agent from 2026-11-12: nothing extended -> every new column NULL, not "no battery".
	r, _ := DexRowFrom("d", base(), now, true)
	if r.DiskQueueAvg != nil || r.NetLossPct != nil || r.BatteryPresent != nil || r.WifiPresent != nil {
		t.Errorf("old agent: disk=%v net=%v battery=%s wifi=%s", r.DiskQueueAvg, r.NetLossPct, b(r.BatteryPresent), b(r.WifiPresent))
	}

	// Desktop: disk + network, no battery, no Wi-Fi adapter.
	d := base()
	d.DiskQueueAvg, d.DiskIopsAvg, d.DiskIopsMax, d.DiskLatencyMsAvg = 0.4, 120, 900, 2.5
	d.NetTarget, d.NetRttMsAvg, d.NetRttMsMin, d.NetRttMsMax, d.NetLossPct = "192.168.1.1", 1.2, 0.8, 3, 0
	d.BatteryAcOnline = true
	r, _ = DexRowFrom("d", d, now, false)
	if r.DiskIOPSMax == nil || *r.DiskIOPSMax != 900 || r.NetRTTAvg == nil || *r.NetLossPct != 0 {
		t.Errorf("desktop disk/net: %+v", r)
	}
	if b(r.BatteryPresent) != "false" || b(r.BatteryAC) != "true" || r.BatteryAvg != nil || b(r.WifiPresent) != "false" {
		t.Errorf("desktop flags: battery=%s ac=%s wifi=%s", b(r.BatteryPresent), b(r.BatteryAC), b(r.WifiPresent))
	}
	if r.NetTarget != nil {
		t.Error("net_target stored with network names off")
	}

	// Laptop on battery and Wi-Fi, every ping lost, names on.
	l := base()
	l.NetTarget, l.NetLossPct, l.NetRttMsAvg = "10.0.0.1", 100, 0
	l.BatteryPresent, l.BatteryChargePctAvg, l.BatteryChargePctMin, l.BatteryChargePctMax = true, 55, 50, 61
	l.WifiPresent, l.WifiConnected, l.WifiSignalPctAvg, l.WifiSsid = true, true, 72, "CorpWiFi"
	r, _ = DexRowFrom("d", l, now, true)
	if r.NetRTTAvg != nil || *r.NetLossPct != 100 || *r.NetTarget != "10.0.0.1" {
		t.Errorf("all lost: rtt=%v loss=%v", r.NetRTTAvg, r.NetLossPct)
	}
	if *r.BatteryAvg != 55 || *r.WifiSignalAvg != 72 || r.WifiSSID == nil || *r.WifiSSID != "CorpWiFi" || r.DiskQueueAvg != nil {
		t.Errorf("laptop: %+v", r)
	}
	r, _ = DexRowFrom("d", l, now, false)
	if r.WifiSSID != nil || r.NetTarget != nil {
		t.Error("names stored with network names off")
	}

	// Bad numbers: negative / NaN become NULL.
	x := base()
	x.DiskQueueAvg, x.DiskLatencyMsAvg = -1, math.NaN()
	x.DiskIopsAvg = 5
	r, _ = DexRowFrom("d", x, now, false)
	if r.DiskQueueAvg != nil || r.DiskLatAvg != nil || *r.DiskIOPSAvg != 5 {
		t.Errorf("bad numbers: %v %v %v", r.DiskQueueAvg, r.DiskLatAvg, r.DiskIOPSAvg)
	}
}
