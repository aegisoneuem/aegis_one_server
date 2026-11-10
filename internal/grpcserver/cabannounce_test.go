package grpcserver

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"aegis-one/internal/cabfeed"
)

func newCabServer(sha string) *Server {
	s := New(slog.Default(), nil, nil, nil, nil)
	s.content = &contentStore{cab: &cabfeed.Catalog{SHA256: sha}}
	return s
}

func TestCabManifestOff(t *testing.T) {
	s := newCabServer("aaa")
	if s.cabManifestMessage() == nil {
		t.Fatal("manifest on by default")
	}
	s.SetCabAnnounce(false, 0)
	if s.cabManifestMessage() != nil {
		t.Fatal("manifest sent while off")
	}
	ch, _ := s.register("dev-1")
	if len(ch) != 0 {
		t.Fatal("register queued a manifest while off")
	}
}

func TestAnnounceSpread(t *testing.T) {
	s := newCabServer("bbb")
	queues := map[string]int{}
	for _, dev := range []string{"d1", "d2", "d3", "d4"} {
		ch, _ := s.register(dev)
		<-ch // the manifest register queues on connect
		queues[dev] = 0
	}
	start := time.Now()
	s.announceSpread(context.Background(), "bbb", 120*time.Millisecond)
	if took := time.Since(start); took < 80*time.Millisecond {
		t.Errorf("not spread out: %v for 4 agents over 120ms", took)
	}
	for dev := range queues {
		ch := s.clients[dev]
		if len(ch) != 1 {
			t.Errorf("%s got %d manifests, want 1", dev, len(ch))
			continue
		}
		if m := <-ch; m.GetCabManifest().GetSha256() != "bbb" {
			t.Errorf("%s got %v", dev, m)
		}
	}

	// A newer cab becoming current stops the old round.
	s.content.cab = &cabfeed.Catalog{SHA256: "ccc"}
	s.announceSpread(context.Background(), "bbb", 40*time.Millisecond)
	for dev, ch := range s.clients {
		if len(ch) != 0 {
			t.Errorf("%s got a manifest for a superseded cab", dev)
		}
	}
}
