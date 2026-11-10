package grpcserver

import (
	"log/slog"
	"testing"
)

func TestDisconnect(t *testing.T) {
	s := New(slog.Default(), nil, nil, nil, nil)
	if s.Disconnect("dev-1") {
		t.Fatal("no stream, but Disconnect reported one")
	}
	ch, kick := s.register("dev-1")
	if !s.Connected("dev-1") {
		t.Fatal("not connected after register")
	}
	if !s.Disconnect("dev-1") {
		t.Fatal("live stream not reported")
	}
	select {
	case <-kick:
	default:
		t.Fatal("kick channel not closed")
	}
	if s.Disconnect("dev-1") {
		t.Fatal("second Disconnect must be a no-op")
	}
	s.unregister("dev-1", ch)
	if s.Connected("dev-1") {
		t.Fatal("still connected after unregister")
	}

	// A reconnect while the old stream is still up: Disconnect ends both.
	_, kickOld := s.register("dev-2")
	_, kickNew := s.register("dev-2")
	if !s.Disconnect("dev-2") {
		t.Fatal("streams not reported")
	}
	<-kickOld
	<-kickNew

	// The old stream's unregister must not drop the new stream's kick channel.
	old, _ := s.register("dev-3")
	_, kick3 := s.register("dev-3")
	s.unregister("dev-3", old)
	if !s.Disconnect("dev-3") {
		t.Fatal("new stream's kick lost")
	}
	<-kick3
}
