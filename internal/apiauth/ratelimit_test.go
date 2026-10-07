package apiauth

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	clock := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	l := newLimiter()
	l.now = func() time.Time { return clock }

	// 60/min -> burst 6, refill 1/s.
	for i := 1; i <= 6; i++ {
		if ok, _, _ := l.allow("a", 60); !ok {
			t.Fatalf("request %d within burst was rejected", i)
		}
	}
	ok, retry, warn := l.allow("a", 60)
	if ok || retry <= 0 || retry > time.Second || !warn {
		t.Fatalf("7th request: ok=%v retry=%v warn=%v, want rejected, retry in (0,1s], warn", ok, retry, warn)
	}
	if _, _, warn := l.allow("a", 60); warn {
		t.Fatalf("second rejection within a minute should not warn again")
	}

	// Another client has its own bucket.
	if ok, _, _ := l.allow("b", 60); !ok {
		t.Fatalf("client b was limited by client a's usage")
	}

	// One second later exactly one token has refilled - rejected requests must
	// not have consumed future tokens.
	clock = clock.Add(time.Second)
	if ok, _, _ := l.allow("a", 60); !ok {
		t.Fatalf("token did not refill after 1s")
	}
	if ok, _, _ := l.allow("a", 60); ok {
		t.Fatalf("got two tokens after 1s, want one")
	}

	// Raising the limit in the DB applies from the next request on, with no
	// back-credit: the second since the last token accrued at the old 1/s, so
	// exactly 1 token is there at the moment of change...
	clock = clock.Add(time.Second)
	if ok, _, _ := l.allow("a", 600); !ok {
		t.Fatalf("token accrued at the old rate was lost on limit change")
	}
	if ok, _, _ := l.allow("a", 600); ok {
		t.Fatalf("limit change granted back-credit at the new rate")
	}
	// ...and from then on 600/min refills 10/s.
	clock = clock.Add(time.Second)
	for i := 1; i <= 10; i++ {
		if ok, _, _ := l.allow("a", 600); !ok {
			t.Fatalf("1s after raising the limit, request %d of 10 was rejected", i)
		}
	}
	if ok, _, _ := l.allow("a", 600); ok {
		t.Fatalf("got 11 tokens in 1s at 600/min, want 10")
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want int
	}{{100 * time.Millisecond, 1}, {time.Second, 1}, {1500 * time.Millisecond, 2}, {0, 1}} {
		if got := (&RateLimitedError{RetryAfter: c.d}).RetryAfterSeconds(); got != c.want {
			t.Errorf("RetryAfter %v -> %d, want %d", c.d, got, c.want)
		}
	}
}
