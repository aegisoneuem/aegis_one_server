package apiauth

import (
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimitedError is returned by Authenticate when the token is valid but its
// client has used up its api_clients.rate_limit_per_minute.
type RateLimitedError struct {
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string { return "rate limit exceeded" }

// RetryAfterSeconds is the Retry-After header value (whole seconds, at least 1).
func (e *RateLimitedError) RetryAfterSeconds() int {
	return max(1, int(math.Ceil(e.RetryAfter.Seconds())))
}

// limiter keeps one token bucket per API client. Refill rate is perMinute/60
// per second; burst is 10% of the per-minute limit (min 1). A burst of the full
// minute would let a client send ~2x its limit across a minute boundary; 10%
// keeps any rolling minute near the configured number.
//
// In-memory and per server instance: with N replicas a client can get up to N
// times its limit. Clients are few and admin-created, so entries are never
// evicted.
type limiter struct {
	mu      sync.Mutex
	clients map[string]*clientBucket
	now     func() time.Time // injectable for tests
}

type clientBucket struct {
	lim       *rate.Limiter
	perMinute int
	lastWarn  time.Time
}

func newLimiter() *limiter {
	return &limiter{clients: make(map[string]*clientBucket), now: time.Now}
}

func burstFor(perMinute int) int {
	return max(1, perMinute/10)
}

// allow takes one request from clientID's bucket. It returns ok=false and how
// long until a request would be allowed when the bucket is empty, plus whether
// this rejection should be logged (at most once a minute per client). A changed
// perMinute (edited in the DB) takes effect immediately.
func (l *limiter) allow(clientID string, perMinute int) (ok bool, retryAfter time.Duration, warn bool) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.clients[clientID]
	if b == nil {
		b = &clientBucket{lim: rate.NewLimiter(rate.Limit(float64(perMinute)/60), burstFor(perMinute)), perMinute: perMinute}
		b.lim.SetBurstAt(now, burstFor(perMinute)) // start full, measured from now
		l.clients[clientID] = b
	} else if b.perMinute != perMinute {
		b.lim.SetLimitAt(now, rate.Limit(float64(perMinute)/60))
		b.lim.SetBurstAt(now, burstFor(perMinute))
		b.perMinute = perMinute
	}

	r := b.lim.ReserveN(now, 1)
	if !r.OK() {
		return false, time.Minute, true
	}
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now) // don't consume a future token for a rejected request
		warn = now.Sub(b.lastWarn) >= time.Minute
		if warn {
			b.lastWarn = now
		}
		return false, d, warn
	}
	return true, 0, false
}
