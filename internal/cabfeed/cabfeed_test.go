package cabfeed

import (
	"net/http"
	"testing"
)

func TestSameVersion(t *testing.T) {
	const etag = `"0325ba4d352dd1:0"`
	const size = 674424266
	resp := func(status int, etag string, length int64) *http.Response {
		r := &http.Response{StatusCode: status, Header: http.Header{}, ContentLength: length}
		if etag != "" {
			r.Header.Set("ETag", etag)
		}
		return r
	}

	cases := []struct {
		name     string
		resp     *http.Response
		lastETag string
		curSize  int64
		want     bool
	}{
		{"edge ignored If-None-Match, same cab", resp(200, etag, size), etag, size, true},
		{"new ETag = new cab", resp(200, `"newer:0"`, size), etag, size, false},
		{"same ETag but different size", resp(200, etag, size+1), etag, size, false},
		{"first ever download (nothing stored)", resp(200, etag, size), "", 0, false},
		{"no ETag from server", resp(200, "", size), etag, size, false},
		{"304 is handled by the caller, not here", resp(304, etag, size), etag, size, false},
	}
	for _, c := range cases {
		if got := sameVersion(c.resp, c.lastETag, c.curSize); got != c.want {
			t.Errorf("%s: sameVersion = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCheckRedirect(t *testing.T) {
	req := func(u string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, ok := range []string{
		"https://download.windowsupdate.com/wsusscn2.cab",
		"https://catalog.s.download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab",
		"https://go.microsoft.com/fwlink/?LinkID=74689",
		"https://WINDOWSUPDATE.COM/x",
	} {
		if err := checkRedirect(req(ok), nil); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://download.windowsupdate.com/wsusscn2.cab", // downgrade
		"https://windowsupdate.com.evil.example/wsusscn2.cab",
		"https://evilmicrosoft.com/wsusscn2.cab",
		"https://cdn.example.net/wsusscn2.cab",
		"ftp://microsoft.com/wsusscn2.cab",
	} {
		if err := checkRedirect(req(bad), nil); err == nil {
			t.Errorf("%s: followed", bad)
		}
	}
	if err := checkRedirect(req("https://download.windowsupdate.com/x"), make([]*http.Request, 5)); err == nil {
		t.Error("redirect loop followed")
	}
}
