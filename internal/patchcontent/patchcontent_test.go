package patchcontent

import (
	"net/url"
	"testing"
)

func TestHostAllowed(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://dl.delivery.mp.microsoft.com/filestreamingservice/files/x/public/a.msu": true,
		"https://catalog.s.download.windowsupdate.com/c/msdownload/a.cab":               true,
		"http://download.windowsupdate.com/msdownload/a.cab":                            true,
		"https://download.microsoft.com/download/a.msu":                                 true,
		"https://evil.com/download.windowsupdate.com/a.msu":                             false,
		"https://download.windowsupdate.com.evil.com/a.msu":                             false,
		"https://notdownload.windowsupdate.com/a.msu":                                   false,
		"ftp://download.windowsupdate.com/a.msu":                                        false,
		"file:///etc/passwd":                                                            false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := hostAllowed(u); got != want {
			t.Errorf("hostAllowed(%s) = %v, want %v", raw, got, want)
		}
	}
}
