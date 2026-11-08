package dbmigrate

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"aegis-one/db"
)

func TestLoadSortsAndNormalizesCRLF(t *testing.T) {
	fsys := fstest.MapFS{
		"migrations/0002_b.sql": {Data: []byte("SELECT 2;\r\n")},
		"migrations/0001_a.sql": {Data: []byte("SELECT 1;\n")},
		"migrations/README.md":  {Data: []byte("ignored")},
	}
	got, err := Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "0001_a.sql" || got[1].Version != "0002" {
		t.Fatalf("order/filter wrong: %+v", got)
	}
	lf, _ := Load(fstest.MapFS{"migrations/0002_b.sql": {Data: []byte("SELECT 2;\n")}})
	if got[1].Checksum != lf[0].Checksum || strings.Contains(got[1].SQL, "\r") {
		t.Fatal("a CRLF checkout must have the same checksum as LF")
	}
}

func TestLoadRejectsBadNames(t *testing.T) {
	for name, fsys := range map[string]fstest.MapFS{
		"duplicate version": {"migrations/0001_a.sql": {}, "migrations/0001_b.sql": {}},
		"bad name":          {"migrations/1_a.sql": {}},
	} {
		if _, err := Load(fsys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPending(t *testing.T) {
	all, _ := Load(fstest.MapFS{
		"migrations/0001_a.sql": {Data: []byte("a")},
		"migrations/0002_b.sql": {Data: []byte("b")},
	})
	p, err := Pending(all, map[string]Applied{"0001": {Version: "0001", Checksum: all[0].Checksum}})
	if err != nil || len(p) != 1 || p[0].Version != "0002" {
		t.Fatalf("pending = %+v, %v", p, err)
	}
	if _, err := Pending(all, map[string]Applied{"0001": {Version: "0001", Checksum: "edited"}}); err == nil {
		t.Fatal("an edited applied migration must be refused")
	}
}

// The real embedded set loads, has the roles file and no gaps in numbering.
func TestEmbeddedMigrations(t *testing.T) {
	all, err := Load(db.Migrations)
	if err != nil {
		t.Fatal(err)
	}
	hasRoles := false
	for i, m := range all {
		if m.Name == rolesFile {
			hasRoles = true
		}
		if want := fmt.Sprintf("%04d", i+1); m.Version != want {
			t.Errorf("expected version %s, found %s: numbering has a gap", want, m.Name)
		}
	}
	if !hasRoles || len(all) < 18 {
		t.Fatalf("embedded set looks wrong: %d files, roles=%v", len(all), hasRoles)
	}
}
