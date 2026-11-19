package devices

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The detail view's antivirus list (migration 0031) resolves the device the
// way the rest of the detail view does (idSQL: agent_reported_id, else the
// UUID) and lists enabled products first.
func TestAntivirusDB(t *testing.T) {
	url := os.Getenv("AEGIS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AEGIS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	h := New(pool, &fakeLive{}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	d := seedDevice(t, pool, "av-"+rnd(), "", 0)
	for _, row := range [][]any{
		{d.uuid, "Acme Endpoint Security", false, false, int64(0x40010)},
		{d.uuid, "Windows Defender", true, true, int64(0x61000)},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO device_antivirus_products (device_id, name, enabled, up_to_date, product_state) VALUES ($1, $2, $3, $4, $5)`, row...); err != nil {
			t.Fatal(err)
		}
	}
	list, err := h.antivirus(ctx, d.deviceID)
	if err != nil {
		t.Fatalf("antivirus(%s): %v", d.deviceID, err)
	}
	if len(list) != 2 || list[0].Name != "Windows Defender" || !list[0].Enabled || !list[0].UpToDate || list[0].ProductState != 0x61000 ||
		list[1].Name != "Acme Endpoint Security" || list[1].Enabled {
		t.Errorf("antivirus(%s) = %+v", d.deviceID, list)
	}
	// A device with no rows: empty (omitted from the JSON), not an error.
	other := seedDevice(t, pool, "noav-"+rnd(), "", 0)
	if list, err := h.antivirus(ctx, other.deviceID); err != nil || len(list) != 0 {
		t.Errorf("no AV rows: %v %v", list, err)
	}
}
