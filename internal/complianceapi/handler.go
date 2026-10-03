// Package complianceapi is a minimal, internal-only read endpoint over
// internal/compliance - there is no admin UI/console yet, so this is how
// "how many patches are installed vs missing" gets answered for now.
package complianceapi

import (
	"encoding/json"
	"net/http"

	"aegis-one/internal/compliance"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Handler struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Handler {
	return &Handler{pool: pool}
}

// GET /internal/compliance            -> fleet totals
// GET /internal/compliance?view=patches -> per-patch breakdown (patch_compliance_by_patch)
// GET /internal/compliance?view=devices -> per-device breakdown (device_patch_compliance_current)
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		http.Error(w, "database not configured on this server", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()

	switch r.URL.Query().Get("view") {
	case "patches":
		rows, err := compliance.ListPatches(ctx, h.pool)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rows)

	case "devices":
		rows, err := compliance.ListDevices(ctx, h.pool)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rows)

	default:
		totals, err := compliance.FleetTotals(ctx, h.pool)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, totals)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
