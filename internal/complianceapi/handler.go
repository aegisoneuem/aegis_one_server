// Package complianceapi is a minimal, internal-only read endpoint over
// internal/compliance - there is no admin UI/console yet, so this is how
// "how many patches are installed vs missing" gets answered for now.
package complianceapi

import (
	"encoding/json"
	"errors"
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
// GET /internal/compliance?view=missing&device_id=X -> that device's missing patches, each with "deployable"
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

	case "missing":
		deviceID := r.URL.Query().Get("device_id")
		if deviceID == "" {
			http.Error(w, "view=missing needs device_id", http.StatusBadRequest)
			return
		}
		report, err := compliance.MissingForDevice(ctx, h.pool, deviceID)
		if errors.Is(err, compliance.ErrUnknownDevice) {
			http.Error(w, "unknown device_id", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, report)

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
