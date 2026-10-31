package ingest

import (
	"context"
	"strconv"
	"strings"

	aegisonev1 "aegis-one/gen/aegisone/v1"
	"aegis-one/internal/identity"
)

// DeviceState saves the agent's fast-lane report (OS build, UBR,
// architecture, pending reboot) on the device row. Fields the agent left
// empty keep their old value.
func (s *Store) DeviceState(ctx context.Context, known *identity.Known, ds *aegisonev1.DeviceStateReport) error {
	build, ubr := SplitBuild(ds.GetBuild())
	var ubrArg *int
	if ubr >= 0 {
		ubrArg = &ubr
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE devices SET
		    os_build       = coalesce($2, os_build),
		    os_ubr         = CASE WHEN $2::text IS NOT NULL THEN $3 ELSE os_ubr END,
		    architecture   = coalesce($4, architecture),
		    os_edition     = coalesce($5, os_edition),
		    os_version     = coalesce($6, os_version),
		    pending_reboot = $7,
		    pending_reboot_reason = CASE WHEN $7 THEN coalesce($8, pending_reboot_reason) ELSE NULL END
		WHERE id = $1`,
		known.DeviceUUID, nullIfEmpty(build), ubrArg, nullIfEmpty(NormalizeArch(ds.GetArchitecture())),
		nullIfEmpty(ds.GetProductName()), nullIfEmpty(ds.GetDisplayVersion()),
		ds.GetRebootPending(), nullIfEmpty(strings.Join(ds.GetRebootPendingSources(), ",")))
	return err
}

// SplitBuild splits the agent's "26100.4652" into build "26100" and UBR 4652.
// A build without a UBR returns -1 for it; anything unparsable returns "", -1.
func SplitBuild(full string) (build string, ubr int) {
	full = strings.TrimSpace(full)
	build, rev, hasRev := strings.Cut(full, ".")
	if _, err := strconv.Atoi(build); err != nil {
		return "", -1
	}
	if !hasRev {
		return build, -1
	}
	n, err := strconv.Atoi(rev)
	if err != nil || n < 0 {
		return "", -1
	}
	return build, n
}

// NormalizeArch maps the agent's architecture ("amd64", "arm64", "x86") to
// the devices.architecture values; anything else is "".
func NormalizeArch(a string) string {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "amd64", "x64", "x86_64":
		return "x64"
	case "arm64", "aarch64":
		return "arm64"
	case "x86", "386", "i386":
		return "x86"
	default:
		return ""
	}
}
