// Package patchbaseline builds the PatchBaseline the server pushes to agents:
// "for your exact build, the latest cumulative KB is ...". The agent caches it
// and, between scans (or offline), compares it with its installed KBs for a
// "likely missing" hint. It applies the baseline only while its own build
// string ("26100.4652") equals the baseline's, so each device gets one for its
// own build, and a new one whenever its build changes. The scan report stays
// the source of truth for what is missing.
//
// The data is MSRC's FixedBuild per Windows product (os_fixed_builds): the
// newest KB for (client|server, architecture, build) whose UBR is above the
// device's is the one it lacks. If the device is already at or past it the
// list is empty, which tells the agent it is current.
package patchbaseline

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	aegisonev1 "aegis-one/gen/aegisone/v1"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Device is what the baseline depends on.
type Device struct {
	Kind  string // client | server
	Arch  string // x86 | x64 | arm64
	Build int    // 26100
	UBR   int    // 4652; -1 when unknown
}

// FullBuild is the build string the agent compares against, built the way the
// agent builds it (CurrentBuildNumber + "." + UBR).
func (d Device) FullBuild() string {
	return strconv.Itoa(d.Build) + "." + strconv.Itoa(d.UBR)
}

func (d Device) known() bool {
	return d.Build > 0 && d.UBR >= 0 && d.Arch != "" && d.Kind != ""
}

// DeviceFrom maps device columns to a Device. edition is the agent's
// ProductName ("Windows Server 2025 Datacenter", "Windows 11 Pro").
func DeviceFrom(edition, osBuild string, ubr *int, arch string) Device {
	d := Device{Kind: "client", Arch: arch, UBR: -1}
	if strings.Contains(strings.ToLower(edition), "server") {
		d.Kind = "server"
	}
	if n, err := strconv.Atoi(strings.TrimSpace(osBuild)); err == nil {
		d.Build = n
	}
	if ubr != nil {
		d.UBR = *ubr
	}
	return d
}

// ErrUnknownDevice means there is no device row for the id.
var ErrUnknownDevice = errors.New("unknown device")

// LoadDevice reads one device's build data.
func LoadDevice(ctx context.Context, pool *pgxpool.Pool, deviceUUID string) (Device, error) {
	var edition, build, arch *string
	var ubr *int
	err := pool.QueryRow(ctx, `SELECT os_edition, os_build, os_ubr, architecture FROM devices WHERE id = $1`,
		deviceUUID).Scan(&edition, &build, &ubr, &arch)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrUnknownDevice
	}
	if err != nil {
		return Device{}, err
	}
	return DeviceFrom(deref(edition), deref(build), ubr, deref(arch)), nil
}

type family struct {
	kind, arch string
	build      int
}

// Latest is the newest KB known for one build family.
type Latest struct {
	KB  string
	UBR int
}

// Index is the newest KB per (kind, architecture, build). It is small (one row
// per Windows release and architecture), so it is loaded whole.
type Index map[family]Latest

// Load reads the newest fixed build per family from os_fixed_builds.
func Load(ctx context.Context, pool *pgxpool.Pool) (Index, error) {
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (os_kind, architecture, os_build) os_kind, architecture, os_build, ubr, kb
		FROM os_fixed_builds
		ORDER BY os_kind, architecture, os_build, ubr DESC, kb DESC`)
	if err != nil {
		return nil, fmt.Errorf("load fixed builds: %w", err)
	}
	defer rows.Close()
	ix := Index{}
	for rows.Next() {
		var f family
		var l Latest
		if err := rows.Scan(&f.kind, &f.arch, &f.build, &l.UBR, &l.KB); err != nil {
			return nil, err
		}
		ix[f] = l
	}
	return ix, rows.Err()
}

// Set records the newest KB for a family (tests and callers building an Index
// by hand).
func (ix Index) Set(kind, arch string, build int, l Latest) {
	ix[family{kind, arch, build}] = l
}

// For returns the baseline for d, or false when the device's build is not
// known yet or the feed has nothing for its build (an unknown release: better
// to send nothing than to tell the agent it is current).
func (ix Index) For(d Device) (*aegisonev1.PatchBaseline, bool) {
	if !d.known() {
		return nil, false
	}
	l, ok := ix[family{d.Kind, d.Arch, d.Build}]
	if !ok {
		return nil, false
	}
	bl := &aegisonev1.PatchBaseline{Build: d.FullBuild(), LatestKbs: []string{}}
	if l.UBR > d.UBR {
		bl.LatestKbs = append(bl.LatestKbs, l.KB)
	}
	return bl, true
}

// Key identifies a baseline's content (issued_at aside), to skip re-sending
// one the agent already has.
func Key(bl *aegisonev1.PatchBaseline) string {
	return bl.GetBuild() + "|" + strings.Join(bl.GetLatestKbs(), ",")
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
