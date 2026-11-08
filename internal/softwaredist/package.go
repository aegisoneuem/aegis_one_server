// Package softwaredist distributes software to agents: installer packages are
// uploaded to the server, then deployed to devices with the agent's signed
// software_deploy command.
//
//	upload:  POST /internal/software/packages (multipart) -> the server hashes
//	         the file (SHA-256) and keeps it as <content dir>/software/<sha256><ext>
//	deploy:  POST /internal/software/deploy -> one software_deployment_results
//	         row per device; Run sends software_deploy when the device is online
//	agent:   fetches the file over FetchContent (kind "package", id = package
//	         id), checks the SHA-256 pinned in the command, installs, re-detects
//	         the product (ProductCode / Uninstall key / DisplayName) and reports
//	         an ActionStatus, which closes the result.
//
// Script packages (ps1/bat/cmd/python/vbs) run arbitrary code as SYSTEM, so
// uploading or deploying one also needs the software.script permission. The
// agent's "command" type (a raw command line, no file) is only offered inside
// a bundle, where it also needs software.script.
//
// v2 (v2.go): a .zip upload is a bundle (aegis-package.json manifest, checked
// at upload) run from an entry point or a command, optionally with before /
// after / rollback steps; detection rules; public parameters; AC-power gate;
// script-content audit flag; and dependencies (requires) installed first.
package softwaredist

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// installerExts are the file extensions accepted per installer type; the
// agent picks the program to run (msiexec, powershell, cmd, ...) by type.
var installerExts = map[string][]string{
	"msi":    {".msi"},
	"exe":    {".exe"},
	"ps1":    {".ps1"},
	"bat":    {".bat"},
	"cmd":    {".cmd"},
	"python": {".py"},
	"vbs":    {".vbs"},
	"inf":    {".inf"},
	"msix":   {".msix", ".appx", ".msixbundle", ".appxbundle"},
}

// IsScript reports whether installerType runs a script rather than an
// installer binary.
func IsScript(installerType string) bool {
	switch installerType {
	case "ps1", "bat", "cmd", "python", "vbs":
		return true
	}
	return false
}

// packageFormat maps an installer type to software_packages.package_format.
func packageFormat(installerType string, bundle bool) string {
	switch {
	case bundle:
		return "bundle"
	case IsScript(installerType):
		return "script"
	case installerType == "inf":
		return "driver"
	}
	return installerType
}

// NeedsScriptPerm reports whether a package runs arbitrary code (a script, or a
// bundle command / steps), which needs software.script on top of
// software.deploy.
func (p *Package) NeedsScriptPerm() bool {
	return IsScript(p.InstallerType) || p.InstallerType == "command" || !p.Steps.empty()
}

type Package struct {
	ID               string    `json:"package_id"`
	Name             string    `json:"name"`
	Version          string    `json:"version"`
	InstallerType    string    `json:"installer_type"`
	FileName         string    `json:"file_name"`
	SHA256           string    `json:"sha256"`
	SizeBytes        int64     `json:"size_bytes"`
	SilentArgs       string    `json:"silent_args,omitempty"`
	ProductCode      string    `json:"product_code,omitempty"`
	UninstallKey     string    `json:"uninstall_key,omitempty"`
	DisplayName      string    `json:"display_name,omitempty"`
	SuccessExitCodes []int32   `json:"success_exit_codes"`
	TimeoutSeconds   int32     `json:"timeout_seconds,omitempty"`
	RequireSignature bool      `json:"require_signature"`
	CreatedAt        time.Time `json:"created_at"`

	IsBundle             bool              `json:"is_bundle"`
	BundleEntryPoint     string            `json:"bundle_entry_point,omitempty"`
	BundleCommand        string            `json:"bundle_command,omitempty"`
	BundleDestination    string            `json:"bundle_destination,omitempty"`
	BundleCleanup        string            `json:"bundle_cleanup,omitempty"`
	BundleFiles          int               `json:"bundle_files,omitempty"`
	Steps                *Steps            `json:"steps,omitempty"`
	Detection            *Detection        `json:"detection,omitempty"`
	Parameters           map[string]string `json:"parameters,omitempty"`
	Requires             []string          `json:"requires,omitempty"`
	RequireACPower       bool              `json:"require_ac_power"`
	CaptureScriptContent bool              `json:"capture_script_content"`

	storageName string
}

// Ext is the file extension of the stored installer (".msi", ".ps1", ...).
func (p *Package) Ext() string { return filepath.Ext(p.storageName) }

// Meta is what the uploader says about a package.
type Meta struct {
	Name             string
	Version          string
	InstallerType    string
	SilentArgs       string
	ProductCode      string
	UninstallKey     string
	DisplayName      string
	SuccessExitCodes []int32
	TimeoutSeconds   int32
	RequireSignature bool

	BundleEntryPoint     string
	BundleCommand        string
	BundleDestination    string
	BundleCleanup        string
	Steps                *Steps
	Detection            *Detection
	Parameters           map[string]string
	Requires             []string
	RequireACPower       bool
	CaptureScriptContent bool
}

// UserError is a request the caller can fix, as opposed to a server failure.
type UserError struct{ msg string }

func (e *UserError) Error() string { return e.msg }

func userErr(format string, a ...any) error { return &UserError{fmt.Sprintf(format, a...)} }

var productCodeRe = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

// Validate checks m against the uploaded file name.
func (m *Meta) Validate(fileName string) error {
	m.Name, m.Version = strings.TrimSpace(m.Name), strings.TrimSpace(m.Version)
	m.InstallerType = strings.ToLower(strings.TrimSpace(m.InstallerType))
	m.ProductCode, m.UninstallKey = strings.TrimSpace(m.ProductCode), strings.TrimSpace(m.UninstallKey)
	m.DisplayName, m.SilentArgs = strings.TrimSpace(m.DisplayName), strings.TrimSpace(m.SilentArgs)
	if err := checkText("name", m.Name, 1, 200); err != nil {
		return err
	}
	if err := checkText("version", m.Version, 1, 100); err != nil {
		return err
	}
	ext := strings.ToLower(filepath.Ext(fileName))
	bundle := ext == ".zip"
	m.BundleEntryPoint, m.BundleCommand = strings.TrimSpace(m.BundleEntryPoint), strings.TrimSpace(m.BundleCommand)
	m.BundleDestination, m.BundleCleanup = strings.TrimSpace(m.BundleDestination), strings.ToLower(strings.TrimSpace(m.BundleCleanup))
	if bundle {
		// A bundle runs either a manifested entry point (as installer_type) or
		// a command line in the extracted folder (installer_type command).
		if (m.BundleEntryPoint == "") == (m.BundleCommand == "") {
			return userErr("a .zip bundle needs exactly one of bundle_entry_point or bundle_command")
		}
		if m.BundleCommand != "" {
			if m.InstallerType != "" && m.InstallerType != "command" {
				return userErr("bundle_command needs installer_type command")
			}
			m.InstallerType = "command"
			if err := checkText("bundle_command", m.BundleCommand, 1, 2000); err != nil {
				return err
			}
		} else {
			if err := checkMemberPath(m.BundleEntryPoint); err != nil {
				return err
			}
			if m.BundleEntryPoint == bundleManifest {
				return userErr("bundle_entry_point can't be the manifest")
			}
			exts, ok := installerExts[m.InstallerType]
			if !ok {
				return userErr("installer_type must be one of msi, exe, ps1, bat, cmd, python, vbs, inf, msix")
			}
			if !contains(exts, strings.ToLower(path.Ext(m.BundleEntryPoint))) {
				return userErr("installer_type %s needs a %s entry point, got %q", m.InstallerType, strings.Join(exts, " or "), m.BundleEntryPoint)
			}
		}
		if err := validateDestination(m.BundleDestination, m.BundleCleanup); err != nil {
			return err
		}
	} else {
		if m.BundleEntryPoint != "" || m.BundleCommand != "" || m.BundleDestination != "" || m.BundleCleanup != "" {
			return userErr("bundle_* fields are only for a .zip bundle")
		}
		if !m.Steps.empty() {
			return userErr("steps need a .zip bundle")
		}
		exts, ok := installerExts[m.InstallerType]
		if !ok {
			return userErr("installer_type must be one of msi, exe, ps1, bat, cmd, python, vbs, inf, msix (or upload a .zip bundle)")
		}
		if !contains(exts, ext) {
			return userErr("installer_type %s needs a %s file, got %q", m.InstallerType, strings.Join(exts, " or "), fileName)
		}
	}
	if m.Steps != nil {
		if err := m.Steps.validate(); err != nil {
			return err
		}
		if m.Steps.empty() {
			m.Steps = nil
		}
	}
	if m.Detection != nil {
		if err := m.Detection.validate(); err != nil {
			return err
		}
	}
	if err := validateParams(m.Parameters); err != nil {
		return err
	}
	m.Requires = dedupe(m.Requires)
	if len(m.Requires) > 16 {
		return userErr("at most 16 direct requires")
	}
	for _, id := range m.Requires {
		if !isUUID(id) {
			return userErr("requires: %q is not a package_id", id)
		}
	}
	if err := checkText("silent_args", m.SilentArgs, 0, 2000); err != nil {
		return err
	}
	if m.ProductCode != "" && !productCodeRe.MatchString(m.ProductCode) {
		return userErr("product_code must look like {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}")
	}
	if m.Detection != nil && (m.ProductCode != "" || m.UninstallKey != "" || m.DisplayName != "") {
		return userErr("detection rules replace product_code / uninstall_key / display_name; don't set both")
	}
	if err := checkText("uninstall_key", m.UninstallKey, 0, 300); err != nil {
		return err
	}
	if strings.ContainsAny(m.UninstallKey, `\/`) {
		return userErr("uninstall_key is the subkey name only (no path separators)")
	}
	if err := checkText("display_name", m.DisplayName, 0, 300); err != nil {
		return err
	}
	if m.TimeoutSeconds < 0 || m.TimeoutSeconds > 86400 {
		return userErr("timeout_seconds must be between 1 and 86400 (0 = the agent's default, 30 minutes)")
	}
	if len(m.SuccessExitCodes) > 20 {
		return userErr("at most 20 success_exit_codes")
	}
	return nil
}

func checkText(field, v string, minLen, maxLen int) error {
	if len(v) < minLen {
		return userErr("%s is required", field)
	}
	if len(v) > maxLen {
		return userErr("%s is longer than %d characters", field, maxLen)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return userErr("%s contains control characters", field)
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

type Store struct {
	pool     *pgxpool.Pool
	dir      string // <content dir>/software
	maxBytes int64
	log      *slog.Logger
}

func NewStore(pool *pgxpool.Pool, contentDir string, maxBytes int64, log *slog.Logger) *Store {
	return &Store{pool: pool, dir: filepath.Join(contentDir, "software"), maxBytes: maxBytes, log: log}
}

// Staged is an uploaded file written to a temp file and hashed, not yet a
// package. Commit or Discard it.
type Staged struct {
	FileName  string
	SHA256    string
	SizeBytes int64
	tmp       string
}

// Stage streams r to a temp file under the software dir, hashing it. It
// refuses empty files and files over the upload cap.
func (s *Store) Stage(fileName string, r io.Reader) (*Staged, error) {
	base := filepath.Base(strings.ReplaceAll(fileName, `\`, "/"))
	if base == "." || base == "/" || base == "" {
		return nil, userErr("the uploaded file has no name")
	}
	if err := checkText("file name", base, 1, 255); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return nil, err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	tmp := filepath.Join(s.dir, ".upload-"+hex.EncodeToString(rnd[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, s.maxBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("receive upload: %w", err)
	}
	if n == 0 {
		os.Remove(tmp)
		return nil, userErr("the uploaded file is empty")
	}
	if n > s.maxBytes {
		os.Remove(tmp)
		return nil, userErr("the uploaded file is larger than the %d-byte limit (AEGIS_SOFTWARE_MAX_UPLOAD_BYTES)", s.maxBytes)
	}
	return &Staged{FileName: base, SHA256: hex.EncodeToString(h.Sum(nil)), SizeBytes: n, tmp: tmp}, nil
}

// Discard removes a staged file that will not be committed.
func (s *Store) Discard(st *Staged) {
	if st != nil && st.tmp != "" {
		os.Remove(st.tmp)
	}
}

// Commit validates meta, moves the staged file into place and records the
// package (with an audit entry). The staged file is consumed either way.
func (s *Store) Commit(ctx context.Context, meta Meta, st *Staged, clientID, clientName string) (*Package, error) {
	defer s.Discard(st)
	if err := meta.Validate(st.FileName); err != nil {
		return nil, err
	}
	bundle := strings.EqualFold(filepath.Ext(st.FileName), ".zip")
	bundleFiles := 0
	if bundle {
		f, err := os.Open(st.tmp)
		if err != nil {
			return nil, err
		}
		info, err := ValidateBundle(f, st.SizeBytes)
		f.Close()
		if err != nil {
			return nil, err
		}
		if meta.BundleEntryPoint != "" && !info.Paths[meta.BundleEntryPoint] {
			return nil, userErr("bundle_entry_point %q is not a file in the bundle manifest", meta.BundleEntryPoint)
		}
		bundleFiles = info.Members
	}
	storageName := "software/" + st.SHA256 + strings.ToLower(filepath.Ext(st.FileName))
	final := filepath.Join(s.dir, st.SHA256+strings.ToLower(filepath.Ext(st.FileName)))
	// Content-addressed: the same bytes uploaded twice share one file.
	if _, err := os.Stat(final); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(st.tmp, final); err != nil {
			return nil, fmt.Errorf("store package file: %w", err)
		}
	} else if err != nil {
		return nil, err
	}

	p := &Package{
		Name: meta.Name, Version: meta.Version, InstallerType: meta.InstallerType, FileName: st.FileName,
		SHA256: st.SHA256, SizeBytes: st.SizeBytes, SilentArgs: meta.SilentArgs, ProductCode: meta.ProductCode,
		UninstallKey: meta.UninstallKey, DisplayName: meta.DisplayName, SuccessExitCodes: meta.SuccessExitCodes,
		TimeoutSeconds: meta.TimeoutSeconds, RequireSignature: meta.RequireSignature, storageName: storageName,
		IsBundle: bundle, BundleEntryPoint: meta.BundleEntryPoint, BundleCommand: meta.BundleCommand,
		BundleDestination: meta.BundleDestination, BundleCleanup: meta.BundleCleanup, BundleFiles: bundleFiles,
		Steps: meta.Steps, Detection: meta.Detection, Parameters: meta.Parameters, Requires: meta.Requires,
		RequireACPower: meta.RequireACPower, CaptureScriptContent: meta.CaptureScriptContent,
	}
	if p.Parameters == nil {
		p.Parameters = map[string]string{}
	}
	if p.Requires == nil {
		p.Requires = []string{}
	}
	if p.SuccessExitCodes == nil {
		p.SuccessExitCodes = []int32{}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if err := checkRequires(ctx, tx, p.Requires); err != nil {
		return nil, err
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO software_packages
			(name, version, package_format, sha256_hash, size_bytes, silent_args, installer_type, file_name, storage_name,
			 product_code, uninstall_key, display_name, success_exit_codes, timeout_seconds, require_signature, created_by_api_client_id,
			 is_bundle, bundle_entry_point, bundle_command, bundle_destination, bundle_cleanup, bundle_files,
			 steps, detection, parameters, requires, require_ac_power, capture_script_content)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, $8, $9, NULLIF($10, ''), NULLIF($11, ''), NULLIF($12, ''), $13, NULLIF($14, 0), $15, $16,
		        $17, NULLIF($18, ''), NULLIF($19, ''), NULLIF($20, ''), NULLIF($21, ''), NULLIF($22, 0),
		        $23::jsonb, $24::jsonb, coalesce($25::jsonb, '{}'), $26::uuid[], $27, $28)
		RETURNING id, created_at`,
		p.Name, p.Version, packageFormat(p.InstallerType, bundle), p.SHA256, p.SizeBytes, p.SilentArgs, p.InstallerType, p.FileName, storageName,
		p.ProductCode, p.UninstallKey, p.DisplayName, p.SuccessExitCodes, p.TimeoutSeconds, p.RequireSignature, clientID,
		bundle, p.BundleEntryPoint, p.BundleCommand, p.BundleDestination, p.BundleCleanup, bundleFiles,
		jsonOrNil(p.Steps), jsonOrNil(p.Detection), jsonOrNil(p.Parameters), p.Requires, p.RequireACPower, p.CaptureScriptContent,
	).Scan(&p.ID, &p.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, userErr("a %s package named %q version %q already exists", packageFormat(p.InstallerType, bundle), p.Name, p.Version)
	}
	if err != nil {
		return nil, fmt.Errorf("insert software_packages: %w", err)
	}
	details, _ := json.Marshal(map[string]any{
		"package_id": p.ID, "name": p.Name, "version": p.Version, "installer_type": p.InstallerType,
		"script": p.NeedsScriptPerm(), "file_name": p.FileName, "sha256": p.SHA256, "size_bytes": p.SizeBytes,
		"bundle": bundle, "requires": p.Requires, "has_steps": p.Steps != nil, "has_detection": p.Detection != nil,
	})
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_api_client_id, actor_label, action, target_type, target_id, details)
		VALUES ('api_client', $1, $2, 'software.package.upload', 'software_package', $3, $4::jsonb)`,
		clientID, clientName, p.ID, string(details)); err != nil {
		return nil, fmt.Errorf("insert audit_log: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.log.Info("software package uploaded", "package_id", p.ID, "name", p.Name, "version", p.Version,
		"installer_type", p.InstallerType, "sha256", p.SHA256, "size_bytes", p.SizeBytes)
	return p, nil
}

// packageColumnsTpl is the package SELECT list with "@" where a table alias
// goes; packageColumns / PackageColumnsP are it without and with "p.".
const packageColumnsTpl = `@id, @name, @version, @installer_type, coalesce(@file_name, ''), @sha256_hash, coalesce(@size_bytes, 0),
	coalesce(@silent_args, ''), coalesce(@product_code, ''), coalesce(@uninstall_key, ''), coalesce(@display_name, ''),
	@success_exit_codes, coalesce(@timeout_seconds, 0), @require_signature, @created_at, coalesce(@storage_name, ''),
	@is_bundle, coalesce(@bundle_entry_point, ''), coalesce(@bundle_command, ''), coalesce(@bundle_destination, ''),
	coalesce(@bundle_cleanup, ''), coalesce(@bundle_files, 0), @steps, @detection, @parameters, @requires::text[],
	@require_ac_power, @capture_script_content`

var (
	packageColumns  = strings.ReplaceAll(packageColumnsTpl, "@", "")
	PackageColumnsP = strings.ReplaceAll(packageColumnsTpl, "@", "p.")
)

// scanPackage reads one row of packageColumns. extra receives further columns
// selected after them.
func scanPackage(row pgx.Row, extra ...any) (*Package, error) {
	var p Package
	var steps, det, params []byte
	dest := []any{&p.ID, &p.Name, &p.Version, &p.InstallerType, &p.FileName, &p.SHA256, &p.SizeBytes,
		&p.SilentArgs, &p.ProductCode, &p.UninstallKey, &p.DisplayName,
		&p.SuccessExitCodes, &p.TimeoutSeconds, &p.RequireSignature, &p.CreatedAt, &p.storageName,
		&p.IsBundle, &p.BundleEntryPoint, &p.BundleCommand, &p.BundleDestination, &p.BundleCleanup, &p.BundleFiles,
		&steps, &det, &params, &p.Requires, &p.RequireACPower, &p.CaptureScriptContent}
	if err := row.Scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	if len(steps) > 0 {
		if err := json.Unmarshal(steps, &p.Steps); err != nil {
			return nil, fmt.Errorf("package %s steps: %w", p.ID, err)
		}
	}
	if len(det) > 0 {
		if err := json.Unmarshal(det, &p.Detection); err != nil {
			return nil, fmt.Errorf("package %s detection: %w", p.ID, err)
		}
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p.Parameters); err != nil {
			return nil, fmt.Errorf("package %s parameters: %w", p.ID, err)
		}
	}
	return &p, nil
}

// checkRequires verifies dependencies: each must be an active package that is
// install-detectable (the plan skips one that's already there).
func checkRequires(ctx context.Context, tx pgx.Tx, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT id::text, name, (product_code IS NOT NULL OR uninstall_key IS NOT NULL OR display_name IS NOT NULL OR detection IS NOT NULL)
		FROM software_packages WHERE id = ANY($1::uuid[]) AND deleted_at IS NULL AND storage_name IS NOT NULL`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var id, name string
		var detectable bool
		if err := rows.Scan(&id, &name, &detectable); err != nil {
			return err
		}
		if !detectable {
			return userErr("required package %s (%s) has no product_code, uninstall_key, display_name or detection rules, "+
				"so the agent can't tell whether it is already installed", name, id)
		}
		found[id] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if !found[id] {
			return userErr("required package %s does not exist", id)
		}
	}
	return nil
}

// jsonOrNil is v as a JSON string, or nil for an empty value (SQL NULL).
func jsonOrNil(v any) *string {
	switch x := v.(type) {
	case *Steps:
		if x == nil {
			return nil
		}
	case *Detection:
		if x == nil {
			return nil
		}
	case map[string]string:
		if len(x) == 0 {
			return nil
		}
	}
	b, _ := json.Marshal(v)
	out := string(b)
	return &out
}

// Get returns a package uploaded through the API, or nil if there is none
// with that id.
func (s *Store) Get(ctx context.Context, id string) (*Package, error) {
	if !isUUID(id) {
		return nil, nil
	}
	p, err := scanPackage(s.pool.QueryRow(ctx, `SELECT `+packageColumns+` FROM software_packages
		WHERE id = $1 AND deleted_at IS NULL AND storage_name IS NOT NULL`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

// List returns all packages uploaded through the API, newest first.
func (s *Store) List(ctx context.Context) ([]Package, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+packageColumns+` FROM software_packages
		WHERE deleted_at IS NULL AND storage_name IS NOT NULL ORDER BY created_at DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Package{}
	for rows.Next() {
		p, err := scanPackage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// ForFetch resolves an agent's FetchContent{kind:"package"}: the package must
// exist, sha256 must be the one pinned in its command, and the device must
// have a deployment of it in progress. Anything else returns nil, so an agent
// can't pull arbitrary (possibly licensed) installers.
func (s *Store) ForFetch(ctx context.Context, packageID, sha256Hex, deviceUUID string) (*Package, error) {
	p, err := s.Get(ctx, packageID)
	if err != nil || p == nil {
		return nil, err
	}
	if !strings.EqualFold(p.SHA256, sha256Hex) {
		return nil, nil
	}
	var active bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM software_deployment_results
		               WHERE device_id = $1 AND package_id = $2 AND status = 'in_progress')`,
		deviceUUID, p.ID).Scan(&active); err != nil {
		return nil, err
	}
	if !active {
		return nil, nil
	}
	return p, nil
}

// Path is where p's file lives on disk.
func (s *Store) Path(p *Package) string {
	return filepath.Join(filepath.Dir(s.dir), filepath.FromSlash(p.storageName))
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
