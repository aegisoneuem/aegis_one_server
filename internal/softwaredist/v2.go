package softwaredist

// Software distribution v2 package features, validated here with the same
// rules the agent enforces (agent repo internal/softdist, pkg/softdistplan) so
// a bad package is refused at upload rather than failing on every endpoint.

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	aegisonev1 "aegis-one/gen/aegisone/v1"
)

// Step is one before / after / rollback command of a bundle workflow.
type Step struct {
	Name                string  `json:"name"`
	Command             string  `json:"command"`
	Arguments           string  `json:"arguments,omitempty"`
	TimeoutSeconds      int32   `json:"timeout_seconds,omitempty"` // 0 = agent default (300)
	SuccessExitCodes    []int32 `json:"success_exit_codes,omitempty"`
	UseSecureParameters bool    `json:"use_secure_parameters,omitempty"`
}

// Steps runs around the main installer: before -> main -> after; rollback on
// any failure (best effort).
type Steps struct {
	Before   []Step `json:"before,omitempty"`
	After    []Step `json:"after,omitempty"`
	Rollback []Step `json:"rollback,omitempty"`
}

func (s *Steps) empty() bool { return s == nil || len(s.Before)+len(s.After)+len(s.Rollback) == 0 }

// Rule is one advanced detection rule.
type Rule struct {
	Kind           string `json:"kind"` // file_exists | file_version | registry_key | registry_value
	Path           string `json:"path,omitempty"`
	MinimumVersion string `json:"minimum_version,omitempty"`
	Hive           string `json:"hive,omitempty"` // HKLM | HKCU
	Key            string `json:"key,omitempty"`
	View           string `json:"view,omitempty"` // "32" | "64"
	ValueName      string `json:"value_name,omitempty"`
	ValueType      string `json:"value_type,omitempty"` // string | dword | qword
	ExpectedValue  string `json:"expected_value,omitempty"`
}

// Detection decides "installed" from rules instead of ProductCode / Uninstall
// key / DisplayName.
type Detection struct {
	Mode  string `json:"mode,omitempty"` // all (default) | any
	Rules []Rule `json:"rules"`
}

const (
	maxStepsPerStage  = 8
	maxStepExitCodes  = 32
	maxStepTimeout    = 3600
	maxDetectionRules = 32
	maxParams         = 64
	maxSecretBytes    = 64 << 10
	maxBundleMembers  = 10000
	maxBundleExpanded = 4 << 30
	maxManifestBytes  = 4 << 20
	bundleManifest    = "aegis-package.json"
)

var (
	paramNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	versionRe   = regexp.MustCompile(`^\d{1,5}(\.\d{1,5}){0,3}$`)
	reservedWin = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$`)
)

func (s *Steps) validate() error {
	if s.empty() {
		return nil
	}
	for stage, list := range map[string][]Step{"before": s.Before, "after": s.After, "rollback": s.Rollback} {
		if len(list) > maxStepsPerStage {
			return userErr("steps.%s: at most %d steps", stage, maxStepsPerStage)
		}
		for i, st := range list {
			where := fmt.Sprintf("steps.%s[%d]", stage, i)
			if st.Name == "" || len(st.Name) > 128 || strings.ContainsAny(st.Name, "\r\n") {
				return userErr("%s.name is required, one line, at most 128 bytes", where)
			}
			if strings.TrimSpace(st.Command) == "" {
				return userErr("%s.command is required (no implicit shell: use cmd.exe /D /C ...)", where)
			}
			if err := checkText(where+".command", st.Command, 1, 2000); err != nil {
				return err
			}
			if err := checkText(where+".arguments", st.Arguments, 0, 4000); err != nil {
				return err
			}
			if st.TimeoutSeconds < 0 || st.TimeoutSeconds > maxStepTimeout {
				return userErr("%s.timeout_seconds must be 0..%d", where, maxStepTimeout)
			}
			if len(st.SuccessExitCodes) > maxStepExitCodes {
				return userErr("%s: at most %d success_exit_codes", where, maxStepExitCodes)
			}
		}
	}
	return nil
}

func (d *Detection) validate() error {
	if d == nil {
		return nil
	}
	d.Mode = strings.ToLower(strings.TrimSpace(d.Mode))
	if d.Mode == "" {
		d.Mode = "all"
	}
	if d.Mode != "all" && d.Mode != "any" {
		return userErr("detection.mode must be all or any")
	}
	if len(d.Rules) == 0 || len(d.Rules) > maxDetectionRules {
		return userErr("detection needs 1..%d rules", maxDetectionRules)
	}
	for i := range d.Rules {
		r := &d.Rules[i]
		where := fmt.Sprintf("detection.rules[%d]", i)
		for name, v := range map[string]string{"path": r.Path, "key": r.Key, "value_name": r.ValueName, "expected_value": r.ExpectedValue} {
			if err := checkText(where+"."+name, v, 0, 1024); err != nil {
				return err
			}
			if strings.Contains(v, "${package_dir}") {
				return userErr("%s.%s may not use ${package_dir}", where, name)
			}
		}
		if strings.Contains(r.Key+r.ValueName+r.MinimumVersion, "${") {
			return userErr("%s: ${...} is only allowed in path and expected_value", where)
		}
		switch r.Kind {
		case "file_exists":
			if r.Path == "" {
				return userErr("%s: file_exists needs path", where)
			}
		case "file_version":
			if r.Path == "" || !versionRe.MatchString(r.MinimumVersion) || !versionParts(r.MinimumVersion) {
				return userErr("%s: file_version needs path and minimum_version (1-4 parts, each 0-65535)", where)
			}
		case "registry_key", "registry_value":
			r.Hive = strings.ToUpper(r.Hive)
			if r.Hive != "HKLM" && r.Hive != "HKCU" {
				return userErr("%s.hive must be HKLM or HKCU", where)
			}
			if r.Key == "" {
				return userErr("%s.key is required", where)
			}
			if r.View != "" && r.View != "32" && r.View != "64" {
				return userErr(`%s.view must be "32" or "64"`, where)
			}
			if r.Kind == "registry_value" {
				switch r.ValueType {
				case "string":
				case "dword", "qword":
					if _, err := strconv.ParseUint(r.ExpectedValue, 10, 64); err != nil {
						return userErr("%s: %s expected_value must be an unsigned decimal", where, r.ValueType)
					}
				default:
					return userErr("%s.value_type must be string, dword or qword", where)
				}
			}
		default:
			return userErr("%s.kind must be file_exists, file_version, registry_key or registry_value", where)
		}
	}
	return nil
}

// usesHKCU reports whether any rule reads the current user's hive (needs a
// user execution context at deploy time).
func (d *Detection) usesHKCU() bool {
	if d == nil {
		return false
	}
	for _, r := range d.Rules {
		if r.Hive == "HKCU" {
			return true
		}
	}
	return false
}

func versionParts(v string) bool {
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n > 65535 {
			return false
		}
	}
	return true
}

// validateParams checks public parameter names and values.
func validateParams(p map[string]string) error {
	if len(p) > maxParams {
		return userErr("at most %d parameters", maxParams)
	}
	seen := map[string]bool{}
	for k, v := range p {
		if !paramNameRe.MatchString(k) {
			return userErr("parameter name %q must match %s", k, paramNameRe)
		}
		if strings.EqualFold(k, "package_dir") {
			return userErr("parameter name package_dir is reserved")
		}
		if seen[strings.ToLower(k)] {
			return userErr("parameter names %q collide (case-insensitive)", k)
		}
		seen[strings.ToLower(k)] = true
		if err := checkText("parameter "+k, v, 0, 4000); err != nil {
			return err
		}
	}
	return nil
}

// validateDestination checks an explicit bundle extraction folder: absolute,
// local, clean, not UNC. Empty means the agent's managed temp folder.
func validateDestination(dest, cleanup string) error {
	if cleanup != "" && cleanup != "always" && cleanup != "retain" {
		return userErr("bundle_cleanup must be always or retain")
	}
	if dest == "" {
		if cleanup == "retain" {
			return userErr("bundle_cleanup retain needs an explicit bundle_destination")
		}
		return nil
	}
	if err := checkText("bundle_destination", dest, 1, 240); err != nil {
		return err
	}
	if strings.HasPrefix(dest, `\\`) || strings.HasPrefix(dest, "//") {
		return userErr("bundle_destination may not be a UNC path")
	}
	if len(dest) < 3 || !unicode.IsLetter(rune(dest[0])) || dest[1] != ':' || dest[2] != '\\' {
		return userErr(`bundle_destination must be an absolute local path like C:\Aegis\pkg`)
	}
	for _, part := range strings.Split(dest[3:], `\`) {
		if part == "" || part == "." || part == ".." || reservedWin.MatchString(part) || strings.ContainsAny(part, `/:*?"<>|`) {
			return userErr("bundle_destination is not a clean path")
		}
	}
	return nil
}

type manifest struct {
	Version int `json:"version"`
	Files   []struct {
		Path      string `json:"path"`
		Size      int64  `json:"size"`
		SHA256    string `json:"sha256"`
		Directory bool   `json:"directory"`
	} `json:"files"`
}

// BundleInfo is what upload validation learned about a bundle ZIP.
type BundleInfo struct {
	Members int
	Paths   map[string]bool // manifested file paths (not directories)
}

// ValidateBundle checks a bundle ZIP the way the agent will before it
// extracts it: a root aegis-package.json listing every member with its size
// and SHA-256, no traversal / links / reserved names / case aliases, within
// the agent's limits.
func ValidateBundle(r io.ReaderAt, size int64) (*BundleInfo, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, userErr("bundle is not a valid ZIP: %v", err)
	}
	if len(zr.File) > maxBundleMembers+1 {
		return nil, userErr("bundle has more than %d members", maxBundleMembers)
	}
	var mf *zip.File
	byName := map[string]*zip.File{}
	lower := map[string]string{}
	for _, f := range zr.File {
		name := strings.TrimSuffix(f.Name, "/")
		if f.Name == bundleManifest {
			mf = f
			continue
		}
		if err := checkMemberPath(name); err != nil {
			return nil, err
		}
		if f.Mode()&0o170000 == 0o120000 { // symlink
			return nil, userErr("bundle member %q is a link", f.Name)
		}
		if other, dup := lower[strings.ToLower(name)]; dup {
			return nil, userErr("bundle members %q and %q differ only by case", other, name)
		}
		lower[strings.ToLower(name)] = name
		byName[name] = f
	}
	if mf == nil {
		return nil, userErr("bundle has no root %s manifest", bundleManifest)
	}
	if mf.UncompressedSize64 > maxManifestBytes {
		return nil, userErr("%s is larger than 4 MiB", bundleManifest)
	}
	rc, err := mf.Open()
	if err != nil {
		return nil, userErr("read %s: %v", bundleManifest, err)
	}
	var m manifest
	err = json.NewDecoder(io.LimitReader(rc, maxManifestBytes)).Decode(&m)
	rc.Close()
	if err != nil || m.Version != 1 {
		return nil, userErr("%s must be JSON with \"version\": 1", bundleManifest)
	}
	info := &BundleInfo{Paths: map[string]bool{}}
	listed := map[string]bool{}
	var expanded uint64
	for _, e := range m.Files {
		f, ok := byName[e.Path]
		if !ok {
			return nil, userErr("manifest lists %q, which is not in the ZIP", e.Path)
		}
		listed[e.Path] = true
		if e.Directory {
			continue
		}
		if f.FileInfo().IsDir() {
			return nil, userErr("manifest says %q is a file, the ZIP has a directory", e.Path)
		}
		if int64(f.UncompressedSize64) != e.Size {
			return nil, userErr("%q: manifest size %d, ZIP size %d", e.Path, e.Size, f.UncompressedSize64)
		}
		expanded += f.UncompressedSize64
		if expanded > maxBundleExpanded {
			return nil, userErr("bundle expands to more than 4 GiB")
		}
		sum, err := hashMember(f)
		if err != nil {
			return nil, userErr("read %q: %v", e.Path, err)
		}
		if !strings.EqualFold(sum, e.SHA256) {
			return nil, userErr("%q: SHA-256 does not match the manifest", e.Path)
		}
		info.Paths[e.Path] = true
	}
	for name := range byName {
		if !listed[name] {
			return nil, userErr("ZIP member %q is not in the manifest", name)
		}
	}
	info.Members = len(info.Paths)
	return info, nil
}

func checkMemberPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, `\`) || strings.Contains(p, ":") || path.Clean(p) != p {
		return userErr("bundle member %q: use clean relative paths with forward slashes", p)
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." || part == "." || reservedWin.MatchString(part) {
			return userErr("bundle member %q has a traversal or reserved name", p)
		}
	}
	return nil
}

func hashMember(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(rc, int64(f.UncompressedSize64)+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Execution is who the installer runs as (per deployment). Password is
// write-only: it never leaves memory except in the signed command.
type Execution struct {
	Mode           string  `json:"mode,omitempty"` // system (default) | logged_in_user | specified_account
	SessionID      *uint32 `json:"session_id,omitempty"`
	Username       string  `json:"username,omitempty"`
	Domain         string  `json:"domain,omitempty"`
	Password       string  `json:"password,omitempty"`
	DetectionScope string  `json:"detection_scope,omitempty"` // machine | user
}

func (e *Execution) validate() error {
	e.Mode = strings.ToLower(strings.TrimSpace(e.Mode))
	if e.Mode == "" {
		e.Mode = "system"
	}
	e.DetectionScope = strings.ToLower(strings.TrimSpace(e.DetectionScope))
	if e.DetectionScope != "" && e.DetectionScope != "machine" && e.DetectionScope != "user" {
		return userErr("execution.detection_scope must be machine or user")
	}
	switch e.Mode {
	case "system":
		if e.Username != "" || e.Domain != "" || e.Password != "" || e.SessionID != nil {
			return userErr("execution mode system takes no account or session_id")
		}
		if e.DetectionScope == "user" {
			return userErr("execution mode system can't use detection_scope user")
		}
	case "logged_in_user":
		if e.Username != "" || e.Domain != "" || e.Password != "" {
			return userErr("execution mode logged_in_user takes no account (optionally session_id)")
		}
	case "specified_account":
		if e.SessionID != nil {
			return userErr("execution mode specified_account takes no session_id")
		}
		if err := checkText("execution.username", e.Username, 1, 256); err != nil {
			return err
		}
		if err := checkText("execution.domain", e.Domain, 0, 256); err != nil {
			return err
		}
		if e.Password == "" {
			return userErr("execution mode specified_account needs a password")
		}
	default:
		return userErr("execution.mode must be system, logged_in_user or specified_account")
	}
	return nil
}

// validateSecrets checks secure parameter names and size, and that no secret
// (or the run-as password) appears in anything public the command carries -
// the agent refuses such a command, so refuse it here first.
func validateSecrets(secrets map[string]string, password string, params map[string]string, public []string) error {
	total := len(password)
	seen := map[string]bool{}
	for k, v := range secrets {
		if !paramNameRe.MatchString(k) {
			return userErr("secure parameter name %q must match %s", k, paramNameRe)
		}
		if seen[strings.ToLower(k)] {
			return userErr("secure parameter names %q collide (case-insensitive)", k)
		}
		seen[strings.ToLower(k)] = true
		for p := range params {
			if strings.EqualFold(p, k) {
				return userErr("secure parameter %q has the same name as a public parameter", k)
			}
		}
		total += len(k) + len(v)
	}
	if total > maxSecretBytes {
		return userErr("secure parameters and password exceed 64 KiB")
	}
	values := []string{}
	for k, v := range secrets {
		values = append(values, "${"+k+"}")
		if len(v) >= 4 {
			values = append(values, v)
		}
	}
	if len(password) >= 4 {
		values = append(values, password)
	}
	for _, text := range public {
		for _, v := range values {
			if v != "" && strings.Contains(text, v) {
				return userErr("secure values (and the run-as password) may not appear in commands, arguments, " +
					"parameters or names; the installer reads them from stdin JSON")
			}
		}
	}
	return nil
}

// CommandType is the agent command for a spec: each feature needs its own
// signed type and the agent never falls back to an older one.
func CommandType(s *aegisonev1.SoftwareDeploySpec) string {
	switch {
	case s.GetDetection() != nil:
		return "software_deploy_detect"
	case s.GetSteps() != nil:
		return "software_deploy_workflow"
	case s.GetBundle() != nil:
		return "software_deploy_bundle"
	case s.GetExecution() != nil || len(s.GetSecureParameters()) > 0:
		return "software_deploy_v2"
	default:
		return "software_deploy"
	}
}

func (s *Steps) proto() *aegisonev1.SoftwareDeploymentSteps {
	if s.empty() {
		return nil
	}
	conv := func(list []Step) []*aegisonev1.SoftwareCommandStep {
		out := make([]*aegisonev1.SoftwareCommandStep, 0, len(list))
		for _, st := range list {
			out = append(out, &aegisonev1.SoftwareCommandStep{
				Name: st.Name, Command: st.Command, Arguments: st.Arguments, TimeoutSeconds: st.TimeoutSeconds,
				SuccessExitCodes: st.SuccessExitCodes, UseSecureParameters: st.UseSecureParameters,
			})
		}
		return out
	}
	return &aegisonev1.SoftwareDeploymentSteps{Before: conv(s.Before), After: conv(s.After), Rollback: conv(s.Rollback)}
}

func (d *Detection) proto() *aegisonev1.SoftwareDetection {
	if d == nil {
		return nil
	}
	out := &aegisonev1.SoftwareDetection{Mode: d.Mode}
	for _, r := range d.Rules {
		out.Rules = append(out.Rules, &aegisonev1.SoftwareDetectionRule{
			Kind: r.Kind, Path: r.Path, MinimumVersion: r.MinimumVersion, Hive: r.Hive, Key: r.Key, View: r.View,
			ValueName: r.ValueName, ValueType: r.ValueType, ExpectedValue: r.ExpectedValue,
		})
	}
	return out
}

// publicText is every public string of a package that a secret must not
// appear in.
func (p *Package) publicText() []string {
	out := []string{p.Name, p.Version, p.SilentArgs, p.ProductCode, p.UninstallKey, p.DisplayName,
		p.BundleEntryPoint, p.BundleCommand, p.BundleDestination}
	for k, v := range p.Parameters {
		out = append(out, k, v)
	}
	if p.Steps != nil {
		for _, list := range [][]Step{p.Steps.Before, p.Steps.After, p.Steps.Rollback} {
			for _, st := range list {
				out = append(out, st.Name, st.Command, st.Arguments)
			}
		}
	}
	if p.Detection != nil {
		for _, r := range p.Detection.Rules {
			out = append(out, r.Path, r.Key, r.ValueName, r.ExpectedValue)
		}
	}
	return out
}
