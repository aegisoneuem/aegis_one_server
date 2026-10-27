package wucatalog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"aegis-one/internal/cabfeed"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Result struct {
	CabSHA256 string
	Updates   int // UpdateIDs with at least one installable file
	Rows      int
	Skipped   bool // the current cab was already indexed
}

// IndexCurrent rebuilds wu_update_files from the current wsusscn2.cab unless
// that cab is already indexed. bsdtar is the libarchive CLI (bsdtar on Linux,
// tar.exe on Windows 10+): the inner cabs are LZX-compressed and Go has no
// reader for that.
func IndexCurrent(ctx context.Context, pool *pgxpool.Pool, contentDir, bsdtar string) (Result, error) {
	cat, err := cabfeed.Current(ctx, pool)
	if err != nil {
		return Result{}, err
	}
	if cat == nil {
		return Result{}, errors.New("no scan cab downloaded yet")
	}
	res := Result{CabSHA256: cat.SHA256}
	var indexed bool
	if err := pool.QueryRow(ctx, `SELECT indexed_at IS NOT NULL FROM scan_catalogs WHERE sha256_hash = $1`, cat.SHA256).Scan(&indexed); err != nil {
		return res, err
	}
	if indexed {
		res.Skipped = true
		return res, nil
	}

	files, err := parseCab(ctx, filepath.Join(contentDir, filepath.FromSlash(cat.FileName)), bsdtar)
	if err != nil {
		return res, err
	}
	res.Updates = len(files)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	if _, err := tx.Exec(ctx, `DELETE FROM wu_update_files`); err != nil {
		return res, err
	}
	rows := make([][]any, 0, len(files)*2)
	for id, list := range files {
		for _, f := range list {
			rows = append(rows, []any{id, f.Digest, f.Name, f.URL})
		}
	}
	n, err := tx.CopyFrom(ctx, pgx.Identifier{"wu_update_files"},
		[]string{"update_id", "file_digest", "file_name", "url"}, pgx.CopyFromRows(rows))
	if err != nil {
		return res, fmt.Errorf("store wu_update_files: %w", err)
	}
	res.Rows = int(n)
	if _, err := tx.Exec(ctx, `UPDATE scan_catalogs SET indexed_at = now() WHERE sha256_hash = $1`, cat.SHA256); err != nil {
		return res, err
	}
	return res, tx.Commit(ctx)
}

// parseCab extracts package.cab from the outer cab to a temp file, then
// streams package.xml out of it straight into Parse (it is ~120 MB).
func parseCab(ctx context.Context, cabPath, bsdtar string) (map[string][]File, error) {
	tmp, err := os.CreateTemp(filepath.Dir(cabPath), ".package-*.cab")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if err := run(ctx, bsdtar, tmp, "-xOf", cabPath, "package.cab"); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("extract package.cab: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, bsdtar, "-xOf", tmp.Name(), "package.xml")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", bsdtar, err)
	}
	files, perr := Parse(out)
	io.Copy(io.Discard, out) //nolint:errcheck // drain so Wait can't block on a full pipe
	if werr := cmd.Wait(); werr != nil {
		return nil, fmt.Errorf("extract package.xml: %w: %s", werr, strings.TrimSpace(stderr.String()))
	}
	return files, perr
}

func run(ctx context.Context, name string, stdout io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
