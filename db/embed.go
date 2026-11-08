// Package db carries the SQL migrations inside the Go binaries, so the
// migrate tool and the server's startup check always agree with the code
// they ship with (internal/dbmigrate).
package db

import "embed"

// Migrations holds migrations/NNNN_name.sql, applied in file-name order.
//
//go:embed migrations/*.sql
var Migrations embed.FS
