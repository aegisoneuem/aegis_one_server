package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PrivilegeReport says whether the server's DB login is too powerful. The
// append-only audit_log relies on triggers that only a superuser or the table's
// owner can disable (0001), so the app must never connect as either (CLAUDE.md).
type PrivilegeReport struct {
	User string
	// Fatal: the login can defeat audit_log's protections.
	Fatal []string
	// Warnings: unusual but not dangerous on their own.
	Warnings []string
}

func CheckPrivileges(ctx context.Context, pool *pgxpool.Pool) (PrivilegeReport, error) {
	var r PrivilegeReport
	var super, inAppRole bool
	if err := pool.QueryRow(ctx, `
		SELECT current_user, r.rolsuper,
		       EXISTS (SELECT 1 FROM pg_roles a WHERE a.rolname = 'aegis_app'
		               AND pg_has_role(current_user, a.oid, 'MEMBER'))
		FROM pg_roles r WHERE r.rolname = current_user`).Scan(&r.User, &super, &inAppRole); err != nil {
		return r, fmt.Errorf("read role attributes: %w", err)
	}
	if super {
		r.Fatal = append(r.Fatal, "is a superuser")
	}

	// Ownership counts if the login owns the table or can act as its owner
	// through role membership.
	rows, err := pool.Query(ctx, `
		SELECT c.relname
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
		  AND pg_has_role(current_user, c.relowner, 'USAGE')
		ORDER BY (c.relname = 'audit_log') DESC, c.relname
		LIMIT 6`)
	if err != nil {
		return r, fmt.Errorf("read table owners: %w", err)
	}
	var owned []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return r, err
		}
		owned = append(owned, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return r, err
	}
	if len(owned) > 0 && !super { // a superuser "owns" everything; already reported
		list := strings.Join(owned[:min(len(owned), 5)], ", ")
		if len(owned) > 5 {
			list += ", ..."
		}
		r.Fatal = append(r.Fatal, "owns (or can act as owner of) application tables: "+list)
	}

	if !inAppRole && !super {
		r.Warnings = append(r.Warnings, "is not a member of the aegis_app role (0004_db_roles.sql); permissions may be incomplete")
	}
	return r, nil
}
