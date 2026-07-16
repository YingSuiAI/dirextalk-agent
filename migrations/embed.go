package migrations

import "embed"

// Files contains the ordered Agent-owned PostgreSQL migrations.
//
//go:embed *.up.sql
var Files embed.FS
