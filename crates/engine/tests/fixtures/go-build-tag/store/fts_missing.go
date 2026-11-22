//go:build !sqlite_fts5

package store

import "errors"

// Open fails as SQLite does when its FTS5 module is not built in.
func Open() error { return errors.New("no such module: fts5") }
