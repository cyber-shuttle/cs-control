// Package db owns cs-plane's Postgres connection and complete state-operation boundary. The DSN's search_path names
// the one schema cs-plane owns, so it can share a server and database with other services. A cached handle plus a
// state-directory file lock serialize read-modify-write cycles across processes; callers may nest a transaction
// inside that cycle when database changes must coordinate with protected files, and read single statements
// unlocked. Feature packages own every table and query. Schema DDL runs only in an empty schema; an existing one is
// accepted by its format marker or rejected.
package db

//go:generate sqlc generate -f ../../sqlc.yaml

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	schemaFormat = "sql-v1"
	metaSchema   = `CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`
)

type DB struct {
	sql      *sql.DB
	mu       sync.Mutex
	cacheKey string
	lockPath string
}

var (
	handlesMu sync.Mutex
	handles   = map[string]*DB{}
)

// DecodePayload reads a JSON payload column and refuses one whose identity does not match its row.
func DecodePayload[T any](payload string, identity func(T) bool, what string) (T, error) {
	var value T
	if err := json.Unmarshal([]byte(payload), &value); err != nil {
		return value, fmt.Errorf("read %s: %w", what, err)
	}
	if !identity(value) {
		return value, fmt.Errorf("read %s: payload identity does not match", what)
	}
	return value, nil
}

// IsConstraint reports whether err is an integrity-constraint violation such as a duplicate key.
func IsConstraint(err error) bool {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	return ok && len(pgErr.Code) == 5 && pgErr.Code[:2] == "23"
}

func open(dsn, schema string) (*DB, error) {
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	handle := &DB{sql: database}
	var owned sql.NullString
	var tables int
	err = database.QueryRow(`SELECT current_schema(), (SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema())`).Scan(&owned, &tables)
	switch {
	case err != nil:
	case !owned.Valid:
		err = errors.New("the database URL's search_path names no existing schema")
	case tables == 0:
		err = handle.Tx(func(tx *sql.Tx) error {
			if _, err := tx.Exec(metaSchema + ";" + schema); err != nil {
				return err
			}
			_, err := tx.Exec(`INSERT INTO schema_meta (key, value) VALUES ('format', $1)`, schemaFormat)
			return err
		})
	default:
		var format string
		if queryErr := database.QueryRow(`SELECT value FROM schema_meta WHERE key = 'format'`).Scan(&format); queryErr != nil || format != schemaFormat {
			err = errors.New("unsupported state database format")
		}
	}
	if err != nil {
		return nil, errors.Join(err, database.Close())
	}
	return handle, nil
}

// Open returns the shared handle for dsn, creating the schema's tables only when it holds none yet. lockDir holds
// the file lock that serializes state cycles across cs-plane processes.
func Open(dsn, lockDir, schema string) (*DB, error) {
	if dsn == "" || lockDir == "" {
		return nil, errors.New("database URL and state directory are required")
	}
	handlesMu.Lock()
	defer handlesMu.Unlock()
	if handle := handles[dsn]; handle != nil {
		return handle, nil
	}
	lockPath := filepath.Join(lockDir, ".lock")
	var handle *DB
	err := security.WithFileLock(lockPath, func() (err error) {
		handle, err = open(dsn, schema)
		return err
	})
	if err != nil {
		return nil, err
	}
	handle.cacheKey, handle.lockPath = dsn, lockPath
	handles[dsn] = handle
	return handle, nil
}

func (d *DB) Close() error {
	handlesMu.Lock()
	defer handlesMu.Unlock()
	err := d.sql.Close()
	if handles[d.cacheKey] == d {
		delete(handles, d.cacheKey)
	}
	return err
}

// Locked runs one complete state cycle under the process mutex and the cross-process directory lock.
func (d *DB) Locked(fn func(*sql.DB) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return security.WithFileLock(d.lockPath, func() error { return fn(d.sql) })
}

func (d *DB) Reader() *sql.DB { return d.sql }

func (d *DB) Tx(fn func(*sql.Tx) error) (err error) {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, tx.Rollback())
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
