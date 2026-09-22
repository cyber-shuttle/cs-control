// Package db owns the process-wide SQLite connection and complete state-operation boundary. A cached handle and
// filesystem lock serialize read-modify-write cycles across processes; callers may nest a transaction inside that
// cycle when database changes must coordinate with protected files. Feature packages own every table and query.
// Schema DDL runs only for a pristine database; existing formats are either accepted exactly or rejected.
package db

//go:generate sqlc generate -f ../../sqlc.yaml

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cyber-shuttle/cs-control/internal/security"
	"modernc.org/sqlite"
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

func Path(dir string) string { return filepath.Join(dir, "state.db") }

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

// IsConstraint reports whether err is a SQLite constraint violation such as a duplicate key.
func IsConstraint(err error) bool {
	sqliteErr, ok := errors.AsType[*sqlite.Error](err)
	return ok && sqliteErr.Code()&0xff == 19
}

func open(path string, pristine bool, schema string) (*DB, error) {
	database, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	handle := &DB{sql: database}
	if pristine {
		err = handle.Tx(func(tx *sql.Tx) error {
			if _, err := tx.Exec(metaSchema + ";" + schema); err != nil {
				return err
			}
			_, err := tx.Exec(`INSERT INTO schema_meta (key, value) VALUES ('format', ?)`, schemaFormat)
			return err
		})
	} else {
		var format string
		if queryErr := database.QueryRow(`SELECT value FROM schema_meta WHERE key = 'format'`).Scan(&format); queryErr != nil || format != schemaFormat {
			err = errors.New("unsupported state database format")
		}
	}
	if err == nil {
		var mode string
		err = database.QueryRow(`PRAGMA journal_mode = WAL`).Scan(&mode)
		if err == nil && mode != "wal" {
			err = fmt.Errorf("enable SQLite WAL mode: got %q", mode)
		}
	}
	if err != nil {
		return nil, errors.Join(err, database.Close())
	}
	return handle, nil
}

// Open returns the shared handle for dir, creating state.db with schema only when no database exists yet.
func Open(dir string, schema string) (*DB, error) {
	if dir == "" {
		return nil, errors.New("state directory is required")
	}
	dir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return nil, err
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	handlesMu.Lock()
	defer handlesMu.Unlock()
	if handle := handles[dir]; handle != nil {
		return handle, nil
	}

	path := Path(dir)
	lockPath := filepath.Join(dir, ".lock")
	var handle *DB
	var pristine bool
	err = security.WithFileLock(lockPath, func() error {
		_, statErr := os.Lstat(path)
		pristine = errors.Is(statErr, os.ErrNotExist)
		if statErr != nil && !pristine {
			return statErr
		}
		handle, err = open(path, pristine, schema)
		return err
	})
	if err != nil {
		if pristine {
			err = errors.Join(err, security.RemoveFile(path), security.RemoveFile(path+"-shm"), security.RemoveFile(path+"-wal"))
		}
		return nil, err
	}
	handle.cacheKey, handle.lockPath = dir, lockPath
	handles[dir] = handle
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
