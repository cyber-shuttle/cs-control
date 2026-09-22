package db

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

const fixtureSchema = `CREATE TABLE fixtures (id INTEGER PRIMARY KEY, value TEXT NOT NULL)`

func countFixtures(t *testing.T, database *DB) (count int) {
	t.Helper()
	testutil.Check(t, database.Locked(func(sqlDB *sql.DB) error {
		return sqlDB.QueryRow(`SELECT count(*) FROM fixtures`).Scan(&count)
	}))
	return count
}

func TestOpenCreatesSchemaOnceAndRejectsForeignDatabases(t *testing.T) {
	dir := t.TempDir()
	database, err := Open(dir, fixtureSchema)
	testutil.Check(t, err)
	testutil.Check(t, database.Locked(func(sqlDB *sql.DB) error {
		_, err := sqlDB.Exec(`INSERT INTO fixtures (id, value) VALUES (1, 'stored')`)
		return err
	}))
	testutil.Check(t, database.Close())

	database, err = Open(dir, `CREATE TABLE fixtures (id INTEGER PRIMARY KEY)`)
	testutil.Check(t, err)
	testutil.Equal(t, countFixtures(t, database), 1, "rows after reopen")
	testutil.Check(t, database.Close())

	foreignDir := t.TempDir()
	raw, err := sql.Open("sqlite", Path(foreignDir))
	testutil.Check(t, err)
	_, err = raw.Exec(`CREATE TABLE unrelated (id INTEGER PRIMARY KEY)`)
	testutil.Check(t, err)
	testutil.Check(t, raw.Close())
	if _, err := Open(foreignDir, fixtureSchema); err == nil {
		t.Fatal("existing database without the format marker was accepted")
	}
	raw, err = sql.Open("sqlite", Path(foreignDir))
	testutil.Check(t, err)
	defer func() { testutil.Check(t, raw.Close()) }()
	var tables int
	testutil.Check(t, raw.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'fixtures'`).Scan(&tables))
	if tables != 0 {
		t.Fatal("foreign database was mutated")
	}
}

func TestOpenCleansUpFailedPristineSchema(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, fixtureSchema+`; CREATE TABLE broken (`); err == nil {
		t.Fatal("broken schema was accepted")
	}
	for _, suffix := range []string{"", "-shm", "-wal"} {
		if _, err := os.Lstat(Path(dir) + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed database artifact %q remains: %v", suffix, err)
		}
	}
}

func TestOpenSharesCanonicalHandleReopensAndRollsBack(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "state")
	testutil.Check(t, os.Symlink(dir, alias))
	first, err := Open(dir, fixtureSchema)
	testutil.Check(t, err)
	aliased, err := Open(alias, "")
	testutil.Check(t, err)
	if aliased != first {
		t.Fatal("equivalent state paths received different handles")
	}
	failure := errors.New("rollback")
	if err := first.Tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO fixtures (id, value) VALUES (1, 'discard')`); err != nil {
			return err
		}
		return failure
	}); !errors.Is(err, failure) {
		t.Fatalf("transaction error = %v", err)
	}
	testutil.Equal(t, countFixtures(t, first), 0, "rows after rollback")
	testutil.Check(t, first.Close())
	reopened, err := Open(alias, "")
	testutil.Check(t, err)
	if reopened == first {
		t.Fatal("Open returned a closed cached handle")
	}
	testutil.Check(t, reopened.Close())
}

func TestOpenAndLockedCyclesWaitForTheStateDirectoryFileLock(t *testing.T) {
	dir := t.TempDir()
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	testutil.Check(t, err)
	defer func() { _ = lock.Close() }()
	blocked := func(name string, operation func() error) {
		t.Helper()
		testutil.Check(t, syscall.Flock(int(lock.Fd()), syscall.LOCK_EX))
		done := make(chan error, 1)
		go func() { done <- operation() }()
		testutil.RemainsBlocked(t, done, name+" bypassed the directory lock")
		testutil.Check(t, syscall.Flock(int(lock.Fd()), syscall.LOCK_UN))
		testutil.Within(t, done, 3*time.Second, name+" remained blocked after the directory lock was released")
	}
	var database *DB
	blocked("Open", func() (err error) {
		database, err = Open(dir, fixtureSchema)
		return err
	})
	defer func() { _ = database.Close() }()
	blocked("state cycle", func() error { return database.Locked(func(*sql.DB) error { return nil }) })
}
