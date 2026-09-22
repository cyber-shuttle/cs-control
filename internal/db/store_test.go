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

func count(t *testing.T, dsn, query string) (n int) {
	t.Helper()
	raw, err := sql.Open("pgx", dsn)
	testutil.Check(t, err)
	defer func() { testutil.Check(t, raw.Close()) }()
	testutil.Check(t, raw.QueryRow(query).Scan(&n))
	return n
}

const tablesInSchema = `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema()`

func TestOpenCreatesSchemaOnceAndRejectsForeignSchemas(t *testing.T) {
	dsn, dir := testutil.Database(t), t.TempDir()
	database, err := Open(dsn, dir, fixtureSchema)
	testutil.Check(t, err)
	testutil.Check(t, database.Locked(func(sqlDB *sql.DB) error {
		_, err := sqlDB.Exec(`INSERT INTO fixtures (id, value) VALUES (1, 'stored')`)
		return err
	}))
	testutil.Check(t, database.Close())
	database, err = Open(dsn, dir, `CREATE TABLE fixtures (id INTEGER PRIMARY KEY)`)
	testutil.Check(t, err)
	testutil.Check(t, database.Close())
	testutil.Equal(t, count(t, dsn, `SELECT count(*) FROM fixtures`), 1, "rows after reopen")

	foreign := testutil.Database(t)
	raw, err := sql.Open("pgx", foreign)
	testutil.Check(t, err)
	_, err = raw.Exec(`CREATE TABLE unrelated (id INTEGER PRIMARY KEY)`)
	testutil.Check(t, errors.Join(err, raw.Close()))
	if _, err := Open(foreign, dir, fixtureSchema); err == nil {
		t.Fatal("a schema without the format marker was accepted")
	}
	testutil.Equal(t, count(t, foreign, tablesInSchema), 1, "tables in the refused schema")
}

func TestOpenRollsBackAFailedPristineSchema(t *testing.T) {
	dsn := testutil.Database(t)
	if _, err := Open(dsn, t.TempDir(), fixtureSchema+`; CREATE TABLE broken (`); err == nil {
		t.Fatal("broken schema was accepted")
	}
	testutil.Equal(t, count(t, dsn, tablesInSchema), 0, "tables left by the failed schema")
}

func TestOpenSharesHandlesReopensAndRollsBack(t *testing.T) {
	dsn, dir := testutil.Database(t), t.TempDir()
	first, err := Open(dsn, dir, fixtureSchema)
	testutil.Check(t, err)
	again, err := Open(dsn, dir, "")
	testutil.Check(t, err)
	if again != first {
		t.Fatal("one database URL received two handles")
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
	testutil.Check(t, first.Close())
	testutil.Equal(t, count(t, dsn, `SELECT count(*) FROM fixtures`), 0, "rows after rollback")
	reopened, err := Open(dsn, dir, "")
	testutil.Check(t, err)
	if reopened == first {
		t.Fatal("Open returned a closed cached handle")
	}
	testutil.Check(t, reopened.Close())
}

func TestOpenAndLockedCyclesWaitForTheStateDirectoryFileLock(t *testing.T) {
	dsn, dir := testutil.Database(t), t.TempDir()
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
		database, err = Open(dsn, dir, fixtureSchema)
		return err
	})
	defer func() { _ = database.Close() }()
	blocked("state cycle", func() error { return database.Locked(func(*sql.DB) error { return nil }) })
}
