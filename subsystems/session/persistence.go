// Session and run persistence belongs to the session subsystem. Rows hold the nested lifecycle values as JSON text
// beside explicit owner and identity columns for principal isolation and stable composite keys. The package keeps
// its in-memory mutation model: each complete cycle loads state under the process-wide lock and replaces both
// tables in one transaction. Queries in query.sql are generated into query.sql.go by sqlc.
package session

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/cyber-shuttle/cs-control/internal/db"
	"github.com/cyber-shuttle/cs-control/internal/security"
)

//go:embed schema.sql
var Schema string

var background = context.Background()

type Store struct {
	Dir      string
	Database *db.DB
}

func (s Store) locked(fn func(*state) error) error {
	return s.Database.Locked(func(database *sql.DB) error {
		queries := New(database)
		sessionRows, err := queries.ListSessions(background)
		if err != nil {
			return err
		}
		runRows, err := queries.ListRuns(background)
		if err != nil {
			return err
		}
		current := &state{Sessions: make(map[string]*Session, len(sessionRows)), Runs: make([]runRecord, 0, len(runRows))}
		for _, row := range sessionRows {
			session, err := db.DecodePayload(row.Payload, func(s Session) bool { return s.ID == row.ID }, "session "+row.ID)
			if err != nil {
				return err
			}
			current.Sessions[session.ID] = &session
		}
		for _, row := range runRows {
			run, err := db.DecodePayload(row.Payload, func(r runRecord) bool { return r.SessionID == row.SessionID && int64(r.Seq) == row.Seq }, fmt.Sprintf("run %s/%d", row.SessionID, row.Seq))
			if err != nil {
				return err
			}
			current.Runs = append(current.Runs, run)
		}
		return fn(current)
	})
}

func (s Store) save(current *state) error {
	return s.Database.Tx(func(tx *sql.Tx) error {
		queries := New(tx)
		if err := errors.Join(queries.ClearSessions(background), queries.ClearRuns(background)); err != nil {
			return err
		}
		for _, session := range current.Sessions {
			payload, err := json.Marshal(session)
			if err != nil {
				return err
			}
			if err := queries.InsertSession(background, InsertSessionParams{ID: session.ID, Owner: security.PrincipalDirName(session.Owner), Payload: string(payload)}); err != nil {
				return err
			}
		}
		for _, run := range current.Runs {
			payload, err := json.Marshal(run)
			if err != nil {
				return err
			}
			if err := queries.InsertRun(background, InsertRunParams{SessionID: run.SessionID, Seq: int64(run.Seq), Owner: security.PrincipalDirName(run.Owner), Payload: string(payload)}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s Service) loadSessions() ([]Session, error) {
	var result []Session
	err := s.store.locked(func(current *state) error {
		for _, id := range slices.Sorted(maps.Keys(current.Sessions)) {
			result = append(result, *current.Sessions[id])
		}
		return nil
	})
	return result, err
}

func (s Service) loadSession(id string) (*Session, error) {
	var result *Session
	err := s.store.locked(func(current *state) error {
		session := current.Sessions[id]
		if session == nil {
			return errSessionNotFound
		}
		result = detached(session)
		return nil
	})
	return result, err
}
