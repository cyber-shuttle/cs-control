// Session and run persistence belongs to the session subsystem. Rows hold the nested lifecycle values as JSON text
// beside explicit owner and identity columns for principal isolation and stable composite keys. Writes keep the
// in-memory mutation model: each cycle loads state under the process-wide lock and replaces both tables in one
// transaction, so a read is one unlocked statement that sees a whole cycle or none of it. Queries in query.sql are
// generated into query.sql.go by sqlc.
package session

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cyber-shuttle/cs-plane/internal/db"
	"github.com/cyber-shuttle/cs-plane/internal/security"
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
			session, err := decodeSession(row.ID, row.Payload)
			if err != nil {
				return err
			}
			current.Sessions[session.ID] = &session
		}
		for _, row := range runRows {
			run, err := decodeRun(row.SessionID, row.Seq, row.Payload)
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

func decodeSession(id, payload string) (Session, error) {
	session, err := db.DecodePayload(payload, func(s Session) bool { return s.ID == id }, "session "+id)
	return session, err
}

func decodeRun(sessionID string, seq int64, payload string) (runRecord, error) {
	return db.DecodePayload(payload, func(r runRecord) bool { return r.SessionID == sessionID && int64(r.Seq) == seq }, fmt.Sprintf("run %s/%d", sessionID, seq))
}

func (s Store) queries() *Queries { return New(s.Database.Reader()) }

func (s Service) loadSessions() ([]Session, error) {
	rows, err := s.Store.queries().ListSessions(background)
	if err != nil {
		return nil, err
	}
	result := make([]Session, 0, len(rows))
	for _, row := range rows {
		session, err := decodeSession(row.ID, row.Payload)
		if err != nil {
			return nil, err
		}
		result = append(result, session)
	}
	return result, nil
}

func (s Service) loadSession(id string) (*Session, error) {
	payload, err := s.Store.queries().GetSession(background, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	session, err := decodeSession(id, payload)
	return &session, err
}

func (s Service) sessionsOf(principal security.Principal) ([]Session, error) {
	rows, err := s.Store.queries().ListSessionsByOwner(background, security.PrincipalDirName(principal))
	if err != nil {
		return nil, err
	}
	result := make([]Session, 0, len(rows))
	for _, row := range rows {
		session, err := decodeSession(row.ID, row.Payload)
		if err != nil {
			return nil, err
		}
		if session.Owner == principal {
			result = append(result, session)
		}
	}
	return result, nil
}

func (s Service) Runs(principal security.Principal) ([]Run, error) {
	rows, err := s.Store.queries().ListRunsByOwner(background, security.PrincipalDirName(principal))
	if err != nil {
		return nil, err
	}
	result := make([]Run, 0, len(rows))
	for _, row := range rows {
		run, err := decodeRun(row.SessionID, row.Seq, row.Payload)
		if err != nil {
			return nil, err
		}
		if run.Owner == principal {
			result = append(result, run.Run)
		}
	}
	return result, nil
}
