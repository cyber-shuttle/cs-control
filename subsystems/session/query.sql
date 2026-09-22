-- name: ListSessions :many
SELECT id, payload FROM sessions;

-- name: ListRuns :many
SELECT session_id, seq, payload FROM runs ORDER BY rowid;

-- name: ClearSessions :exec
DELETE FROM sessions;

-- name: ClearRuns :exec
DELETE FROM runs;

-- name: InsertSession :exec
INSERT INTO sessions (id, owner, payload) VALUES (?, ?, ?);

-- name: InsertRun :exec
INSERT INTO runs (session_id, seq, owner, payload) VALUES (?, ?, ?, ?);
