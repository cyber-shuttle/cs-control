-- name: ListSessions :many
SELECT id, payload FROM sessions ORDER BY id;

-- name: ListRuns :many
SELECT session_id, seq, payload FROM runs ORDER BY position;

-- name: ClearSessions :exec
DELETE FROM sessions;

-- name: ClearRuns :exec
DELETE FROM runs;

-- name: InsertSession :exec
INSERT INTO sessions (id, owner, payload) VALUES ($1, $2, $3);

-- name: InsertRun :exec
INSERT INTO runs (session_id, seq, owner, payload) VALUES ($1, $2, $3, $4);

-- name: GetSession :one
SELECT payload FROM sessions WHERE id = $1;

-- name: ListSessionsByOwner :many
SELECT id, payload FROM sessions WHERE owner = $1 ORDER BY id;

-- name: ListRunsByOwner :many
SELECT session_id, seq, payload FROM runs WHERE owner = $1 ORDER BY position;
