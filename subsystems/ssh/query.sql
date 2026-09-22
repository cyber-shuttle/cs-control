-- name: ListHosts :many
SELECT host, payload FROM ssh_hosts WHERE principal = ? ORDER BY host;

-- name: ListHostPrincipals :many
SELECT DISTINCT principal FROM ssh_hosts ORDER BY principal;

-- name: InsertHost :exec
INSERT INTO ssh_hosts (principal, host, payload) VALUES (?, ?, ?);

-- name: UpdateHost :execrows
UPDATE ssh_hosts SET payload = ? WHERE principal = ? AND host = ? COLLATE BINARY;

-- name: DeleteHost :execrows
DELETE FROM ssh_hosts WHERE principal = ? AND host = ? COLLATE BINARY;

-- name: GetKey :one
SELECT name, type, fingerprint FROM ssh_keys WHERE principal = ? AND name = ?;

-- name: ListKeys :many
SELECT name, type, fingerprint FROM ssh_keys WHERE principal = ? ORDER BY name;

-- name: InsertKey :exec
INSERT INTO ssh_keys (principal, name, type, fingerprint) VALUES (?, ?, ?, ?);

-- name: DeleteKey :execrows
DELETE FROM ssh_keys WHERE principal = ? AND name = ?;
