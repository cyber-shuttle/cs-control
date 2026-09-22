-- name: ListHosts :many
SELECT host, payload FROM ssh_hosts WHERE principal = $1 ORDER BY lower(host);

-- name: ListHostPrincipals :many
SELECT DISTINCT principal FROM ssh_hosts ORDER BY principal;

-- name: InsertHost :exec
INSERT INTO ssh_hosts (principal, host, payload) VALUES ($1, $2, $3);

-- name: UpdateHost :execrows
UPDATE ssh_hosts SET payload = $1 WHERE principal = $2 AND host = $3;

-- name: DeleteHost :execrows
DELETE FROM ssh_hosts WHERE principal = $1 AND host = $2;

-- name: GetKey :one
SELECT name, type, fingerprint FROM ssh_keys WHERE principal = $1 AND name = $2;

-- name: ListKeys :many
SELECT name, type, fingerprint FROM ssh_keys WHERE principal = $1 ORDER BY name;

-- name: InsertKey :exec
INSERT INTO ssh_keys (principal, name, type, fingerprint) VALUES ($1, $2, $3, $4);

-- name: DeleteKey :execrows
DELETE FROM ssh_keys WHERE principal = $1 AND name = $2;
