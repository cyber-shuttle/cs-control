CREATE TABLE ssh_hosts (
  principal TEXT NOT NULL,
  host TEXT NOT NULL,
  payload TEXT NOT NULL,
  PRIMARY KEY (principal, host)
);

-- An alias is unique regardless of case, as OpenSSH matches Host patterns.
CREATE UNIQUE INDEX ssh_hosts_alias ON ssh_hosts (principal, lower(host));

CREATE TABLE ssh_keys (
  principal TEXT NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  PRIMARY KEY (principal, name)
);
