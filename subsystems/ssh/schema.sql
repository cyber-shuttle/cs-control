CREATE TABLE ssh_hosts (
  principal TEXT NOT NULL,
  host TEXT NOT NULL COLLATE NOCASE,
  payload TEXT NOT NULL,
  PRIMARY KEY (principal, host)
);

CREATE TABLE ssh_keys (
  principal TEXT NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  PRIMARY KEY (principal, name)
);
