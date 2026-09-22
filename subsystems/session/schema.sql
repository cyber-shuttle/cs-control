CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  payload TEXT NOT NULL
);

CREATE TABLE runs (
  position BIGINT GENERATED ALWAYS AS IDENTITY,
  session_id TEXT NOT NULL,
  seq BIGINT NOT NULL,
  owner TEXT NOT NULL,
  payload TEXT NOT NULL,
  PRIMARY KEY (session_id, seq)
);
