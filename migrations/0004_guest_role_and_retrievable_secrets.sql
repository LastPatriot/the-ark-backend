-- no-transaction
-- New `guest` role (view, download, upload) for PINs and join tokens; join tokens may
-- also grant contributor. Adds encrypted copies of PINs and join-token secrets
-- (src/vault.rs) so the admin can look them up again; rows from before this stay NULL.
--
-- SQLite cannot alter a CHECK constraint, so both tables are rebuilt the way SQLite
-- documents: with foreign keys off (only possible outside a transaction), so
-- sessions.pin_id and sessions.token_id keep pointing at the rebuilt tables.
PRAGMA foreign_keys = OFF;
BEGIN IMMEDIATE;

CREATE TABLE pins_new (
  id          TEXT PRIMARY KEY,
  folder_id   TEXT REFERENCES folders(id),       -- NULL = hub PIN (home page)
  label       TEXT NOT NULL,                     -- e.g. "Photographers"
  pin_hash    TEXT NOT NULL,                     -- argon2id
  role        TEXT NOT NULL CHECK (role IN ('viewer','uploader','guest','contributor','editor','hub')),
  expires_at  TEXT,
  max_uses    INTEGER,
  uses        INTEGER NOT NULL DEFAULT 0,
  revoked_at  TEXT,
  created_at  TEXT NOT NULL,
  pin_sealed  TEXT                               -- the PIN, encrypted for this row id
);
INSERT INTO pins_new (id, folder_id, label, pin_hash, role, expires_at, max_uses, uses, revoked_at, created_at)
  SELECT id, folder_id, label, pin_hash, role, expires_at, max_uses, uses, revoked_at, created_at FROM pins;
DROP TABLE pins;
ALTER TABLE pins_new RENAME TO pins;

CREATE TABLE join_tokens_new (
  id            TEXT PRIMARY KEY,
  folder_id     TEXT NOT NULL REFERENCES folders(id),
  token_hash    TEXT NOT NULL UNIQUE,            -- sha256 of the raw token
  role          TEXT NOT NULL CHECK (role IN ('viewer','uploader','guest','contributor')),
  label         TEXT NOT NULL,
  expires_at    TEXT,
  max_uses      INTEGER,
  uses          INTEGER NOT NULL DEFAULT 0,
  revoked_at    TEXT,
  created_at    TEXT NOT NULL,
  token_sealed  TEXT                             -- the raw token, encrypted for this row id
);
INSERT INTO join_tokens_new (id, folder_id, token_hash, role, label, expires_at, max_uses, uses, revoked_at, created_at)
  SELECT id, folder_id, token_hash, role, label, expires_at, max_uses, uses, revoked_at, created_at FROM join_tokens;
DROP TABLE join_tokens;
ALTER TABLE join_tokens_new RENAME TO join_tokens;

COMMIT;
PRAGMA foreign_keys = ON;
