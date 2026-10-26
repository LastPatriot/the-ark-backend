-- journal_mode=WAL and foreign_keys=ON are set on every connection in db.rs;
-- SQLite refuses to switch journal mode inside the migration transaction.

CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE folders (
  id            TEXT PRIMARY KEY,               -- uuid v7
  parent_id     TEXT REFERENCES folders(id),    -- NULL = top-level
  slug          TEXT NOT NULL,
  name          TEXT NOT NULL,
  disk_dir      TEXT NOT NULL,                  -- relative to ARK_DATA_DIR/files, never from user input
  is_open       INTEGER NOT NULL DEFAULT 0,     -- open = no PIN needed
  default_role  TEXT,                           -- role when open
  storage_limit INTEGER,                        -- bytes, NULL = unlimited
  archived_at   TEXT,
  created_at    TEXT NOT NULL,
  UNIQUE (parent_id, slug)
);
-- UNIQUE (parent_id, slug) does not cover top-level folders: NULLs are distinct in SQLite.
CREATE UNIQUE INDEX folders_top_slug ON folders(slug) WHERE parent_id IS NULL;

CREATE TABLE folder_slug_history (               -- old slugs redirect after renames
  old_slug  TEXT NOT NULL,
  parent_id TEXT,
  folder_id TEXT NOT NULL REFERENCES folders(id),
  PRIMARY KEY (parent_id, old_slug)
);

CREATE TABLE pins (
  id          TEXT PRIMARY KEY,
  folder_id   TEXT REFERENCES folders(id),       -- NULL = hub PIN (home page)
  label       TEXT NOT NULL,                     -- e.g. "Photographers"
  pin_hash    TEXT NOT NULL,                     -- argon2id
  role        TEXT NOT NULL CHECK (role IN ('viewer','uploader','contributor','editor','hub')),
  expires_at  TEXT,
  max_uses    INTEGER,
  uses        INTEGER NOT NULL DEFAULT 0,
  revoked_at  TEXT,
  created_at  TEXT NOT NULL
);

CREATE TABLE join_tokens (
  id          TEXT PRIMARY KEY,
  folder_id   TEXT NOT NULL REFERENCES folders(id),
  token_hash  TEXT NOT NULL UNIQUE,              -- sha256 of the raw token
  role        TEXT NOT NULL CHECK (role IN ('viewer','uploader')),
  label       TEXT NOT NULL,
  expires_at  TEXT,
  max_uses    INTEGER,
  uses        INTEGER NOT NULL DEFAULT 0,
  revoked_at  TEXT,
  created_at  TEXT NOT NULL
);

CREATE TABLE sessions (
  id            TEXT PRIMARY KEY,                -- random, stored in signed cookie
  root_folder   TEXT REFERENCES folders(id),     -- scope root; NULL only for hub/admin
  role          TEXT NOT NULL,                   -- viewer|uploader|contributor|editor|hub|admin
  pin_id        TEXT REFERENCES pins(id),
  token_id      TEXT REFERENCES join_tokens(id),
  device_label  TEXT,
  ip            TEXT,
  created_at    TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  revoked_at    TEXT
);

CREATE TABLE files (
  id           TEXT PRIMARY KEY,
  folder_id    TEXT NOT NULL REFERENCES folders(id),
  name         TEXT NOT NULL,                    -- display name
  disk_name    TEXT NOT NULL,                    -- sanitized name on disk
  version      INTEGER NOT NULL DEFAULT 1,
  is_current   INTEGER NOT NULL DEFAULT 1,
  size         INTEGER NOT NULL,
  sha256       TEXT NOT NULL,
  mime         TEXT,
  status_tag   TEXT CHECK (status_tag IN ('draft','approved','final')),
  uploaded_by  TEXT,                             -- PIN/token label, never personal data
  session_id   TEXT REFERENCES sessions(id),
  created_at   TEXT NOT NULL,
  deleted_at   TEXT                              -- in trash when set
);
CREATE INDEX files_folder ON files(folder_id, is_current, deleted_at);
CREATE INDEX files_hash   ON files(folder_id, sha256);

CREATE TABLE uploads (
  id          TEXT PRIMARY KEY,                  -- tus upload id
  folder_id   TEXT NOT NULL REFERENCES folders(id),
  filename    TEXT NOT NULL,
  size        INTEGER NOT NULL,
  offset      INTEGER NOT NULL DEFAULT 0,
  session_id  TEXT NOT NULL REFERENCES sessions(id),
  status      TEXT NOT NULL DEFAULT 'active',    -- active|complete|aborted
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE previews (
  file_id  TEXT NOT NULL REFERENCES files(id),
  kind     TEXT NOT NULL,                        -- thumb|poster|hls
  path     TEXT NOT NULL,
  status   TEXT NOT NULL DEFAULT 'pending',
  PRIMARY KEY (file_id, kind)
);

CREATE TABLE sync_queue (                        -- milestone 4
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id     TEXT NOT NULL REFERENCES files(id),
  action      TEXT NOT NULL CHECK (action IN ('upload','delete')),
  status      TEXT NOT NULL DEFAULT 'pending',
  attempts    INTEGER NOT NULL DEFAULT 0,
  last_error  TEXT,
  synced_at   TEXT
);

CREATE TABLE login_attempts (                    -- PIN / admin rate limiting
  key         TEXT PRIMARY KEY,                  -- e.g. "pin:<folder_id>:<ip>"
  failures    INTEGER NOT NULL,
  locked_until TEXT
);

CREATE TABLE audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  actor      TEXT NOT NULL,                      -- 'admin' or PIN/token label
  action     TEXT NOT NULL,
  target     TEXT,
  details    TEXT,
  created_at TEXT NOT NULL
);
