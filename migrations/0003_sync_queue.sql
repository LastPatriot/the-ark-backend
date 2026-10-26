-- sync_queue was not used before M4. Recreated without the foreign key to files so a
-- remote delete can stay queued after its file row is purged, and with the remote
-- path and retry schedule the sync worker needs.
DROP TABLE sync_queue;
CREATE TABLE sync_queue (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id         TEXT NOT NULL,
  action          TEXT NOT NULL CHECK (action IN ('upload','delete')),
  remote_path     TEXT NOT NULL,                 -- relative to ARK_SYNC_REMOTE
  status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','done','failed')),
  attempts        INTEGER NOT NULL DEFAULT 0,
  last_error      TEXT,
  next_attempt_at TEXT,
  created_at      TEXT NOT NULL,
  synced_at       TEXT
);
CREATE INDEX sync_queue_due ON sync_queue(status, next_attempt_at);
CREATE INDEX sync_queue_file ON sync_queue(file_id);
