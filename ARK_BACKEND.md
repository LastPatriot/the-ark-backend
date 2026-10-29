# Ark Backend — Build Guide

Ark turns any Wi-Fi network into a shared media drive. One Rust server runs on a host
(a PC for the hackathon demo, a Raspberry Pi later). Users join from a browser by
scanning a QR code; a PIN or join QR unlocks **one folder and its subfolders only**.

This file covers the backend only. The frontend will be built later and consume this
API. Until then, every endpoint is documented and tested through **Swagger UI**
(OpenAPI), served by the backend at `/docs`.

- Owner: Opeyemi (backend and platform)
- Demo freeze: 6 Nov 2026 (submission). Hackathon: 28 Nov 2026.

---

## 1. Stack

| Concern | Crate / tool |
| --- | --- |
| Runtime | `tokio` |
| HTTP | `axum`, `tower-http` (trace, cors, compression, limit) |
| Database | SQLite via `sqlx` (features: `sqlite`, `runtime-tokio`, `macros`, `migrate`) |
| Serialization | `serde`, `serde_json` |
| Password / PIN hashing | `argon2` |
| Random tokens | `rand` (128-bit tokens, base64url via `base64`) |
| IDs | `uuid` (v7) |
| Cookies / sessions | `axum-extra` (`cookie-signed`) or `tower-sessions` with SQLite store |
| QR codes | `qrcode` (SVG and PNG via `image`) |
| mDNS | `mdns-sd` |
| Local DNS server (milestone 3) | `hickory-server` |
| API docs / testing | `utoipa` (OpenAPI 3 from code) + `utoipa-swagger-ui` (feature `axum`) |
| Embedded frontend (later) | `rust-embed` |
| Hashing files | `sha2` |
| Logging | `tracing`, `tracing-subscriber` |
| Errors | `thiserror`, `anyhow` |
| Thumbnails (milestone 2) | `image` crate in a blocking task, or shell out to `vipsthumbnail` |
| Video previews (later) | shell out to `ffmpeg` |

Target platforms: `x86_64-pc-windows-msvc` / `x86_64-unknown-linux-gnu` (demo PC),
`aarch64-unknown-linux-gnu` (Pi, build with `cross` or `cargo zigbuild`).

---

## 2. Repository layout

```
ark/
  Cargo.toml
  migrations/
    0001_init.sql
  src/
    main.rs            # config, startup, router, background tasks
    config.rs          # ARK_* env vars / ark.toml
    db.rs              # pool, migrations
    error.rs           # AppError -> HTTP responses
    openapi.rs         # #[derive(OpenApi)] doc, security schemes, Swagger UI mount
    auth/
      mod.rs           # Session extractor, Scope checks, role guards
      pin.rs           # hash/verify PINs, rate limiting
      admin.rs         # admin login
    routes/
      mod.rs
      folders.rs       # unlock, list, create subfolder
      items.rs         # rename/move/tag/delete/restore
      uploads.rs       # tus subset
      downloads.rs     # /dl with Range support
      join.rs          # /j/{token}
      events.rs        # SSE live updates
      admin.rs         # /api/v1/admin/*
      static_files.rs  # embedded frontend + SPA fallback (added when the frontend exists)
    storage.rs         # safe path resolution, .part files, versions, trash
    qr.rs              # QR generation
    discovery.rs       # mDNS announce + IP-change watcher
    workers/
      thumbnails.rs
      trash.rs
      sync.rs          # milestone 4
  scripts/
    upload_test.sh     # curl-driven tus upload for large files (see section 11)
  web/dist/            # built frontend, embedded later
```

---

## 3. Configuration

Environment variables (or `ark.toml`), with defaults:

| Key | Default | Notes |
| --- | --- | --- |
| `ARK_BIND` | `0.0.0.0:80` | Port 80 needs admin rights / `CAP_NET_BIND_SERVICE` on Linux. Use `0.0.0.0:8080` in dev. |
| `ARK_DATA_DIR` | `./ark-data` | Holds `ark.db`, `files/`, `previews/`, `uploads/` |
| `ARK_HOSTNAME` | `ark` | Announced as `ark.local` |
| `ARK_SESSION_HOURS` | `12` | Session lifetime |
| `ARK_COOKIE_KEY` | generated on first run, stored in DB settings | Signs session cookies |
| `ARK_MAX_CHUNK_MB` | `16` | Upper bound for a single PATCH body |
| `ARK_DOCS` | `true` | Serve Swagger UI at `/docs`. Set `false`, or admin-only, for real deployments |

On first run, if no admin password exists, the server prints a one-time setup code
to the console and only `/admin/setup` is usable until the admin password is set.

---

## 4. Database schema (`migrations/0001_init.sql`)

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

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
```

---

## 5. Access model (the most important part)

### Roles and permissions

| Operation | viewer | uploader | guest | contributor | editor | hub | admin |
| --- | --- | --- | --- | --- | --- | --- | --- |
| List folder / previews | yes | own uploads only | yes | yes | yes | yes | yes |
| Download | yes | no | yes | yes | yes | yes | yes |
| Upload | no | yes | yes | yes | yes | yes | yes |
| Create subfolder | no | no | no | yes | yes | yes | yes |
| Rename / move / tag | no | no | no | no | yes | yes | yes |
| Delete to trash / restore | no | no | no | no | yes | yes | yes |
| See home page folder list | no | no | no | no | no | yes | yes |
| Create top-level folders, PINs, QR, settings | no | no | no | no | no | no | yes |

Implement as `fn can(role: Role, action: Action) -> bool` with one match table, plus a
unit test per cell.

### Scope rule

Every session has a `root_folder`. A request on folder `F` is allowed only if `F` is
`root_folder` or a descendant of it.

- Check with an ancestor walk (`WITH RECURSIVE` on `folders.parent_id`), cached per request.
- Out-of-scope requests return **403** with no folder name in the body.
- Listing endpoints never return siblings or parents of the root.
- A subfolder PIN never grants access to its parent.
- Hub and admin sessions have no root restriction.
- One browser can hold several sessions (one cookie per folder: `ark_s_<folder_id_prefix>`).
  They never combine: in folder `F` only the session rooted closest to `F` counts (hub
  and admin only where no folder session covers `F`). Unlocking a folder again ends the
  session it replaces; `POST /api/v1/logout` ends one or all.
- `POST /api/v1/unlock` `{pin}` unlocks from the home page: the PIN alone picks the
  folder (or the hub). PIN digits are therefore unique across all active PINs; its
  lockout key is separate from the per-folder ones.
- PINs and join-token secrets are also stored encrypted (key in `<data_dir>/secret.key`)
  so the admin can look them up; the hashes still do the checking.

### PIN handling

- 4 to 8 digits, hashed with argon2id. Verify against all non-revoked, non-expired PINs
  of the target folder, then of its ancestors (inheritance) unless the folder has its own PINs.
- Rate limit per `(folder, ip)`: 5 failures -> 5-minute lock, doubling after that.
  Same for admin login.
- Revoking a PIN or token sets `revoked_at` on it **and** on all sessions created from it.

### Sessions

- Random 128-bit id in a signed, `HttpOnly`, `SameSite=Lax` cookie; `Secure` when served over HTTPS.
- Auth extractor: loads session, checks expiry/revocation, returns `Session { id, root_folder, role }`.
- Never trust the frontend: every handler calls `require(scope, action)`.

---

## 6. Routes

### Pages and files

| Route | Behaviour |
| --- | --- |
| `GET /docs` | Swagger UI (when `ARK_DOCS=true`) |
| `GET /api-docs/openapi.json` | OpenAPI 3 spec, generated from code |
| `GET /` and `GET /f/{*path}` | Later: serve the frontend app. Until then `/` redirects to `/docs` |
| `GET /j/{token}` | Validate join token, create session (role from token), set cookie, `302` to `/f/{slug}` |
| `GET /dl/{file_id}` | Stream file with `Range` support, `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` |
| `GET /preview/{file_id}/{kind}` | Thumbnail/poster; requires viewer-level access to the file's folder |
| `GET /healthz` | `200 ok` |
| `GET /assets/*` | Embedded frontend assets |

### JSON API (`/api/v1`)

| Method and path | Purpose | Min role |
| --- | --- | --- |
| `GET /me` | Current sessions: list of `{folder_slug, role}` plus hub/admin flags | none |
| `POST /hub/unlock` `{pin}` | Hub PIN -> hub session | none |
| `POST /folders/{slug}/unlock` `{pin}` | Folder PIN -> scoped session | none |
| `GET /folders` | Top-level folders | hub |
| `GET /folders/{slug}/items?path=a/b` | List subfolders and current files (uploader: own files) | viewer |
| `POST /folders/{slug}/subfolders` `{path, name}` | Create subfolder | contributor |
| `PATCH /items/{id}` `{name?, move_to?, status_tag?}` | Rename / move / tag | editor |
| `DELETE /items/{id}` | Move to trash | editor |
| `POST /items/{id}/restore` `{version?}` | Restore from trash or older version | editor |
| `GET /files/{id}/versions` | Version list | editor |
| `GET /events?folder={slug}` | SSE stream: `file_added`, `file_updated`, `file_deleted`, `folder_added` | viewer |
| `POST /uploads` ... | tus, see section 7 | uploader |

### Admin API (`/api/v1/admin`, admin session only)

| Method and path | Purpose |
| --- | --- |
| `POST /setup` `{setup_code, password}` | First-run admin password |
| `POST /login` `{password}` | Admin session |
| `GET/POST/PATCH/DELETE /folders` | Top-level folder CRUD, archive, set active folder |
| `GET/POST/PATCH/DELETE /pins` | PIN CRUD incl. hub PIN; revoke ends sessions |
| `POST /tokens` / `DELETE /tokens/{id}` | Join tokens; returns raw token once |
| `GET /qr?url=...&format=svg\|png` | QR for a folder link or join link |
| `GET /sessions` / `DELETE /sessions/{id}` | Active sessions, end one |
| `GET /activity` | Audit log, paginated |
| `GET /storage` | Used/free space per folder |
| `GET /trash` / `DELETE /trash` | List / empty trash |

Error body everywhere: `{"error": "code", "message": "human text"}`.

### Swagger / OpenAPI

- Annotate every handler with `#[utoipa::path(...)]` (method, path, params, request
  body, responses incl. 401/403/404/409/429) and derive `ToSchema` on every request and
  response type. Register them in one `#[derive(OpenApi)]` struct in `openapi.rs`.
- Group endpoints with tags: `auth`, `folders`, `items`, `uploads`, `downloads`,
  `events`, `admin`, `system`.
- Mount with `SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi())`.
- **Auth in Swagger:** declare a `cookie` security scheme (`ark_session`). Because Swagger
  UI is served from the same origin, calling `POST /folders/{slug}/unlock` or
  `POST /admin/login` from Swagger sets the cookie and later calls just work.
  For curl and scripts, also accept `Authorization: Bearer <session_id>`; the unlock and
  login responses return `{ "session_id": ..., "role": ..., "root_folder": ... }`.
- **Uploads in Swagger:** tus endpoints are documented (headers + `application/offset+octet-stream`
  body), and Swagger can send a small file as one PATCH. Large or resumable uploads are
  tested with `scripts/upload_test.sh` (curl) or tus-js-client in a test page.
- SSE (`/events`) can't be exercised in Swagger; test with `curl -N`.
- The OpenAPI JSON is the contract for the frontend: Wole can generate a typed client
  from `/api-docs/openapi.json` when frontend work starts.

---

## 7. Uploads (tus 1.0 core subset)

Implement only what `tus-js-client` needs: **creation**, **HEAD/PATCH resume**, and
**termination**. Advertise `Tus-Resumable: 1.0.0`, `Tus-Version: 1.0.0`,
`Tus-Extension: creation,termination`, `Tus-Max-Size`.

| Request | Behaviour |
| --- | --- |
| `OPTIONS /api/v1/uploads` | tus capability headers |
| `POST /api/v1/uploads` | Headers `Upload-Length`, `Upload-Metadata` (base64 `filename`, `folder`, `path`). Check role and scope, quota, then create `uploads` row and empty `uploads/{id}.part`. Return `201` + `Location: /api/v1/uploads/{id}` |
| `HEAD /api/v1/uploads/{id}` | Return `Upload-Offset`, `Upload-Length` (owner session only) |
| `PATCH /api/v1/uploads/{id}` | `Content-Type: application/offset+octet-stream`, `Upload-Offset` must equal stored offset else `409`. Stream body to file at offset, cap at `ARK_MAX_CHUNK_MB`, update offset, return `204` + new `Upload-Offset` |
| `DELETE /api/v1/uploads/{id}` | Abort and remove `.part` |

On final chunk (`offset == size`):
1. Compute SHA-256 while streaming (keep a running hasher per upload, or hash on finalize).
2. If a current file in the folder has the same hash, drop the `.part` and return the existing file (dedup).
3. If the name exists, insert as next `version` and mark the old row `is_current = 0`.
4. Atomically rename `.part` into the folder's `disk_dir` with a unique `disk_name`.
5. Insert `files` row, queue thumbnail job, emit SSE `file_added`, write audit entry.

Client chunk size: 8 MB (stays under Cloudflare's 100 MB request limit for remote use).

---

## 8. Storage rules

- Root: `ARK_DATA_DIR/files/<folder disk_dir>/...`. `disk_dir` is generated from the folder
  id at creation; user-chosen names live only in the DB.
- `disk_name` = sanitized display name + short suffix for versions
  (`cover__v2.psd`). Strip path separators, control chars, `..`, reserved Windows names.
- Every resolved path is canonicalized and must `starts_with` the files root, else 500 + log.
- Trash: set `deleted_at`; a daily worker hard-deletes files older than 30 days.
- Never serve user files inline as HTML; always `attachment` + `nosniff`.

---

## 9. Discovery and QR

- **mDNS:** register `ark.local` (A record for each LAN IPv4) and service `_http._tcp`
  named "Ark" with `mdns-sd`. Run an IP watcher every 10 s; on change, unregister and
  re-register immediately.
- **QR:** encode `http://ark.local/f/{slug}` (folder link) or `http://ark.local/j/{token}`
  (join link). Medium error correction. Never encode an IP.
- **Local DNS (milestone 3):** `hickory-server` on UDP/TCP 53 answering `ark.local` and
  `ark` with the current IP (TTL 30 s) and forwarding everything else to the upstream
  resolver. The router's DHCP must hand out the host's IP as DNS; needs admin rights for port 53.

---

## 10. Milestones and acceptance checks

### M1 — Core (target 27 Oct)
- [ ] Project skeleton, config, tracing, SQLite + migrations
- [ ] OpenAPI + Swagger UI at `/docs`, cookie and bearer auth schemes
- [ ] Admin setup + login, create top-level folders
- [ ] Folder PINs with roles, unlock endpoint, signed sessions, scope enforcement
- [ ] List items, create subfolders
- [ ] tus upload (create, HEAD, PATCH, finalize) and `/dl` with Range
- **Check:** every M1 endpoint appears in Swagger and works from it (setup -> login -> create folder -> add PIN -> unlock -> list -> small upload -> download). Then, with `scripts/upload_test.sh` from two machines on the router, upload a 2 GB file each; kill Wi-Fi mid-upload on one, reconnect, it resumes; both files download intact (compare SHA-256).

### M2 — Demo features (target 3 Nov)
- [ ] Join tokens + `/j/{token}`, QR endpoint (SVG/PNG)
- [ ] Hub PIN and home page folder list
- [ ] SSE live updates
- [ ] Image thumbnails worker
- [ ] Versions, trash, restore, status tags
- [ ] Rate limiting, audit log, revoke-ends-sessions
- [ ] mDNS announce + IP watcher
- **Check (via Swagger and curl):** upload-only QR cannot list or download; a `sunday-service` session gets 403 on `/api/v1/folders/youth-camp/items`; 6 wrong PINs lock the device; new photo appears on another phone within 2 s.

### M3 — Hardening (target 6 Nov, submission)
- [ ] Local DNS server, tested on an older Android
- [ ] Load test: 15 concurrent uploads from phones
- [ ] Windows service / Linux systemd unit, auto-start
- [ ] Unit tests for permission matrix and scope checks; path traversal tests

### M4 — After submission (by 28 Nov, if time allows)
- [ ] Video posters and 720p HLS previews (ffmpeg)
- [ ] ZIP download of a selection
- [ ] Cloud sync worker (internet detection, queue, rclone or S3 multipart)
- [ ] Cloudflare Tunnel setup endpoint

---

## 11. Dev workflow

```bash
# run in dev (port 8080, no admin rights needed)
ARK_BIND=0.0.0.0:8080 ARK_DATA_DIR=./dev-data cargo run

# migrations
cargo sqlx migrate run --database-url sqlite://dev-data/ark.db

# API docs: open http://localhost:8080/docs

# large resumable upload test (tus via curl): create, then PATCH in 8 MB chunks,
# then HEAD to confirm the offset; interrupt and rerun to test resume
./scripts/upload_test.sh http://localhost:8080 sunday-service ./big-video.mp4 <session_id>

# watch live events
curl -N -H "Authorization: Bearer <session_id>" \
  "http://localhost:8080/api/v1/events?folder=sunday-service"

# tests
cargo test

# build for the Pi
cross build --release --target aarch64-unknown-linux-gnu
```

Demo host checklist: PC on LAN cable to the router, IP reserved in the router, AP
isolation off, firewall allows Ark on the private network, `http://ark.local` tested on
an iPhone and an older Android.

## 12. Conventions

- Handlers stay thin: parse -> `require(scope, action)` -> service function -> response.
- All timestamps UTC RFC 3339 strings.
- No personal data stored: activity shows PIN/token labels only.
- Every admin action and every delete/restore writes to `audit_log`.
- Every endpoint and type is in the OpenAPI doc; an endpoint missing from `/docs` is not done.
- The OpenAPI spec is the contract the frontend will consume later; when an endpoint
  changes, update its annotation and tell Wole.
