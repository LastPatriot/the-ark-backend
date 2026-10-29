# Ark Frontend Guide

How the frontend talks to the Ark backend. The contract is the OpenAPI spec at
`/api-docs/openapi.json` (browse it at `/docs`); this guide covers what the spec
can't say: flows, constraints of the venue network, and gotchas.

Backend owner: Opeyemi. If something here disagrees with `/docs`, `/docs` wins. Tell
Opeyemi either way.

---

## 1. Ground rules

1. **Same origin, no CORS.** The built app is served by the backend itself (see §11),
   so every request is same-origin and cookies just work. In development, proxy the
   backend through your dev server (§2); don't call `http://localhost:8080` directly
   from the page.
2. **No internet at the venue.** Phones join the venue Wi-Fi, which may have no
   internet. Bundle everything: fonts, icons, scripts. No CDNs, Google Fonts, analytics
   or remote images.
3. **Plain HTTP, not a secure context.** Phones open `http://ark.local`. Browsers treat
   that as insecure, so these are **unavailable**: service workers / PWA install,
   `crypto.randomUUID()`, `navigator.clipboard`, `getUserMedia`, Web Share (mostly).
   `<input type="file" accept="image/*,video/*" multiple>` works fine, and so does
   picking from the camera roll.
4. **Old phones.** Expect older Android WebViews and iOS Safari 14+. Set the build target
   accordingly (Vite: `build.target: 'es2018'`, or `@vitejs/plugin-legacy`).
5. **Never trust the UI for access.** Hide buttons the role can't use (§5), but the
   backend checks every call anyway.
6. **QR codes and links use `ark.local`, never an IP.** Build links from
   `window.location.origin` so they keep working through the tunnel too.

## 2. Local setup

```bash
# backend (in the repo root)
ARK_BIND=0.0.0.0:8080 ARK_DATA_DIR=./dev-data cargo run
# first run prints "Ark admin setup code: NNNNNN"
```

Vite proxy so the app and API share an origin (cookies, SSE and uploads all work):

```ts
// vite.config.ts
export default defineConfig({
  server: {
    proxy: {
      '/api': 'http://localhost:8080',
      '/dl': 'http://localhost:8080',
      '/preview': 'http://localhost:8080',
      '/zip': 'http://localhost:8080',
      '/j': 'http://localhost:8080',
    },
  },
  build: { target: 'es2018' },
})
```

Typed client from the spec, for example:

```bash
npx openapi-typescript http://localhost:8080/api-docs/openapi.json -o src/api/schema.d.ts
```

Regenerate whenever Opeyemi says an endpoint changed.

## 3. Conventions

- JSON everywhere except uploads and downloads. Ids are UUID strings. Sizes are bytes.
  Times are UTC RFC 3339 with milliseconds (`2026-10-26T13:18:16.672Z`).
- **Errors** always look like `{"error": "code", "message": "human text"}`. Branch on
  `error` and show `message` (it's written for users) or your own copy.
- Two kinds of "path":
  - **slug**: the top-level folder (`sunday-service`), in URLs like
    `/api/v1/folders/{slug}/...`.
  - **path**: the subfolder path below it (`day-1/photos`), as `?path=` or a body field.
    An empty path is the top level.

| Status | Meaning for the UI |
| --- | --- |
| 400 | Bad input; see `error` |
| 401 `unauthorized` | No valid session for this: show the PIN pad (§4) |
| 401 `invalid_pin` / `invalid_password` | Wrong PIN or password; let them retry |
| 403 `forbidden` | Has a session, but not for this folder or action. Offer a PIN for this folder |
| 404 | Doesn't exist (or a link expired) |
| 409 | Conflict; see `error` (`name_taken`, `slug_taken`, `not_empty`, ...) |
| 413 | `quota_exceeded`, `too_large`, `chunk_too_large` |
| 429 `too_many_attempts` | Locked out. `Retry-After` header = seconds. Show a countdown |
| 503 `setup_required` | Fresh install: show the admin setup screen (§9) |

Full list of codes in §12.

## 4. Sessions and unlocking

- Auth is **HttpOnly cookies set by the backend**; JS never sees or stores tokens. One
  browser can hold several sessions at once (one per unlocked folder, plus hub and
  admin). Default lifetime is 12 hours.
- `GET /api/v1/me` lists what this browser has unlocked:
  `{ sessions: [{folder_id, folder_slug, path, role}], hub, admin }`. Use it to pick
  the role for the folder on screen, and to show "unlocked" state on the home page.
- A session covers its folder **and everything below it**, never parents or siblings.
- **Sessions never combine.** In any folder, exactly one session decides what the user
  can do: the one unlocked closest to that folder (hub/admin only where no folder
  session covers it). Example: viewer PIN on `sunday-service`, then uploader QR on
  `day-1` -> `day-1` is upload-only, the rest of `sunday-service` is still view-only.
  Show the role of the session that applies (the `/me` entry whose folder is the
  current folder or its nearest ancestor).
- **Unlocking a folder again replaces its session.** Entering a contributor PIN where
  the browser has a viewer session for that same folder ends the viewer one.

**Folder page flow** (`/f/{slug}/{path...}`):

```
GET /api/v1/folders/{slug}/items?path={path}
  200 -> render
  401 -> PIN pad -> POST /api/v1/folders/{slug}/unlock {"pin": "2468", "path": "{path}"}
           200 -> refetch items     401 invalid_pin -> "Wrong PIN"
           429 -> countdown from Retry-After   400 pin_required -> needs a PIN
  403 -> "You don't have access here" + PIN pad (a PIN for this folder may exist)
  404 -> "Folder not found"
```

- **Open folders** need no PIN: `POST .../unlock` with `{}` (or `{"path": ...}`) creates
  a session. If you get `400 pin_required`, the folder isn't open.
- PINs are 4–8 digits (`400 invalid_pin_format` otherwise). Use `inputmode="numeric"`.
- **Lockout:** 5 wrong PINs lock that device out for 5 minutes, doubling after that.
  Don't auto-retry PIN calls.
- **Join links / QR codes** (`/j/{token}`) are handled entirely by the backend: it sets
  the cookie and redirects (302) to `/f/{slug}/{path}`. The app just loads that route as
  usual. An expired or used-up link returns a JSON 404; we can make that a nicer page later.
- **Lock / switch role:** `POST /api/v1/logout` ends sessions and clears their cookies.
  Send exactly one of:
  - `{"folder_id": "..."}`: ends the session that applies in that folder (pass the
    current folder's `id` from the items response). The next items call returns 401
    (PIN pad) or falls back to a session on a parent folder.
  - `{"role": "hub"}` / `{"role": "admin"}`: ends that session.
  - `{"all": true}`: ends everything on this browser.

  Returns `{ended: n}` (`0` is fine). Afterwards refetch `/me` and the current folder,
  and close and reopen the `EventSource`: the server closes streams of ended sessions
  within a few seconds. Resumable uploads belong to the session that started them, so
  warn before locking while uploads are in progress.

## 5. Roles: what to show

| UI | viewer | uploader | guest | contributor | editor | hub | admin |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Browse folder, see previews | yes | **own uploads only** | yes | yes | yes | yes | yes |
| Download / play / ZIP | yes | **no** | yes | yes | yes | yes | yes |
| Upload button | no | yes | yes | yes | yes | yes | yes |
| New subfolder | no | no | **no** | yes | yes | yes | yes |
| Rename, move, tag, delete, restore, versions | no | no | no | no | yes | yes | yes |
| Home page folder list | no | no | no | no | no | yes | yes |
| Admin screens | no | no | no | no | no | no | yes |

Uploader is the "upload-only QR" role (e.g. a poster at the entrance): an upload page
that shows what *this phone* sent, nothing else.

Guest is the "see everything, download, add yours" role: nothing can be renamed,
deleted or created, not even the guest's own uploads. It is the usual event QR.

Join links can be `viewer`, `uploader`, `guest` or `contributor`. Like PINs, a link
covers its folder and every subfolder below it.

## 6. Browsing

`GET /api/v1/folders/{slug}/items?path=` returns:

```jsonc
{
  "folder":     { "id", "slug", "name", "path", "created_at" },
  "subfolders": [{ "id", "slug", "name", "path", "created_at" }],
  "files": [{
    "id", "name", "size", "mime", "version",
    "status_tag",      // null | "draft" | "approved" | "final"
    "uploaded_by",     // PIN/QR label, e.g. "Photographers" (never a person's name)
    "created_at",
    "previews"         // [] | ["thumb"] | ["poster", "hls"]
  }]
}
```

Files are newest first, current versions only, trash excluded. Subfolders sort by name.
Build child links from `subfolder.path`.

**Previews** (all need the same access as listing):

| `previews` contains | Use |
| --- | --- |
| `thumb` | `<img src="/preview/{id}/thumb">`: JPEG, longest edge 480 px (images) |
| `poster` | `<img src="/preview/{id}/poster">`: JPEG frame, 480 px wide (videos) |
| `hls` | `/preview/{id}/hls/index.m3u8`: 720p stream (videos) |

Previews are generated after upload, so a new file starts with `previews: []`.
Show a placeholder by `mime` and wait for the `file_updated` event (§8). HEIC photos from
iPhones currently get **no thumbnail**; show a generic image icon.

**Video playback:** if `hls` is ready, play it (Safari/iOS natively via `<video src=...m3u8>`;
elsewhere with `hls.js`, bundled locally). Otherwise `<video src="/dl/{id}">` works too
(Range is supported, so seeking works), but the original may be large or a codec the phone can't play.

## 7. Uploading (tus)

Use **tus-js-client** (bundle it). Uploads resume after Wi-Fi drops, and after a page reload too.

```ts
import * as tus from 'tus-js-client'

function uploadFile(file: File, folderSlug: string, path: string) {
  const upload = new tus.Upload(file, {
    endpoint: '/api/v1/uploads',
    chunkSize: 8 * 1024 * 1024,            // must stay <= 16 MB (server limit), 8 MB suits Cloudflare
    retryDelays: [0, 1000, 3000, 5000, 10000, 20000],
    metadata: { filename: file.name, folder: folderSlug, path },
    removeFingerprintOnSuccess: true,
    onProgress: (sent, total) => setProgress(sent / total),
    onAfterResponse: (_req, res) => {
      const fileId = res.getHeader('Ark-File-Id')   // set on the final chunk
      if (fileId) markDone(file, fileId)
    },
    onError: (err) => showUploadError(err),
  })
  // Resume an interrupted upload of the same file (e.g. after a reload)
  upload.findPreviousUploads().then((previous) => {
    if (previous.length) upload.resumeFromPreviousUpload(previous[0])
    upload.start()
  })
}
```

- `folder` is the **top-level slug**; `path` is the subfolder path ("" for the top).
- Errors: `403` the role can't upload here, `413 quota_exceeded` folder full,
  `413 too_large` over 64 GiB. tus-js-client exposes the response on `err.originalResponse`.
- An upload belongs to the session that started it; if the session has gone, the
  resume 404s and tus-js-client starts again automatically.
- **Same name** as an existing file creates a new version (it replaces the old one in the
  listing). **Identical content** already in the folder isn't stored twice: you get the
  existing file's id back.
- Several files: run 2–3 uploads in parallel, not 50. The Wi-Fi is the bottleneck.

## 8. Live updates (SSE)

```ts
const es = new EventSource(`/api/v1/events?folder=${slug}&path=${encodeURIComponent(path)}`)
for (const type of ['file_added', 'file_updated', 'file_deleted', 'folder_added', 'folder_updated']) {
  es.addEventListener(type, (e) => scheduleRefetch(JSON.parse(e.data)))
}
es.addEventListener('resync', () => refetchAll())   // events were dropped
es.onerror = () => { /* EventSource reconnects by itself; if it keeps failing, GET /me */ }
```

- Event data: `{ type, folder_id, id, name }`. Events cover the folder **and all its
  subfolders**, so check `folder_id` against the folder on screen, or just refetch the listing.
- Debounce refetches (~300 ms); a batch upload fires many events.
- `file_updated` also fires when a thumbnail, poster or HLS stream becomes ready.
- Uploader sessions only get events for their own files.
- The stream closes if the session is revoked; the reconnect then gets 401, so send the
  user back to the PIN pad.

## 9. Editing, trash, ZIP

| Action | Call |
| --- | --- |
| New subfolder | `POST /api/v1/folders/{slug}/subfolders` `{path, name}`; slug comes from the name (`409 slug_taken`) |
| Rename / tag file | `PATCH /api/v1/items/{id}` `{name}` / `{status_tag: "approved"}` (`null` clears) |
| Move file or subfolder | `PATCH /api/v1/items/{id}` `{move_to: "<folder id>"}`; must be inside the session's folder |
| Rename subfolder | `PATCH /api/v1/items/{id}` `{name}`; old links keep working |
| Delete | `DELETE /api/v1/items/{id}`: file goes to trash (30 days); subfolder only if empty (`409 not_empty`) |
| Restore / revert | `POST /api/v1/items/{id}/restore` `{}` from trash, or `{version: 2}` to make v2 current |
| Versions | `GET /api/v1/files/{id}/versions` |

`PATCH /items` returns `{kind: "file", ...}` or `{kind: "folder", ...}`.
Renames and moves apply to all versions of a file.

**ZIP of a selection** (two steps so it downloads with a normal link and progress bar):

```ts
const r = await post('/api/v1/zip', { file_ids: [...], folder_ids: [...] })
window.location.href = r.url      // "/zip/<token>", valid 10 min, same browser only
```

Single files: a plain `<a href="/dl/{id}">`. It always downloads (attachment), with
the original name.

## 10. Admin screens

- **First run:** any API call returns `503 setup_required`. Show "Enter the setup code
  shown on the Ark console + choose a password" -> `POST /api/v1/admin/setup`
  `{setup_code, password (8+ chars)}`. That also logs the admin in.
- **Login:** `POST /api/v1/admin/login` `{password}` (rate limited like PINs).
- **Hub (home page)**: `GET /api/v1/folders` needs a hub or admin session; otherwise
  401/403 -> hub PIN pad -> `POST /api/v1/hub/unlock` `{pin}`.

| Screen | Endpoints |
| --- | --- |
| Folders | `GET/POST /admin/folders`, `PATCH/DELETE /admin/folders/{id}` (delete = archive) |
| PINs | `GET/POST /admin/pins`, `PATCH/DELETE /admin/pins/{id}`; omit `folder_id` + role `hub` for the hub PIN. Revoking signs out its sessions. Each PIN in the list has its digits in `pin`, so the admin can look them up any time (`null` for revoked PINs and ones made before this existed: show "revoke and recreate to see it") |
| QR / join links | `POST /admin/tokens` `{folder_id, role: viewer\|uploader\|guest\|contributor, label, expires_at?, max_uses?}`; `GET /admin/tokens` lists them with their `url` (same `null` rule), so the QR can be shown or reprinted any time; `DELETE /admin/tokens/{id}` |
| QR image | `<img src="/api/v1/admin/qr?url={encoded url}&format=svg">` (or `png` for printing) |
| Sessions | `GET /admin/sessions`, `DELETE /admin/sessions/{handle}` |
| Activity | `GET /admin/activity?limit=50&before={next_before}` |
| Storage | `GET /admin/storage` |
| Trash | `GET /admin/trash`, `DELETE /admin/trash` (empty now) |
| Cloud backup | `GET /admin/sync`, `POST /admin/sync/retry` |
| Remote access | `GET/PUT/DELETE /admin/tunnel`; `PUT {}` = quick tunnel, then show `public_url` |

(All under `/api/v1`.) A folder's shareable link is `http://ark.local/f/{slug}`. Build
the QR from it, or from a join token's `url`.

## 11. Routes and build

The app owns these routes (history API, no hash routing):

| Route | Page |
| --- | --- |
| `/` | Home: hub folder list, or a "scan a QR / enter a folder" landing |
| `/f/{slug}` and `/f/{slug}/{sub/path}` | Folder page |
| `/admin/...` | Admin screens (your choice of sub-routes) |

The backend owns `/api/*`, `/dl/*`, `/preview/*`, `/zip/*`, `/j/*`, `/docs`, `/healthz`.

Build output goes to `web/dist/` with assets under `/assets/`. The backend will embed it
and serve `index.html` for unknown routes (SPA fallback). **That part isn't built on the
backend yet**; until then `/` and `/f/*` redirect to `/docs`. Tell Opeyemi when you
have a first build.

## 12. Error codes

| Status | Codes |
| --- | --- |
| 400 | `invalid_logout`, `invalid_pin_format`, `pin_required`, `invalid_name`, `invalid_slug`, `invalid_role`, `invalid_label`, `invalid_time`, `invalid_move`, `not_a_file`, `password_too_short`, `default_role_required`, `empty_selection`, `too_many_files`, `invalid_url`, `invalid_hostname`; uploads: `missing_upload_length`, `missing_upload_offset`, `missing_filename`, `missing_folder`, `invalid_metadata`, `invalid_header` |
| 401 | `unauthorized`, `invalid_pin`, `invalid_password`, `invalid_setup_code` |
| 403 | `forbidden` |
| 404 | `not_found` |
| 409 | `slug_taken`, `name_taken`, `in_trash`, `not_empty`, `pin_in_use`, `already_set_up`, `offset_mismatch` |
| 412 / 413 / 415 | `tus_version` / `quota_exceeded`, `too_large`, `chunk_too_large` / `content_type` |
| 429 | `too_many_attempts` (+ `Retry-After`) |
| 503 | `setup_required` |
| 500 | `internal` (bug: tell Opeyemi, with the time it happened) |

## 13. Known gaps (ask Opeyemi)

- Editors can't list the trash (only admins can); restore needs the file id.
- No HEIC thumbnails.
- Accented letters are dropped from slugs (`Ọdún` -> `d-n`).
- Serving the built frontend from the backend (§11).
