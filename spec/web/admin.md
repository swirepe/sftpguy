# Admin Web Spec

## Status

This document describes the current built-in admin web surface as implemented in the repository today. It is an implementation spec, not a future-state proposal.

## Purpose

The admin web surface gives operators a browser-based control plane for:

- archive health and summary metrics
- user and file inspection
- audit and event review
- auth-attempt triage
- session and upload review
- user-hash and IP banning
- maintenance and bad-file workflows
- self-test execution
- support-file editing (`whitelist.txt`, `blacklist.txt`, `admin_keys.txt`, `bad_files.txt`)
- one-time login URL generation
- a richer browser-style admin explorer
- live runtime charts and optional Prometheus metrics

## Source Of Truth

The main code paths behind this surface are:

- `internal/adminhttp/server.go`
- `internal/adminhttp/core.go`
- `internal/adminhttp/statsviz.go`
- `admin_http_server.go`
- `admin_http_handlers_core.go`
- `admin_http_handlers_activity.go`
- `admin_http_handlers_insights.go`
- `admin_http_handlers_maintenance.go`
- `admin_http_handlers_iplists.go`
- `admin_http_handlers_adminkeys.go`
- `admin_http_handlers_login.go`
- `admin_http_handlers_selftest.go`
- `admin_http_handlers_explorer.go`
- `admin_ui/index.html`
- `admin_ui/admin.js`
- `admin_ui/admin.css`
- `internal/adminexplorer/explorer.go`

## Entry Points

### Top-level routes

- `/` redirects to `/admin`.
- `/admin` serves the main admin shell UI.
- `/admin/explorer/` serves the dedicated admin explorer.
- `/admin/stats/` serves a statsviz dashboard.
- `/admin/one-time-login?token=...` exchanges a single-use token for an auth cookie and redirects to `/admin`.
- The Prometheus path is optional and is registered separately when metrics are enabled, normally `/metrics`.

### Static assets

- `/admin/static/admin.css`
- `/admin/static/admin.js`

## Access And Authentication

### Enablement

- The surface exists when `-admin.http` is set.
- Auth is optional. If `-admin.http.token` or `-admin.http.token.file` is configured, admin routes require auth.
- If no admin token is configured, the entire admin surface is unauthenticated.

### Auth mechanisms

- Bearer token in the `Authorization` header.
- Auth cookie using the configured token cookie name, default `sftpguy_admin_token`.

### Auth coverage

When admin token auth is enabled, the same auth wrapper protects:

- `/admin`
- `/admin/explorer/...`
- `/admin/stats/...`
- `/admin/api/...`
- the optional Prometheus metrics route

### One-time login flow

- `POST /admin/api/one-time-login` generates a single-use login URL plus a QR-code data URL.
- `GET /admin/one-time-login?token=...` consumes that token, sets the admin auth cookie on `/admin`, and redirects to `/admin`.
- One-time login tokens are in-memory only.
- Token TTL is 24 hours.
- Tokens are single-use.
- Startup may also log a one-time login URL if token auth is enabled and token generation is available.

### Main UI token UX

- The browser UI keeps the bearer token in `localStorage` under `sftpguy_admin_token`.
- On a `401`, the JS prompts for a token and retries the request.
- There is no dedicated login page in the main shell.

### Security notes

- There is no role split inside the admin web surface. A successful admin session can use every admin capability.
- The one-time-login cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` only when the request is over TLS.

## Main Admin Shell

### General UI structure

The main UI at `/admin` is a single-page shell with:

- a header with links to Explorer and Stats
- a live status line showing archive/version/ports/uptime/range
- global quick actions
- tabbed content panes
- an actor drawer
- a session timeline drawer
- toast notifications and local action history

### Global controls

The shell exposes:

- `Refresh All`
- time-range selection
- rows-per-page selection
- auto-refresh with selectable interval
- `Export Users CSV`
- `Export Audit CSV`
- quick owner actions: ban, unban, open actor
- quick IP actions: ban, open actor

### Supported ranges

The range selector and most time-windowed APIs support:

- `15m`
- `1h`
- `6h`
- `12h`
- `24h`
- `48h`
- `7d`
- `14d`
- `30d`
- `all`

### Keyboard shortcuts

Main shell shortcuts:

- `Alt+1` through `Alt+]` switch tabs
- `Shift+R` refreshes all data
- `Shift+L` toggles live event polling in the Logs tab
- `Esc` closes the actor and session drawers

### Client-side persistence

The shell persists:

- bearer token in `localStorage`
- selected time range in `localStorage` as `sftpguy_admin_range`
- table page size in `localStorage` as `sftpguy_admin_page_size`

The shell does not persist:

- generated one-time login URLs across reloads

### Deep links

Boot query params currently supported by the shell:

- `tab`
- `owner`
- `q`

`?owner=...` deep-links into the Files tab and runs an owner-specific file search.

## Main Shell Capabilities By Tab

### Summary

Summary combines:

- `/admin/api/summary`
- `/admin/api/insights`
- `/admin/api/uploads/recent?limit=12`

It shows:

- archive identity and uptime
- total users, contributors, files, directories, stored bytes
- contributor threshold
- recent activity KPIs
- top events
- top users
- top IPs with direct ban action
- quick recent uploads
- crash watch based on parsed panic entries from the process log

### Users

Users supports:

- search by hash substring
- sortable table views
- open actor drawer
- ban
- unban
- purge

User detail data comes from `/admin/api/users/{hashOrPrefix}` and includes:

- user stats
- tracked files
- recent events

User actions are:

- `POST /admin/api/users/{hashOrPrefix}/ban`
- `POST /admin/api/users/{hashOrPrefix}/unban`
- `POST /admin/api/users/{hashOrPrefix}/purge`

User prefix resolution is supported. Ambiguous prefixes return `409`.

### Files

Files supports two modes:

- directory browsing via `/admin/api/files?path=...`
- file search via `/admin/api/files/search`

Capabilities include:

- opening a directory by relative path
- moving up one directory
- searching by file path text
- searching by exact owner hash
- opening matching directories directly in the tab
- linking each file or directory to the richer Explorer
- marking a file as bad

Returned rows include:

- name/path
- owner
- download count
- size
- file-vs-directory

Both browse and search paths are normalized and reject traversal outside the upload root.

### Audit

Audit uses `/admin/api/audit` and provides:

- time-windowed event review from the SQLite log
- filter by user, event, path, meta, IP, or session
- sortable table view
- CSV export from currently loaded rows

### Logs

Logs is a combined operational view:

- event log rows from `/admin/api/events`
- panic-oriented parsed process-log rows from `/admin/api/system-log/parsed?panic_only=1`

Capabilities include:

- filtering
- browsing older event pages via `before_id`
- jumping back to newest
- live polling of `/admin/api/events/stream`
- direct IP ban action from event rows

The event section is sourced from the SQLite log table. The panic section is sourced from the process log file on disk.

### Auth

Auth uses `/admin/api/auth-attempts` and shows:

- recent auth attempts
- aggregated username/password combos
- last-seen IP for a combo
- linked session and generated user hash when present
- copy actions for `username:password`

This is explicitly geared toward credential-stuffing / password-attempt review.

### Sessions

Sessions uses `/admin/api/sessions` and exposes:

- session aggregation by `user_session`
- start/end time
- duration
- total event count
- upload count
- download count
- denied count
- open-vs-closed state

Clicking a session opens the session timeline drawer, backed by `/admin/api/sessions/{sessionOrPrefix}`.

### Uploads

Uploads uses `/admin/api/uploads/recent` and shows:

- recent uploads
- uploader
- IP
- path
- delta bytes
- current size
- session

### Banned

Banned uses `/admin/api/banned` and shows:

- shadow-banned pubkey hashes
- exact-IP blacklist bans

Capabilities include:

- ban a new IP
- unban a user hash
- unban an exact IP

The dedicated IP-ban workflow only manages exact IP entries. CIDR and range management is handled through the IP-list editor instead.

### Self Test

Self Test uses:

- `GET /admin/api/self-test`
- `POST /admin/api/self-test/run`

Capabilities include:

- launch the integration self-test suite
- poll while it is running
- inspect suite summary
- inspect per-step pass/fail/skip results
- inspect captured test-user action timelines grouped by user and session

Concurrent runs are blocked. Starting a new run while one is active returns `409`.

### Login URLs

Login URLs is a client-side list of results from `POST /admin/api/one-time-login`.

Capabilities include:

- generate one-time login URLs
- display creation time
- open the generated link
- copy the generated link
- display the QR code

The shell keeps at most 30 generated URLs in memory. The server does not expose a list endpoint for previously generated URLs.

### IP Lists

IP Lists combines:

- `GET /admin/api/ip-lists`
- `POST /admin/api/ip-lists/{whitelist|blacklist}`
- `POST /admin/api/ip-lists/test`
- `GET /admin/api/admin-keys`
- `POST /admin/api/admin-keys`

Capabilities include:

- edit `whitelist.txt`
- edit `blacklist.txt`
- edit `admin_keys.txt`
- view path, entry count, and invalid-line count for each
- test an IP against current whitelist/blacklist state

Current effective-ban semantics:

- whitelist match overrides blacklist match
- response reports `whitelist`, `blacklist`, and `effective_banned`

Admin key lines currently accept:

- normal `authorized_keys` lines
- raw 64-character SHA-256 public-key hashes
- optional trailing `# ...` comments

### Maintenance

Maintenance combines:

- `GET /admin/api/maintenance`
- `POST /admin/api/maintenance/run`
- `GET /admin/api/maintenance/logs`
- `GET/POST /admin/api/maintenance/bad-files`
- `POST /admin/api/maintenance/mark-bad`

Capabilities include:

- view current maintenance run state
- run a maintenance pass manually
- inspect the last maintenance result
- inspect parsed maintenance log entries from the process log
- edit `bad_files.txt`
- mark an existing uploaded file as bad by hashing it and appending it to `bad_files.txt`

The last-run summary exposes these sub-operations:

- `clean_deleted`
- `reconcile_orphans`
- `purge_sshdbot`
- `purge_blacklisted_files`

Notable maintenance behaviors:

- only one run can execute at a time
- manual admin runs are synchronous from the HTTP caller's perspective
- bad-file saves do not reject invalid lines; invalid lines are stored and reported back
- `mark-bad` rejects directories
- `mark-bad` rejects zero-length files

## Actor Drawer

The actor drawer is driven by `GET /admin/api/actor`.

Capabilities:

- open by user hash or IP
- show ban state
- show direct actions relevant to actor type
- show recent uploads
- show recent sessions
- show recent events
- for users, show user stats such as seen count, upload/download counts, last login, and last address

User actor lookups support hash-prefix resolution. Ambiguous prefixes return `409`.

## Session Timeline Drawer

The session drawer is driven by `GET /admin/api/sessions/{sessionOrPrefix}` and shows:

- resolved session ID
- user
- IP
- start/end time
- a visual event timeline

Session lookups support prefix resolution. Ambiguous prefixes return `409`.

## Admin Explorer

### Route and purpose

The explorer lives under `/admin/explorer/` and is a richer file browser than the Files tab.

It provides:

- full directory browsing
- file download
- multi-view browsing
- upload workflows
- previews for multiple content types
- owner lookup and owner profile embedding
- admin moderation actions directly in the preview pane

### View modes

Current built-in views:

- table
- tiles
- tree
- classic

Explorer preference cookies currently track:

- theme
- view
- hue
- preview-pane open/closed

### Directory browsing features

The explorer exposes:

- breadcrumbs
- parent navigation
- current directory stats
- sorting by name, downloads, size, or modified time
- client-side filtering
- keyboard navigation
- mobile preview sheet behavior

Keyboard affordances inside explorer include:

- `/` or `?` to focus filter
- arrow/navigation support
- `Enter` and `Space` actions on the current selection
- `Esc` to clear selection / close preview

### Uploads

Explorer uploads support:

- multiple file upload
- folder upload via `webkitdirectory`
- CSRF validation
- max-size enforcement through `MaxUploadBytes`
- collision avoidance by choosing unique file and folder names
- redirect back to the current directory after upload with `new=...` hints for newly created top-level names

### Preview system

The preview pane is backed by `?preview=true` JSON responses and supports:

- directory summaries
- images with thumbnails and dimensions
- text previews and text stats
- videos, including native and Video.js-backed playback
- archive listing previews
- PDF previews with page count
- STL previews with a 3-D viewer and triangle count
- generic file metadata

Preview payloads also include:

- relative path
- owner
- download count
- owner-files URL
- owner-details URL

### Owner details in preview

When owner details are available, the preview pane loads `/admin/api/users/{owner}` and renders:

- owner status
- stats
- tracked files
- recent events

### Admin actions from explorer

Explorer preview actions currently include:

- delete path via `POST /admin/api/explorer/delete`
- ban owner via `POST /admin/api/explorer/ban-owner`
- mark file bad via `POST /admin/api/maintenance/mark-bad`
- jump to owner-file view

Delete removes the on-disk path and then deletes tracked metadata for that path.

### File serving behavior

- Directory paths render explorer HTML.
- File paths are served as attachments via `http.ServeFile`.
- Thumbnail generation is available via `?thumb=1`.

### Explorer security behavior

- Relative-path normalization prevents traversal outside the upload root.
- Uploads require a CSRF token and cookie pair.
- Non-HTML direct access from obviously cross-site contexts is rejected when `Sec-Fetch-Site` or `Referer` indicate the request is not same-origin.

### Important current quirk

The explorer still contains an "unlock" concept and sets an `explorer_unlocked` cookie on upload, but `isUnlocked()` currently always returns `true`. In practice this means:

- downloads are always available inside the admin explorer
- thumbnail access is always available
- media preview URLs are always emitted
- the "uploading unlocks downloads" copy is stale relative to current behavior

## Stats And Metrics

### `/admin/stats/`

The statsviz page is a separate authenticated page with a WebSocket feed at `/admin/stats/ws`.

Current chart groups include:

- archive totals
- archive footprint
- access control counts
- SSH activity
- handshake and auth totals
- session mix and average duration
- SFTP requests, outcomes, browse ops, mutations, and latency
- transfer counts and bytes
- permission denial breakdowns
- admin HTTP request and latency metrics

### Prometheus metrics

When Prometheus is enabled, the configured metrics route is mounted on the same admin HTTP server and protected by the same auth rules.

## HTTP API Inventory

| Route | Methods | Purpose |
| --- | --- | --- |
| `/admin` | `GET` | Main admin shell HTML. |
| `/admin/static/admin.css` | `GET` | Main shell stylesheet. |
| `/admin/static/admin.js` | `GET` | Main shell JS. |
| `/admin/explorer` | `GET` | Redirects to slash form. |
| `/admin/explorer/` and descendants | `GET`, `POST` | Admin explorer browsing, previews, downloads, uploads, and static asset/thumbnail sub-modes. |
| `/admin/stats` | `GET` | Redirects to slash form. |
| `/admin/stats/` | `GET` | statsviz dashboard HTML. |
| `/admin/stats/ws` | `GET` | statsviz WebSocket feed. |
| `/admin/api/health` | `GET` | Lightweight health/version payload. |
| `/admin/api/summary` | `GET` | Archive summary payload. |
| `/admin/api/users` | `GET` | User list filtered by `q`. |
| `/admin/api/users/{hashOrPrefix}` | `GET` | User detail payload. |
| `/admin/api/users/{hashOrPrefix}/{ban|unban|purge}` | `POST` | User admin actions. |
| `/admin/api/files` | `GET` | Directory listing by relative `path`. |
| `/admin/api/files/search` | `GET` | File search by `q` and/or exact `owner`. |
| `/admin/api/audit` | `GET` | Time-windowed audit rows. |
| `/admin/api/auth-attempts` | `GET` | Recent auth attempts and aggregated username/password combos. |
| `/admin/api/events` | `GET` | Event log rows with pagination. |
| `/admin/api/events/stream` | `GET` | Incremental event polling by `since_id`. |
| `/admin/api/insights` | `GET` | High-level KPIs, top lists, suspicious IPs, and panic summary. |
| `/admin/api/sessions` | `GET` | Session aggregates. |
| `/admin/api/sessions/{sessionOrPrefix}` | `GET` | Session timeline detail. |
| `/admin/api/uploads/recent` | `GET` | Recent uploads. |
| `/admin/api/actor` | `GET` | Combined actor drawer payload for user or IP. |
| `/admin/api/system-log` | `GET` | Raw tailed process-log lines. |
| `/admin/api/system-log/parsed` | `GET` | Structured process-log parsing, optionally panic-only. |
| `/admin/api/banned` | `GET` | Current shadow-banned hashes and exact-IP blacklist bans. |
| `/admin/api/banned/ip` | `POST` | Add an exact-IP blacklist ban. |
| `/admin/api/banned/ip/{ip}` | `DELETE` | Remove an exact-IP blacklist ban. |
| `/admin/api/maintenance` | `GET` | Current maintenance status and last run snapshot. |
| `/admin/api/maintenance/run` | `POST` | Run a maintenance pass. |
| `/admin/api/maintenance/logs` | `GET` | Parsed maintenance log entries from the process log. |
| `/admin/api/maintenance/bad-files` | `GET`, `POST` | Read or overwrite `bad_files.txt`. |
| `/admin/api/maintenance/mark-bad` | `POST` | Hash an uploaded file and add it to `bad_files.txt`. |
| `/admin/api/ip-lists` | `GET` | Read whitelist and blacklist editor payloads. |
| `/admin/api/ip-lists/{whitelist|blacklist}` | `POST` | Overwrite one IP list file and reload it. |
| `/admin/api/ip-lists/test` | `POST` | Test effective allow/ban behavior for an IP. |
| `/admin/api/admin-keys` | `GET`, `POST` | Read or overwrite `admin_keys.txt` and reload it. |
| `/admin/api/self-test` | `GET` | Current self-test state. |
| `/admin/api/self-test/run` | `POST` | Start a self-test run. |
| `/admin/api/explorer/delete` | `POST` | Delete a file or directory from the explorer. |
| `/admin/api/explorer/ban-owner` | `POST` | Ban the tracked owner of an explorer path. |
| `/admin/api/one-time-login` | `POST` | Generate a one-time login URL and QR code. |
| `/admin/one-time-login` | `GET` | Exchange a one-time token for the auth cookie. |

## Data Sources And Persistence

### SQLite-backed

The main shell reads heavily from SQLite tables for:

- users
- files
- shadow bans
- audit/event log rows

### Process-log-backed

Insights, maintenance-log parsing, and parsed panic views read from the configured log file on disk.

### Support-file-backed

Operator-editable files currently surfaced by the admin web:

- `whitelist.txt`
- `blacklist.txt`
- `admin_keys.txt`
- `bad_files.txt`

HTTP save endpoints overwrite the whole file and immediately reload the corresponding in-memory structure when available.

### Client/browser state

- main shell token/range/page-size in `localStorage`
- explorer theme/view/hue/preview and CSRF cookies
- login URL history in page memory only

## Current Constraints And Quirks

- The main shell is intentionally simple and handwritten; there is no frontend framework or typed API client.
- Several tabs fetch large result sets eagerly rather than doing infinite scroll or server-side paging in the UI.
- User and session detail routes support prefixes, which is convenient but can fail with `409` when the prefix is ambiguous.
- The raw system-log endpoint exists but the shipped shell does not currently surface it directly; the Logs tab uses the parsed panic endpoint instead.
- The Banned tab only exposes exact-IP add/remove actions. CIDR or range editing is done through the blacklist editor.
- One-time login URLs are not queryable after generation; only the token consumer route exists server-side.
- Support-file editors save content even when some lines are invalid; invalid lines are reported back instead of blocking the write.
- The explorer "unlock downloads" concept is currently dead code from a behavior standpoint because the admin explorer is always effectively unlocked.

