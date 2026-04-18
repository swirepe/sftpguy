# Explorer Command Spec

## Status

This document describes the current standalone explorer command in `cmd/explorer` as implemented in the repository today. It is an implementation spec, not a future-state proposal.

## Purpose

`cmd/explorer` is a small built-in web file browser and uploader for a directory on disk. It is separate from the main admin web UI and separate from the richer admin explorer.

## Source Of Truth

The main code paths behind this command are:

- `cmd/explorer/main.go`
- `cmd/explorer/main_test.go`

## Scope

The command provides:

- directory browsing
- file download
- browser-based uploads, including folder uploads
- a lightweight lock/unlock model based on successful uploads
- public-path exceptions for selected files and directories

It does not provide:

- user accounts
- deletion or rename APIs
- server-side editing
- per-file authorization beyond the simple lock/public model

## Startup And Flags

The command supports these flags:

- `-dir`: root directory to serve, default `./shared`
- `-port`: HTTP port, default `8080`
- `-maxsize`: max upload size in MB, default `1000`
- `-log`: log file path, default `explorer.log`
- `-header`: optional HTML fragment injected at the top of every page
- `-footer`: optional HTML fragment injected at the bottom of every page
- `-src`: prints the command source and exits

Startup behavior:

- resolves the root directory to an absolute path
- creates the root directory if missing
- writes logs to both stdout and the configured log file
- starts a plain `http.ListenAndServe` server on the configured port

## Request Model

### Method handling

- `GET` and `HEAD` serve either a directory view or a file download
- `POST` uploads into the addressed directory
- other methods return `405`

### Path handling

- URL paths are cleaned with `filepath.Clean`
- requests are rejected if the resolved path escapes the configured root
- a missing path returns `404`

## Security Headers And Origin Checks

Every request gets:

- `Content-Security-Policy` with a per-request nonce for scripts
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`

Cross-origin protection is intentionally narrow:

- the command checks `Sec-Fetch-Site` and `Referer`
- if a request appears cross-origin and targets a non-HTML path with an extension, it returns `403`
- this mainly protects direct linked downloads and assets, not same-origin browsing

## Lock And Public Access Model

### Lock cookie

- The unlock state is stored in the `explorer_unlocked=true` cookie.
- Locked visitors can browse directory pages.
- Locked visitors cannot download non-public files.
- A blocked file download redirects back to the parent directory with `?error=locked&wanted=<filename>`.

### Public paths

The command treats these as always public:

- anything under `<root>/public`
- `robots.txt` at the root

Public files remain downloadable even when the visitor is locked.

### Unlocking

- A successful upload sets the unlock cookie.
- The unlock cookie lasts 30 days.
- The cookie is `HttpOnly` and `SameSite=Strict`.

## Directory Listing UX

### Rendering

- Directory pages are server-rendered HTML.
- Responses send `Cache-Control: no-store`.
- A CSRF token is generated or reused for the page and sent back in a cookie.

### Page features

The directory view includes:

- breadcrumbs from root to the current directory
- an optional parent link
- sortable columns for name, size, and modified time
- separate directory and file rows, with directories always sorted first
- highlighting of public entries
- upload controls including drag-and-drop and folder upload
- optional injected header and footer fragments

### Hidden directories

Listings omit these Synology-style service directories:

- `#recycle`
- `@eaDir`

### HEAD behavior

- `HEAD` on a directory produces the same headers as `GET`, including `Content-Length`
- the response body is omitted

## File Download Behavior

- Files are served as attachments using a UTF-8 `Content-Disposition` filename
- successful reads are logged
- non-public file downloads are blocked until unlocked

## Upload Model

### Preconditions

Uploads require:

- the target path to already exist
- the target path to be a directory
- a valid multipart body
- either:
- a valid `X-CSRF-Token` header that matches the CSRF cookie
- or the first multipart part must be `csrf_token` and match the CSRF cookie

### Size enforcement

- If `Content-Length` is known and exceeds the configured limit, the server returns `413` before reading the body.
- The request body is also wrapped with `http.MaxBytesReader` for streaming enforcement.

### Accepted upload shapes

- regular file uploads
- folder uploads via browser-supplied nested filenames such as `webkitdirectory`

### Collision handling

- top-level file collisions are written as `name (N).ext`
- top-level uploaded folders are created with unique names like `folder (N)` when necessary
- nested files inside a remapped uploaded folder follow the folder's chosen final name

### Atomicity And Cleanup

- The upload handler streams parts one by one.
- Multipart parts without filenames are skipped.
- If any later part fails after earlier files or directories were created, the handler removes the files and top-level created directories from that upload attempt.
- If zero files were successfully saved, the request is rejected with `400`.

## CSRF Model

- The CSRF token lives in the `explorer_csrf` cookie.
- The token is 32 random bytes hex-encoded to 64 characters.
- The upload page renders the token into a hidden field for same-origin JavaScript to read.
- The browser upload script sends the token in an `X-CSRF-Token` request header and also includes it as a multipart `csrf_token` field.
- If XHR upload fails before the request completes, picker-based uploads fall back to a standard form submit.
- The CSRF cookie is `HttpOnly` and `SameSite=Strict`.

## Filesystem Semantics

- The command creates parent directories as needed during upload.
- Uploaded files are written directly into the served root tree.
- For top-level single-file uploads, the handler uses exclusive create semantics and collision suffixes.
- For nested folder uploads, files overwrite within the unique remapped top-level folder created for that upload.

## Logging

The command logs:

- each incoming request with client IP, method, path, and query
- successful reads
- successful writes
- upload rejections such as bad target, oversized payload, missing CSRF token, or malformed multipart data

Client IP comes from:

- `X-Forwarded-For` first, when present
- otherwise the remote socket address

## Current Constraints And Quirks

- Browsing a directory does not require unlock; only non-public file download does.
- Unlocking is not identity-based. Any successful upload grants a browser cookie with download access.
- Cross-origin protection is heuristic and path-extension based rather than a full auth model.
- Header-based CSRF validation happens before multipart streaming starts.
- The form-submit fallback still expects `csrf_token` to be the first multipart part.
- The command is intentionally simple and does not share the SFTP server's ownership, moderation, or contributor logic.
