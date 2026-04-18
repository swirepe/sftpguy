# SFTP Spec

## Status

This document describes the current built-in SFTP service as implemented in the repository today. It is an implementation spec, not a future-state proposal.

## Purpose

The SFTP service is the primary archive surface. It provides:

- anonymous or pseudo-anonymous upload access
- contributor-gated download access
- per-path ownership enforcement
- shadow-ban and IP-ban anti-abuse behavior
- bad-file detection and purge workflows
- optional admin SFTP access as the system owner

## Source Of Truth

The main code paths behind this surface are:

- `sftpguy.go`
- `admin.go`
- `maintenance.go`
- `bad_files.go`
- `iplist.go`
- `adminkeys.go`
- `test_server.go`
- `selftest_integration_test.go`
- `sftp_permissions_test.go`
- `welcome_test.go`
- `sshdbot_test.go`

## Service Model

- The server listens for SSH on `:<port>`, default `:2222`.
- The only supported file-transfer subsystem is SFTP.
- The archive root is the configured upload directory, default `./uploads`.
- Metadata, ownership, counters, and audit history are stored in SQLite.
- The process also runs background maintenance and async bad-upload checks.

## Startup And Initialization

### Host key behavior

- If the configured host key file does not exist, the server generates an Ed25519 private key and writes a matching `.pub` file.
- If `-admin.sftp` is enabled, startup also tries to ensure the server host public key is present in `admin_keys.txt`.

### Store initialization

On startup the store:

- opens the SQLite database in WAL mode
- applies the base schema plus additive migrations
- initializes live-reloading blacklist, whitelist, admin-key, and bad-file lists
- seeds the whitelist with private and loopback ranges when missing
- seeds the bad-file list from the embedded defaults unless an explicit file already exists
- migrates legacy `ip_banned` rows into the file-backed blacklist

### Background work

- An hourly maintenance loop starts automatically.
- An async bad-upload checker runs in the background and is fed by completed uploads.
- Self-test mode shortens shadow-ban delay windows to keep tests fast.

### Optional source bootstrap

- `-src` copies the embedded source tree into the upload directory at startup.
- The generated source snapshot directory is also marked unrestricted for downloads.
- `-src.out` exports the embedded source snapshot to a directory and exits instead of serving.

## Relevant Configuration

The SFTP surface is primarily shaped by these flags and env vars:

- `-port`: SSH listen port
- `-dir`: archive root directory
- `-hostkey`: SSH host key path
- `-db.path`: SQLite database path
- `-banner` and `-banner.stats`: SSH banner source and optional banner stats
- `-noauth`: enables SSH `none` auth
- `-admin.sftp`: enables admin SFTP login
- `-contrib`: bytes required to unlock non-public downloads
- `-unrestricted`: comma-separated files or directories always downloadable
- `-dir.owners_only`: prevents uploads into directories owned by other users
- `-dir.rate`: global mkdir rate limit
- `-dir.max`: maximum tracked directory count
- `-maxsize`: per-file size ceiling, `0` means unlimited
- `-blacklist`, `-whitelist`, `-admin.keys`, `-bad`, `-caid.db`: anti-abuse and moderation support files
- `-test` and `-test.continue`: startup self-test modes

Admin web flags exist alongside the SFTP service but are covered separately in [spec/admin.md](admin.md) and [spec/web/admin.md](web/admin.md).

## Authentication And Identity

### Public-key auth

- Any presented SSH public key is accepted.
- The raw SSH public key bytes are hashed with SHA-256 and used as the stable user identity.
- If `-admin.sftp` is enabled and the key matches either the server host key or an entry in `admin_keys.txt`, the session is marked as admin.

### No-auth mode

- When `-noauth` is enabled, SSH `none` auth is offered.
- The user identity is derived from the remote IP as `anon-auth:<sha256>`.

### Keyboard-interactive auth

- Keyboard-interactive auth is accepted for any username and any entered password.
- The server prompts with a message that says the password is the user's email address.
- The effective identity is `pwd-auth:<sha256(username:password)>`.
- The supplied username and password are logged in the audit log as an auth attempt.

### Effective login types

Sessions are categorized as:

- `pubkey-hash`
- `anon-auth`
- `pwd-auth`
- `admin-sftp`

### Important implementation note

This service is not a conventional authenticated multi-user SFTP server. In the current implementation, public-key and keyboard-interactive logins are identity derivation mechanisms, not access-control checks.

## Session Behavior

- IP-blacklisted connections are accepted and immediately wrapped in a throttled TCP connection before SSH auth completes.
- Successful sessions log `session/start` and `session/end` events with duration, login type, admin flag, ban flag, and operation counters.
- User stats are upserted on login, including `last_login`, `last_address`, and `seen`.
- Admin SFTP sessions operate as the special `system` owner regardless of the original login key hash.

## SSH Channel And Request Handling

### Supported channel type

- Only SSH `session` channels are accepted.
- Non-session channels are rejected.

### Supported requests on a session channel

- `subsystem=sftp`: accepted and starts the SFTP request server
- `env`: accepted and ignored
- `pty-req`: accepted and ignored
- `shell`: accepted only to print a message that the server is SFTP-only, then the channel exits
- `exec`: rejected and logged; also triggers sshdbot pattern inspection

### Unsupported requests

- Other request types are rejected.

## Welcome And Banner UX

### SSH banner

- The SSH transport banner comes from the configured banner file when present.
- Otherwise it falls back to a generated `name + version` banner.
- If `-banner.stats` is enabled, banner stats include users, contributors, files, and total stored size.

### User welcome

Regular SFTP sessions receive a server-side welcome on `stderr` that includes:

- first-time or returning-user messaging
- contributor-lock status
- upload threshold remaining when still locked
- max file size when configured
- pseudo-UID derived from the user hash
- a summary of recently owned files and directories when available
- a list of currently existing unrestricted files or directories

### Admin welcome

Admin SFTP sessions receive a separate admin banner that states:

- admin mode is active
- the session is connected as the system owner
- read, write, rename, and delete are unrestricted
- max file size still applies

## Archive Model And Ownership

### Filesystem root

- All paths are normalized relative to the configured upload directory.
- Path traversal outside the upload root is denied.
- Symlinks and other non-regular, non-directory entries are denied.

### Ownership model

- The `files` table tracks path ownership, size, and directory status.
- System-owned paths belong to the special owner `system`.
- User-created paths belong to the user's effective hash.
- Admin sessions authenticate as `system` and can act across all paths without taking ownership.

### Default unrestricted paths

The default always-downloadable paths are:

- `README.txt`
- `RULES.txt`
- `LICENSE.txt`
- `public/`

Configured unrestricted paths can be exact files, exact directories, or any parent directory path ending in `/`.

### UID/GID presentation

- SFTP stat responses present pseudo-UID/GID values derived from the owner hash.
- Unrestricted entries use special fixed UID/GID values instead of per-user ownership numbers.

## Permission Model

### Read access

Read access is allowed when any of the following is true:

- the session is admin
- the path is unrestricted
- the user has uploaded at least the contributor threshold

Otherwise file reads are denied with a contributor-lock message.

### Write and modify access

Write, delete, and rename access is allowed when:

- the session is admin
- the target path does not yet exist
- the existing path is owned by the same user

Write and modify access is denied when:

- the existing path is system-owned and the session is not admin
- the existing path is owned by another user
- directory-owner locking is enabled and the parent directory belongs to another non-system user

### Directory creation limits

New directory creation is additionally constrained by:

- a global mkdir rate limiter
- a maximum tracked directory count

## SFTP Operation Semantics

### List and stat

- `List` works only on directories.
- `Stat`, `Lstat`, and `Fstat` return a single entry.
- Hidden service directories `#recycle` and `@eaDir` are omitted from listings.

### Read

- Reads are blocked for non-contributors unless the path is unrestricted.
- Reads of directories fail.
- Successful reads log a download event and increment both user and file download counters.
- Shadow-banned reads are throttled to `2 KB/s`.

### Write

- Writes first pass path normalization, ban checks, permission checks, and parent-directory preparation.
- New files are claimed in the DB before writing.
- Existing files can only be overwritten by their owner or by admin.
- Append mode is honored for resumed uploads.
- Max file size is enforced during writes, not just at open time.
- On close, the server updates path size and owner metadata, records upload deltas, logs the upload, enqueues bad-file inspection, and reports remaining bytes needed for contributor unlock when applicable.

### Mkdir

- `Mkdir` uses the same parent ownership and directory limit logic as uploads.
- Parent directories are created with `MkdirAll`.
- Directory paths are registered in the DB as owned by the creating user.

### Remove and rmdir

- `Remove` and `Rmdir` both require modify permission on the target path.
- The server removes the on-disk path recursively and then deletes tracked metadata.

### Rename

- Rename requires modify permission on both source and destination paths.
- On success it performs `os.Rename`, logs the rename event, and updates tracked DB paths.

### Setstat and unsupported commands

- `Setstat` is accepted as a no-op.
- Other unsupported file commands return `ErrSshFxOpUnsupported`.

## Shadow Bans, IP Bans, And Anti-Abuse

### Shadow-banned users

Shadow bans are stored in the `shadow_banned` table.

For shadow-banned users:

- login still works
- directory listing still works, with a small artificial delay
- reads still work, but are throttled
- mutating operations sleep for a randomized delay and then fail with a generic error

### IP blacklist and whitelist

- IP allow/deny comes from live-reloaded text files.
- Whitelist matching overrides blacklist matching.
- Blacklisted IPs are throttled at the TCP level before auth.

### sshdbot detection

Rejected `exec` payloads are inspected for a known pattern that launches `./.<digits>/(sshd|xinetd)`.

When matched, the server:

- extracts callback IPs from the payload
- blacklists the callback IPs
- blacklists the uploader host `/24`
- adds the dropped bot binary to the bad-file list
- purges the user
- purges the detected bot path
- logs `admin/sshdbot_detected`

## Bad Files And Maintenance

### Bad-file matching

- The bad-file list is a live-reloaded text file of `sha256  filename` entries.
- Zero-length file hashes are ignored.
- An optional CAID database can extend bad-file matching for sufficiently large files.

### Async upload enforcement

- Completed uploads are inspected asynchronously against the bad-file list and optional CAID matcher.
- When a match is found, the file is purged and the owner's last known address range may be blacklisted.

### Scheduled maintenance

The hourly maintenance pass currently includes:

- legacy IP ban migration
- cleanup of deleted/stale tracked files
- orphan reconciliation
- purge of known bad files
- purge of sshdbot artifacts

Maintenance records status snapshots for admin inspection and emits admin maintenance events.

## Persistence And Audit Data

### Main tables

- `users`: login and transfer counters plus last address and seen count
- `files`: tracked paths, owners, sizes, directory bit, and download count
- `shadow_banned`: per-user shadow bans
- `log`: append-only event log with timestamp, IP, session, event kind, path, and JSON metadata

### Notable event kinds

The server records, among others:

- `connect`
- `login`
- `auth/attempt`
- `session/start`
- `session/end`
- `upload`
- `download`
- `delete`
- `rename`
- `shell`
- `exec`
- `denied/*`
- `admin/*`

## Self-Test Coverage

The built-in self-test suite exercises current SFTP behavior including:

- regular upload and download flows
- contributor unlock behavior
- admin SFTP login and unrestricted admin operations
- ban and unban behavior
- sshdbot purge behavior

## Current Constraints And Quirks

- Public-key login accepts any key; key possession identifies a user but does not authorize them.
- Keyboard-interactive accepts any credentials and logs the submitted password text.
- The service is SFTP-only even though shell requests are politely acknowledged.
- System-owned unrestricted directories such as `public/` are readable by all but still protected from non-admin modification at the directory-entry level.
