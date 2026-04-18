# Admin Spec

## Status

This document describes the current admin capabilities across the server as implemented in the repository today. It is an umbrella implementation spec, not a future-state proposal.

## Purpose

The admin surface exists to let an operator:

- inspect archive health and activity
- moderate users and IPs
- purge abusive content
- manage support files that drive allowlists, blocklists, admin keys, and bad-file matching
- access the archive as the system owner over SFTP
- run maintenance and self-test workflows
- use the browser-based admin console and explorer

## Related Specs

- [spec/web/admin.md](web/admin.md) covers the browser admin surface in detail.
- [spec/sftp.md](sftp.md) covers the primary SFTP service and its admin-specific SFTP behavior.

## Source Of Truth

The main code paths behind the admin surfaces are:

- `admin.go`
- `admin_http_server.go`
- `admin_http_handlers_*.go`
- `internal/adminhttp/*`
- `adminkeys.go`
- `iplist.go`
- `bad_files.go`
- `maintenance.go`
- `test_server.go`
- `selftest_integration_test.go`

## Admin Surfaces

There are four major admin surfaces today:

1. Admin SFTP
2. Admin web
3. File-backed support lists and moderation state
4. Maintenance and self-test controls

## Access Model

### Role model

- There is effectively one admin role.
- The current implementation does not split admin powers into sub-roles.
- Any successful admin session gets full moderation and maintenance capability for that surface.

### Admin SFTP access

Admin SFTP exists only when `-admin.sftp` is enabled.

An SSH public key is treated as admin when either:

- its SHA-256 hash matches the server host public key
- its hash or full authorized-key line appears in `admin_keys.txt`

### Admin web access

Admin web exists only when `-admin.http` is configured.

Auth behavior:

- if no admin HTTP token is configured, the web admin is completely unauthenticated
- if a token is configured, admin routes accept either a bearer token or an auth cookie
- one-time login URLs can mint the cookie for browser use

The full browser surface is specified in [spec/web/admin.md](web/admin.md).

## Admin SFTP

### Effective identity

- Admin SFTP sessions run as the special `system` owner.
- The original login key hash is still available for logging and welcome messaging.

### Capabilities

Admin SFTP sessions may:

- read any path
- write any path
- rename any path
- delete any path
- create directories regardless of ordinary user ownership

The main remaining limit is:

- max file size still applies

### Audit behavior

- Admin SFTP login emits `admin/login`.
- Normal session start/end and file operation events are still recorded.

### Operator UX

The admin welcome banner explicitly states:

- admin mode is active
- the user is connected as the system owner
- actions affect all users immediately

## Admin Web

The current web admin surface includes:

- the main `/admin` shell
- the dedicated admin explorer
- the statsviz dashboard
- optional Prometheus metrics
- one-time login URL exchange

At a high level it supports:

- summary dashboards and insights
- user, file, actor, session, and audit inspection
- quick user-hash ban and unban actions
- IP blacklist management
- maintenance status and ad hoc maintenance runs
- support-file editing for whitelist, blacklist, admin keys, and bad files
- self-test invocation
- a richer browser explorer with moderation actions

For route-by-route behavior, UI structure, and API inventory, see [spec/web/admin.md](web/admin.md).

## Support Files

The admin system relies heavily on live-reloaded text files.

### `whitelist.txt`

- Stores IPs and CIDR ranges that are always trusted.
- Seeded with localhost, RFC1918, link-local, and local IPv6 ranges when missing.
- Whitelist precedence overrides blacklist matches.
- Supports comments using `#`.
- Reloads in the background every 30 seconds and after in-process edits.

### `blacklist.txt`

- Stores exact IPs and CIDR ranges to throttle or block.
- Supports comments using `#`.
- Can be updated by web admin actions, maintenance, and sshdbot workflows.
- Reloads in the background every 30 seconds and after in-process edits.

### `admin_keys.txt`

- Stores admin SSH credentials as either raw SHA-256 hashes or full authorized-key lines.
- Supports comments and trailing inline comments.
- Invalid lines are ignored and logged as warnings.
- Reloads in the background every 30 seconds.
- When admin SFTP is enabled, startup tries to append the server host public key if it is not already present.

### `bad_files.txt`

- Stores bad-file signatures as `sha256  filename`.
- Comments and blank lines are ignored.
- The embedded default list is seeded only when an explicit file is not already present.
- Zero-length file hashes are intentionally ignored.
- Reloads in the background every 30 seconds and after in-process edits.

## Moderation Capabilities

### User shadow bans

- User bans are stored in the `shadow_banned` table, not in a file.
- Banned users can still connect and browse but have degraded behavior.
- Web admin exposes ban and unban for user hashes.

### IP bans

- IP bans live in the file-backed blacklist.
- Web admin can add and remove exact IP entries.
- Maintenance and sshdbot detection can also append broader CIDR bans.

### Purge

Admin capabilities include:

- purging a user by owner hash
- purging by file path
- deleting the user's tracked files from disk
- deleting the user's tracked DB rows
- clearing shadow bans for the purged user

### sshdbot response

When the server detects the known rejected `exec` sshdbot payload pattern, the admin workflow automatically:

- records an admin event
- blacklists callback IPs
- blacklists the source host `/24`
- adds the uploaded bot binary to the bad-file list
- purges the user and bot path

## Maintenance

### Automatic maintenance

- The server starts an hourly maintenance loop on startup.
- Maintenance state tracks whether a pass is running, what triggered it, and the last completed result.

### Current maintenance actions

The maintenance pass currently includes:

- migration of legacy DB-backed IP bans into the file-backed blacklist
- cleanup of deleted tracked files
- orphan reconciliation
- purge of known bad files
- purge of sshdbot artifacts

### Admin visibility

The admin web surface exposes:

- current maintenance status
- manual maintenance run
- parsed maintenance log search
- bad-file list inspection and editing
- mark-file-as-bad actions

## Self-Test

### Startup modes

- `-test` runs the integration self-test suite after startup and exits with pass/fail status.
- `-test.continue` runs the same suite but keeps serving afterward.

### Current coverage

The self-test suite covers admin-relevant behavior including:

- admin SFTP login using the server host key
- admin SFTP login using a newly configured admin key file entry
- unrestricted admin file operations
- ban and unban behavior
- sshdbot detection and purge workflows

The admin web surface can also trigger self-test actions through its API.

## Audit And Events

The admin implementation emits dedicated admin event kinds:

- `admin/login`
- `admin/ban`
- `admin/unban`
- `admin/purge`
- `admin/selftest`
- `admin/config`
- `admin/maintenance`
- `admin/sshdbot_detected`

These sit alongside the ordinary session, transfer, and denial events in the shared event log.

## Current Constraints And Quirks

- Admin web can be completely unauthenticated if `-admin.http` is set without a token.
- Admin SFTP trusts the server host key as an admin credential when `-admin.sftp` is enabled.
- There is no fine-grained authorization split between read-only inspection and destructive admin actions.
- Much of the admin control plane is file-backed and eventually consistent on a short reload loop rather than centrally transactional.
