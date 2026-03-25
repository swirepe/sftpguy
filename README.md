# sftpguy

`sftpguy` is an anonymous, share-first SFTP archive written in Go. It accepts whatever SSH identity material a client presents, derives a stable anonymous user ID from it, and grants download privileges based on contributions:

* Anyone can login anonymously, upload files, and list directories
* Downloads are enabled for a user once they have upload enough bytes (default 1mb)
* Users can edit, rename, or delete only their own files

It is designed for public or semi-public dropboxes and community archives, not for private user accounts.


> [!WARNING]
> This is not a traditional authenticated SFTP server.
> 
> By default, any SSH public key is accepted. Keyboard-interactive logins are also accepted and turned into anonymous identities, and `-noauth` can allow fully unauthenticated SSH sessions. Do not expose this to an untrusted network unless you actually want anonymous access and have added network controls, admin tokens, or IP restrictions. Do not use real user passwords with it.  Do not use it with data you care about.  **You're going to get a lot of bots and garbage**, but that's part of the fun.

## Try it

An instance is running at `ftp.neuroky.me`.  Connect to it with:

    sftp ftp.neuroky.me

Or create a temporary public key, because it accepts all keys:

```bash
TMPKEY=$(mktemp nkXXXXXXXX)
ssh-keygen -t ed25519 -N '' -f $TMPKEY
sftp  -o "PreferredAuthentications=publickey" -i $TMPKEY ftp.neuroky.me
```

Or if you want to use a password, because it accepts any user/password combination:

    sftp -o "PreferredAuthentications=keyboard-interactive" ftp.neuroky.me

These are all different ways to access the same archive.  A web-based version (source at [cmd/explorer/main.go](cmd/explorer/main.go)) is running at [https://ftp.neuroky.me/](https://ftp.neuroky.me/).


You may consider using a modern sftp client like [lftp,](https://lftp.yar.ru/) although you might not see the welcome banner. 

## Is this AI slop?

Yeah.

Kinda.

The core of the server was lovingly handcrafted by a human.  You can see this in [sftpguy.go](sftpguy.go) or, more succinctly, in [cmd/mini/mini.go](md/mini/mini.go).  The core of the admin and maintenance operations are handwritten.  There used be an admin TUI that I scrapped and replaced with a web interface.  The admin web interface is all machine-written, and behind a flag.


## What Makes It Different

- Any public key can log in; the server hashes the presented key and uses that hash as the user identity.
- Non-contributors can upload immediately, but downloads are limited to unrestricted paths until they upload enough data.
- The first user to create a path claims it. Owners can modify their own paths; other users cannot overwrite or delete them.
- System-owned files stay protected even inside unrestricted folders.
- A built-in admin web console exposes users, files, audit history, sessions, maintenance, self-test, IP lists, and a browser-style explorer.
- A separate admin SFTP mode can grant system-owner access to approved keys.
- SQLite stores file ownership, user stats, bans, and the audit log.

## Archive Rules

- Users may always upload new files and directories.
- Users may always modify, rename, or delete files and directories they created.
- Non-contributors may only download unrestricted paths.
- Contributors unlock all downloads after uploading at least `-contrib` bytes.
- Default unrestricted paths are `README.txt`, `RULES.txt`, `LICENSE.txt`, and `public/`.
- Symlinks and path traversal are rejected.
- `-dir.owners_only` can prevent uploads into directories owned by someone else.
- `-maxsize` caps file size, and `-dir.max` caps total directory count.

## Quick Start

Build and run the server:

```bash
go build .
./sftpguy \
  -port 2222 \
  -dir ./uploads \
  -db.path ./sftp.db \
  -logfile ./sftp.log \
  -admin.http 127.0.0.1:8080 \
  -admin.http.token.file ./admin.token \
  -admin.sftp
```

On first start, `sftpguy` will create or seed the common runtime files it needs, including:

- `id_ed25519` and `id_ed25519.pub` if the host key does not exist yet
- `sftp.db`
- `sftp.log`
- `uploads/`
- `whitelist.txt`
- `bad_files.txt`
- `admin_keys.txt` when admin SFTP mode needs it

If `-admin.http.token.file` is set and the file is missing or empty, the server generates a bearer token for the admin console and logs a one-time login URL at startup.

## Connecting As A User

Generate any SSH keypair and connect with `sftp`:

```bash
ssh-keygen -t ed25519 -N '' -f ./demo_user
sftp -P 2222 -i ./demo_user anything@127.0.0.1
```

The username is not used for public-key logins. Identity comes from the presented key material.

Until the contribution threshold is reached, users can still:

- upload files
- list directories
- manage the files they own
- download only unrestricted paths

## Important Flags

Run `go run . -h` for the full list. The flags most operators care about are:

| Flag | Purpose |
| --- | --- |
| `-port` | SSH listen port. Default: `2222`. |
| `-dir` | Upload directory on disk. Default: `./uploads`. |
| `-db.path` | SQLite database path. Default: `sftp.db`. |
| `-hostkey` | SSH host key path. Default: `id_ed25519`. |
| `-contrib` | Bytes required to unlock all downloads. Default: `1mb`. |
| `-unrestricted` | Comma-separated list of always-downloadable files/directories. |
| `-dir.owners_only` | Only allow uploads into directories the current user owns. |
| `-maxsize` | Maximum file size, for example `500mb`, `2gb`, or `0` for unlimited. |
| `-admin.http` | Bind address for the web admin console, for example `127.0.0.1:8080`. |
| `-admin.http.token` | Static bearer token for admin HTTP auth. |
| `-admin.http.token.file` | Load or generate the admin bearer token from a file. |
| `-admin.sftp` | Enable system-owner SFTP logins for approved admin keys. |
| `-admin.keys` | File containing admin public keys or SHA-256 key hashes. |
| `-blacklist` / `-whitelist` | IP list files used for blocking and trusted ranges. |
| `-bad` | File of bad SHA-256 hashes that trigger automatic purge and blacklist updates. |
| `-prometheus.enable` | Enable metrics on the admin HTTP listener. Default: `true`. |
| `-prometheus.root` | Metrics path. Default: `/metrics`. |
| `-test` | Run the integration self-test suite, then exit. |
| `-test.continue` | Run self-test, then keep serving. |
| `-src` | Export the embedded source snapshot into the upload directory and mark it unrestricted. |
| `-src.out` | Export the embedded source snapshot to a directory, then exit. |

## Environment Variables

Every flag-backed setting also supports environment variables. The code accepts both the bare name and an `SFTP_`-prefixed form.

Examples:

- `PORT` or `SFTP_PORT`
- `DB_PATH` or `SFTP_DB_PATH`
- `ARCHIVE_NAME` or `SFTP_ARCHIVE_NAME`
- `ADMIN_HTTP` or `SFTP_ADMIN_HTTP`

Flags still win if you set both.

## Admin Interfaces

### Web Console

When `-admin.http` is set, the admin UI is served at:

```text
http://HOST:PORT/admin
```

The web console includes:

- archive summary and stats
- file browser and owner lookup
- audit log, auth attempts, live events, and session timelines
- banned IP management
- IP list and admin key editing
- bad-file maintenance controls
- self-test execution
- one-time login URL generation

> [!CAUTION]
> If you set `-admin.http` without `-admin.http.token` or `-admin.http.token.file`, the admin console is unauthenticated. Bind it to localhost or protect it another way.

### Admin SFTP

`-admin.sftp` enables a privileged SFTP mode. When the client key matches one of the keys in `admin_keys.txt`, or matches the server host key, the session runs as the system owner and bypasses normal ownership and contributor restrictions.

`admin_keys.txt` accepts:

- normal `authorized_keys` lines
- raw 64-character SHA-256 public-key hashes

## Support Files

These files are operator-facing and can be edited while the server is running. They are reloaded in the background.

| File | Purpose |
| --- | --- |
| `whitelist.txt` | Trusted IPs/CIDRs. Localhost and common private-network ranges are seeded automatically. |
| `blacklist.txt` | IPs/CIDRs to block. |
| `admin_keys.txt` | Admin public keys or hashes for privileged SFTP access. |
| `bad_files.txt` | SHA-256 hashes and optional filenames for content that should be purged on upload or during maintenance. |

## Maintenance And Moderation

At startup and every hour after that, `sftpguy` runs maintenance that:

- removes stale database entries for files already deleted on disk
- reconciles on-disk files back into the database
- checks uploads against the bad-file hash list
- purges matched bad files
- can add the last known owner address to the blacklist when a bad file is found

Users can also be shadow-banned. Shadow-banned sessions can still log in and browse, but destructive operations are delayed and fail in a generic way, and transfer speed is throttled.

## Metrics And Testing

Prometheus metrics are exposed from the admin HTTP listener at `-prometheus.root`, which defaults to `/metrics`.

If admin HTTP auth is configured, the metrics endpoint uses the same auth.

Useful commands:

```bash
go test ./...
go run . -test
go run . -test.continue -admin.http 127.0.0.1:8080
```

## Installing As A systemd Service

The binary has a built-in installer:

```bash
sudo ./sftpguy \
  -install \
  -install.service sftpguy \
  -install.user anonymous \
  -install.group ftp \
  -dir /var/lib/sftpguy/uploads \
  -db.path /var/lib/sftpguy/sftp.db \
  -logfile /var/log/sftpguy.log
```

This copies the current binary into `/var/lib/<service>/<service>`, writes `/etc/systemd/system/<service>.service`, optionally creates the service user and group, reloads systemd, enables the unit, and starts it.

## Repository Extras

This repo also contains a couple of related helper binaries:

- [`cmd/mini`](cmd/mini/mini.go): a much smaller stripped-down share-first SFTP server
- [`cmd/explorer`](cmd/explorer/main.go): a standalone HTTP file explorer/uploader, as seen running at [https://ftp.neuroky.me](https://ftp.neuroky.me)
- [`cmd/explorer-deluxe`](cmd/explorer-deluxe/main.go): a fancier `cmd/explorer` with thumbnails, a tree view, etc.  The basis of the [admin explorer](internal/adminexplorer/explorer.go), but without the admin capabilities.  

The main project entrypoint is still the root `./sftpguy` binary.
