# Artificial Women Photo Anthropology — verified uploader runbook

Updated: 2026-11-08. This guide is for the replacement scheduled automation; the 22 creative series, titles, time slots, and deliverables are in **`curiosity-upload/anthropology-series-catalog.md`** in this same repository/branch. Those two files, not a sprawling multi-year scheduled-task prompt or a prior read-only run conversation, are the source of truth.

## What is actually working

- GitHub repository: `swirepe/sftpguy`; **branch `curiosity-upload-pilot-2026-11-07`** (not the default branch).
- Primary uploader: `curiosity-upload/upload_native_anthropology_http.py`.
- GitHub Action: `.github/workflows/anthropology-http-upload.yml` called "Native anthropology HTTP POST upload". It is triggered by a **new commit that adds a new manifest** matching `curiosity-upload/anthropology-http-batch-*.json` on that branch.
- The action decodes exact original image bytes from GitHub-staged base64 chunks, checks format/size/SHA256, and POSTs multipart to `https://ftp.neuroky.me/` using a cookie and `X-CSRF-Token`, then reads back `?please` to check the full remote bytes and SHA256. No SFTP login or explorer credentials are needed for this transport. It can now create a missing allowed root folder by sending a `folder/filename` multipart name to the archive root, while existing folders continue using their ordinary folder POST.
- The HTTP script has an allowlist for **all 22 series**, exact spelling and case, and refuses conflicting overwrites or incorrectly named content.
- Successful real-file proof from 2026-11-08: https://github.com/swirepe/sftpguy/actions/runs/42450851693 verified an original native PNG and remote read-back SHA256; destination: https://ftp.neuroky.me/Artificial%20Women%20from%20the%20Victorian%20Era%20Love%20The%201980s/2026-11-08_0015_victorian_arcade_muse_http.png .
- Fallback: `curiosity-upload/upload_native_anthropology_batch.py` run by `.github/workflows/curiosity-upload-pilot.yml` for manifests named `curiosity-upload/anthropology-native-batch-*.json`. This uses ephemeral-key SFTP, creates root folders if missing, and checks `VERIFIED_SIZE:` per file, with `VERIFIED_SHA256:` only if remote read is permitted. Prefer the HTTP route because it performs remote content-hash round trips and has been proved end-to-end. Do **not** confuse "SFTP stat succeeded" with a remote hash verification.

## Execute the scheduled slot: the actual sequence

1. Resolve today's local hour and day of week in **America/New_York**. Open both repository files anew via the connected GitHub connector; use `ref=curiosity-upload-pilot-2026-11-07`. Determine *all* due series by the catalog. Do not silently replace another series when two or more collide in one hour.
2. Invoke **native ChatGPT image generation** one media asset at a time. Make separate originals (no contact sheets or collages); two convention GIFs, if due, must contain genuinely changing animated frames. If a generator is inaccessible, say which assets were not created; do not silently switch to Runway, other image generators, or placeholders. Do not falsely claim generation.
3. For each actually generated media file, use the accessible original raw file in the current execution environment, not an image thumbnail, preview, model output URL alone, or a rebuilt image. Store in `/mnt/data` when possible. Compute its raw `bytes`, `sha256`, and correct file suffix. Use collision-resistant date+clock+description filenames. Check that a `gif` is truly animated.
4. If direct archive HTTPS or SFTP is **actually available in the current execution environment**, you may upload by the same correct multipart protocol and perform a `?please` GET round-trip + size/SHA256 verification. Do not repeatedly assume that a failed local network test means the GitHub bridge is unavailable. The GitHub Action is the normal path.
5. **Staging from a network-isolated runtime to GitHub (tested method):**
   - Base64 encode each original file without modifying its bytes. Split its continuous base64 ASCII stream into separate chunks of approximately **200,000 characters**, cut at multiples of four. Save chunks under `/mnt/data` as `.txt` files. Calculate sha256 from the **original binary**, never the base64.
   - The connected GitHub `create_file` action accepts UTF-8 text and can create `staging-anthropology/<unique-release>-<name>.b64.part01`, `part02`, etc. If a local file's contents cannot flow directly into a connector tool call, use the **Library-to-GitHub bridge**: upload each `.txt` part to a unique temporary Library folder `/Anthropology-Transfer-Staging/<release>/` using `files__manage_library`; list the folder and read back the literal UTF-8 chunk text with `files__read` through `functions.exec`; pass that exact text to `mcp__GitHub__create_file` **without printing the huge data in the chat or truncating it**. Write GitHub chunk files **sequentially**, on the correct branch, finishing all of them before a manifest commit. Temporary Library copies can be deleted after success.
   - For files already in the conversation Library, use `files__materialize` if original bytes are not mounted, rather than recreating them from a displayed preview.
   - Keep staged path names unique to the release and do not re-use stale signed third-party URLs.
6. Last, commit **one new manifest** (never before all chunks exist) on the same branch:
   ```json
   {
     "items": [
       {
         "folder": "married to her artificial sea",
         "name": "2026-11-08_0400_mermaid_repairing_nets.png",
         "bytes": 2547005,
         "sha256": "<actual lowercase 64-character original-file digest>",
         "parts": [
           "staging-anthropology/<actual-release-and-image>.b64.part01",
           "staging-anthropology/<actual-release-and-image>.b64.part02"
         ]
       }
     ]
   }
   ```
   This JSON is **illustrative only**, not a valid task output: use measured byte count, real sha256, and list ALL actual parts, even if more than two. Each manifest can contain **1–30** independently generated items. File names must match `YYYY-MM-DD_<safe_ascii_slug>.<png|jpg|jpeg|webp|gif>`; date plus HHMM and descriptive slug are recommended. Use a new unique manifest name `curiosity-upload/anthropology-http-batch-<release-id>.json` each slot. This final manifest commit is what triggers the HTTP Action.
7. Inspect GitHub Actions for the **manifest commit SHA** using the connected GitHub workflow-run/job/steps/logs actions. A correct finished batch has exactly one `HTTP_VERIFIED:` or matching `HTTP_ALREADY_VERIFIED:` per requested file, containing the **exact expected remote folder and filename, byte count and SHA256**, and a final `HTTP_NATIVE_ANTHROPOLOGY_BATCH_COMPLETE:` for all items. A pending workflow, merged commit, locally present file, or upload POST alone does **not** prove archive success. Check `?please` from a proper networked environment if needed to reconcile discrepancies.
8. On errors, check missing parts, wrong branch, manifest filename, checksum, exact folder case, nonanimated GIF, CSRF/HTTP response, connection and collision. Retry only with idempotent no-overwrite handling; don't spam identical jobs or duplicate files. Report a per-series count of **generated / verified uploaded / failed**, exact missing items, action run URLs if available. Say "staged" or "workflow submitted" if verification is not yet complete. Do not claim success on inference. Do not let recovery of an old backlog block today's due slot.

## Workflow constraints and durability

The old automation was already disabled. The new automation must use this runbook and catalog **without embedding their full contents in its own prompt**. This avoids repeating the previous context explosion. Keep per-run reporting concise, and do not paste base64 or giant logs into responses. The archive is organized directly by conceptual root folders, not by dated release subfolders. Upload only new files; never edit unrelated archive contents or the separate "Daily Curiosity Finds" automation.

The server's unauthenticated explorer may serve a *locked HTML page* instead of an image on an ordinary GET. A real binary read-back uses `?please` (as in the verified script). Files with identical name but different digest should cause a **hard failure**, never overwriting them.

If a future run has no supported native image tool or cannot reach the connected GitHub/files tools, report the missing capability and actual work completed rather than repeatedly inventing network access. Direct network access from a local container is not a prerequisite for the proven connector bridge.

Do not use this project as a reason to edit or delete historical photo files. A previously noted 2026-11-07 23:00 pair of native originals was generated but not uploaded; only backfill if the **exact original binary files** can be recovered, otherwise mark those files missing without claiming recovery.
