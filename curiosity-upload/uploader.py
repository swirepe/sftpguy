#!/usr/bin/env python3
"""Download vetted public-domain/CC0 artifacts, then upload through sftpguy's HTTP explorer."""
import hashlib
import http.cookiejar
import io
import json
import mimetypes
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = os.environ.get("ARCHIVE_URL", "https://ftp.neuroky.me").rstrip("/")
UA = "Curiosity-Archive-Pilot/0.1 (+https://github.com/swirepe/sftpguy)"
LIMIT = 64_000_000


def die(message):
    raise RuntimeError(message)


def get_bytes(opener, url, max_bytes=LIMIT):
    if not url.startswith("https://"):
        die("Only HTTPS downloads are supported: " + url)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with opener.open(req, timeout=90) as response:
        data = bytearray()
        while True:
            chunk = response.read(256 * 1024)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > max_bytes:
                die("Download too large: " + url)
        return bytes(data)


def existing(opener, path):
    url = BASE + "/" + urllib.parse.quote(path.strip("/"), safe="/") + "/"
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
    try:
        with opener.open(req, timeout=30) as response:
            return response.status == 200
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return False
        raise


def build_multipart(files, csrf):
    boundary = "----curiosity-" + uuid.uuid4().hex
    out = io.BytesIO()
    def add(value):
        out.write(value.encode("utf-8") if isinstance(value, str) else value)
    add("--" + boundary + "\r\n")
    add('Content-Disposition: form-data; name="csrf_token"\r\n\r\n')
    add(csrf + "\r\n")
    for name, contents in files:
        if not re.fullmatch(r"[A-Za-z0-9_ ?./-]+", name) or ".." in name:
            die("Unsafe filename: " + name)
        content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        add("--" + boundary + "\r\n")
        add('Content-Disposition: form-data; name="uploadFiles"; filename="' + name + '"\r\n')
        add("Content-Type: " + content_type + "\r\n\r\n")
        add(contents)
        add("\r\n")
    add("--" + boundary + "--\r\n")
    return boundary, out.getvalue()


def main():
    if len(sys.argv) != 2:
        die("Usage: uploader.py manifest.json")
    with open(sys.argv[1], encoding="utf-8") as f:
        job = json.load(f)
    day = job["date"]
    if not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", day):
        die("Invalid date")

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.cookiejar = jar
    records = []
    for item in job["items"]:
        src, target_path = item["url"], item["name"]
        if not re.fullmatch(r"[A-Za-z0-9_ ?./-]+", target_path) or ".." in target_path or "/" not in target_path:
            die("Unsafe or uncategorized target path: " + target_path)
        if existing_file(opener, target_path):
            print("SKIPPED existing:", target_path, flush=True)
            records.append({**item, "remote_path": target_path, "status": "already_present"})
            continue
        print("Downloading:", src, flush=True)
        data = get_bytes(opener, src, min(item.get("max_bytes", LIMIT), LIMIT))
        if item.get("signature") and not data.startswith(item["signature"].encode("ascii")):
            die("Unexpected file signature for " + target_path)
        sha1 = hashlib.sha1(data).hexdigest()
        if item.get("sha1") and item["sha1"].lower() != sha1:
            die("Upstream SHA-1 mismatch: " + target_path)
        recorded = {**item, "remote_path": target_path, "status": "uploaded",
                    "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        upload_one(opener, target_path, data)
        records.append(recorded)

    # A stable, collision-safe provenance filename for each distinct selection.
    # Keep originals inside their existing subject folders; only metadata is separate.
    selection_key = hashlib.sha256(json.dumps(job, sort_keys=True).encode("utf-8")).hexdigest()[:12]
    manifest_path = "Archive-Manifests/curiosity-" + day + "-" + selection_key + ".json"
    report = {**job, "items": records, "uploader": "GitHub Actions curiosity pilot"}
    manifest_bytes = (json.dumps(report, indent=2, ensure_ascii=False) + chr(10)).encode("utf-8")
    if existing_file(opener, manifest_path):
        print("SKIPPED existing manifest:", manifest_path, flush=True)
    else:
        upload_one(opener, manifest_path, manifest_bytes)
    uploaded = sum(1 for r in records if r["status"] == "uploaded")
    skipped = len(records) - uploaded
    print("SUCCESS: uploaded", uploaded, "files; skipped", skipped,
          "already present; all new uploads verified.", flush=True)


def existing_file(opener, path):
    url = BASE + "/" + urllib.parse.quote(path.strip("/"), safe="/")
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    try:
        with opener.open(req, timeout=30) as response:
            return response.status == 200
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return False
        raise


def upload_one(opener, dest, contents):
    parts = dest.strip("/").split("/")
    # The explorer creates the FIRST multipart path component as a new folder
    # even if it already exists; POST directly into the longest existing parent.
    prefix_length = 0
    for i in range(1, len(parts)):
        if existing(opener, "/".join(parts[:i])):
            prefix_length = i
        else:
            break
    parent = "/".join(parts[:prefix_length])
    filename = "/".join(parts[prefix_length:])
    url = BASE + ("/" + urllib.parse.quote(parent, safe="/") + "/" if parent else "/")
    with opener.open(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=35) as resp:
        resp.read(250000)
    csrf = next((c.value for c in opener.cookiejar if c.name == "explorer_csrf"), None)
    if not csrf:
        die("Explorer did not provide a CSRF cookie")
    boundary, body = build_multipart([(filename, contents)], csrf)
    req = urllib.request.Request(url, data=body, method="POST",
        headers={"User-Agent": UA, "X-CSRF-Token": csrf,
            "Content-Type": "multipart/form-data; boundary=" + boundary})
    print("Uploading:", dest, "via", url, flush=True)
    with opener.open(req, timeout=180) as response:
        if response.status not in (200, 201, 204):
            die("Unexpected upload HTTP status: " + str(response.status))
    target_url = BASE + "/" + urllib.parse.quote(dest, safe="/")
    with opener.open(urllib.request.Request(target_url, method="HEAD",
        headers={"User-Agent": UA}), timeout=40) as resp:
        if resp.status != 200:
            die("Remote verification failed: " + target_url)
        size = resp.headers.get("Content-Length")
        if size is not None and int(size) != len(contents):
            die("Remote byte count mismatch: " + target_url)
    print("VERIFIED:", target_url, "bytes:", len(contents), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("FAILED:", exc, file=sys.stderr)
        sys.exit(1)
