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
LIMIT = 25_000_000


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
        if not re.fullmatch(r"[A-Za-z0-9_./-]+", name) or ".." in name:
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
    collection = job["collection"]
    day = job["date"]
    if not re.fullmatch(r"[A-Za-z0-9_-]+", collection):
        die("Invalid collection")
    if not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", day):
        die("Invalid date")

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    base_exists = existing(opener, collection)
    if base_exists and existing(opener, collection + "/" + day):
        die("Dated archive directory already exists. Refusing to create a duplicate.")

    records = []
    contents = []
    for item in job["items"]:
        src, relative = item["url"], item["name"]
        print("Downloading:", src, flush=True)
        data = get_bytes(opener, src, min(item.get("max_bytes", LIMIT), LIMIT))
        if item.get("signature") and not data.startswith(item["signature"].encode("ascii")):
            die("Unexpected file signature for " + relative)
        sha1 = hashlib.sha1(data).hexdigest()
        if item.get("sha1") and item["sha1"].lower() != sha1:
            die("Upstream SHA-1 mismatch: " + relative)
        records.append({**item, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        contents.append((relative, data))

    report = {**job, "items": records, "uploaded_by": "GitHub Actions curiosity pilot"}
    manifest_bytes = (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    contents.append(("manifest.json", manifest_bytes))

    # Acquire same-origin CSRF cookie from the explorer before posting.
    target = BASE + ("/" + urllib.parse.quote(collection, safe="") + "/" if base_exists else "/")
    with opener.open(urllib.request.Request(target, headers={"User-Agent": UA}), timeout=35) as resp:
        resp.read(250000)
    csrf = next((c.value for c in jar if c.name == "explorer_csrf"), None)
    if not csrf:
        die("Explorer did not provide a CSRF cookie")
    sub = day + "/" if base_exists else collection + "/" + day + "/"
    payload = [(sub + name, data) for name, data in contents]
    boundary, body = build_multipart(payload, csrf)
    req = urllib.request.Request(
        target, data=body, method="POST",
        headers={
            "User-Agent": UA,
            "X-CSRF-Token": csrf,
            "Content-Type": "multipart/form-data; boundary=" + boundary,
        },
    )
    print("Uploading", len(payload), "files to", target, "(bytes:", len(body), ")", flush=True)
    with opener.open(req, timeout=180) as response:
        print("Upload HTTP status:", response.status, flush=True)
        if response.status not in (200, 201, 204):
            die("Unexpected upload response")

    # Check the exact expected paths. No success without remote verification.
    for relative, data in contents:
        name = collection + "/" + day + "/" + relative
        url = BASE + "/" + urllib.parse.quote(name, safe="/")
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
        with opener.open(req, timeout=40) as resp:
            if resp.status != 200:
                die("Verification HEAD failed: " + url)
            size = resp.headers.get("Content-Length")
            if size is not None and int(size) != len(data):
                die("Verification size mismatch for " + url + ": " + size)
        print("VERIFIED:", url, "(", len(data), "bytes )", flush=True)
    print("SUCCESS: all remote files verified.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("FAILED:", exc, file=sys.stderr)
        sys.exit(1)
