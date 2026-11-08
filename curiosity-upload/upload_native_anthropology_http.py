#!/usr/bin/env python3
"""Upload intact native media from verified base64 parts to the public archive by HTTP POST.

Manifest: curiosity-upload/anthropology-http-batch-*.json
Parts: staging-anthropology/*.b64.partNN
GET directory -> session + CSRF cookie -> multipart HTTP POST -> round-trip SHA256 check.
The HTTP explorer creates uniquely named files on collision; preflight avoids that.
"""
import base64
import hashlib
import http.cookiejar
import io
import json
import mimetypes
import pathlib
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

from PIL import Image

BASE = "https://ftp.neuroky.me"
ROOT = pathlib.Path(".").resolve()
ALLOWED = {
    "do androids dream of erotic feet?",
    "ai macromastia convention and fundraiser",
    "if these artificial women can remember to eat, you can too",
    "if these artificial women can remember to do drugs, you can too",
    "Artificial Women Make Terrible Decisions",
    "Artificial Women Have to Work Tomorrow",
    "Artificial Women Get Sick Too",
    "Artificial Women Don't Know What to Do With Themselves",
    "Artificial Women Waiting for Something",
    "Bad Artificial Women Behaving Badly",
    "Artificial Women Have Feelings Too",
    "Artificial Women Are In Love With The Night",
    "Artificial Women Are In Love With Themselves",
    "Artificial Women from the Victorian Era Love The 1980s",
    "Artificial Women from the 1980s Love The Victorian Era",
    "Big Dumb Slutty Classical Goddesses",
    "Artificial Women Maybe Overreacted But Are Not Yet Ready To Apologize",
}
NAME = re.compile(r"20\d{2}-\d{2}-\d{2}_[A-Za-z0-9_-]+\.(?:png|jpe?g|webp|gif)\Z")
USER_AGENT = "ChatGPT-Anthropology-HTTP-Upload/1.0"


def url_for(folder, name=""):
    return BASE + "/" + urllib.parse.quote(folder, safe="") + "/" + urllib.parse.quote(name, safe="") if name else BASE + "/" + urllib.parse.quote(folder, safe="") + "/"


def decode(item):
    folder = item["folder"]
    name = item["name"]
    if folder not in ALLOWED or not NAME.fullmatch(name):
        raise ValueError("Invalid archive destination: " + repr((folder, name)))
    paths = item.get("parts") or [item["source"]]
    if not 1 <= len(paths) <= 100:
        raise ValueError("Invalid part count")
    pieces = []
    for s in paths:
        p = pathlib.Path(s)
        if p.is_absolute() or ".." in p.parts or not str(p).startswith("staging-anthropology/"):
            raise ValueError("Unsafe source part: " + s)
        absolute = (ROOT / p).resolve()
        if not absolute.is_relative_to(ROOT):
            raise ValueError("Source escapes checkout")
        pieces.append("".join(absolute.read_text("ascii").split()))
    raw = base64.b64decode("".join(pieces), validate=True)
    h = hashlib.sha256(raw).hexdigest()
    if len(raw) != int(item["bytes"]) or h != item["sha256"]:
        raise RuntimeError("Source integrity failure: " + name)
    with Image.open(io.BytesIO(raw)) as im:
        expected = {"png": "PNG", "jpg": "JPEG", "jpeg": "JPEG", "webp": "WEBP", "gif": "GIF"}[name.rsplit(".", 1)[1].lower()]
        if im.format != expected:
            raise RuntimeError("Wrong original-media format: " + name)
        if expected == "GIF" and getattr(im, "n_frames", 1) < 2:
            raise RuntimeError("Not an animated GIF: " + name)
        print("VALIDATED_HTTP_NATIVE:", name, "format:", im.format, "dimensions:", im.size, "bytes:", len(raw), "sha256:", h, flush=True)
    return raw, h


def opener():
    cookies = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
    client.addheaders = [("User-Agent", USER_AGENT)]
    return client, cookies


def request(client, url, *, method="GET", data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with client.open(req, timeout=90) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 404, b""
        detail = e.read(512)
        raise RuntimeError(f"HTTP {e.code} at {url}: {detail!r}") from e


def upload_one(client, cookies, item, raw, digest):
    folder, name = item["folder"], item["name"]
    dir_url = url_for(folder)
    file_url = url_for(folder, name)
    status, _ = request(client, dir_url)
    if status != 200:
        raise RuntimeError(f"Archive folder missing: {dir_url} (HTTP {status})")
    csrf = next((c.value for c in cookies if c.name == "explorer_csrf"), None)
    if not csrf or not re.fullmatch(r"[a-f0-9]{64}", csrf):
        raise RuntimeError("Missing or invalid CSRF cookie from explorer")

    status, already = request(client, file_url + "?please")
    if status == 200:
        old_hash = hashlib.sha256(already).hexdigest()
        if old_hash != digest:
            raise RuntimeError(f"Refusing overwrite of existing different file: {file_url}")
        print("HTTP_ALREADY_VERIFIED:", file_url, "bytes:", len(already), "sha256:", digest, flush=True)
        return

    boundary = "----ChatGPTNativeArchive" + secrets.token_hex(16)
    mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
    prefix = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="upload"; filename="{name}"\r\n'
        f"Content-Type: {mime}\r\n\r\n"
    ).encode("utf-8")
    body = prefix + raw + f"\r\n--{boundary}--\r\n".encode("ascii")
    status, _ = request(client, dir_url, method="POST", data=body, headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "X-CSRF-Token": csrf,
    })
    if status not in (200, 201, 303):
        raise RuntimeError(f"HTTP upload returned {status} for {file_url}")
    status, received = request(client, file_url + "?please")
    received_hash = hashlib.sha256(received).hexdigest()
    if status != 200 or len(received) != len(raw) or received_hash != digest:
        raise RuntimeError(f"HTTP round-trip verification failed: {file_url}, status={status}, bytes={len(received)}, hash={received_hash}")
    print("HTTP_VERIFIED:", file_url, "bytes:", len(received), "sha256:", received_hash, flush=True)


def main():
    manifest = json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
    items = manifest["items"]
    if not 1 <= len(items) <= 30:
        raise ValueError("Invalid batch size")
    if len({(i["folder"], i["name"]) for i in items}) != len(items):
        raise ValueError("Duplicate destination")
    prepared = [(i, *decode(i)) for i in items]  # Validate entire batch BEFORE any upload.
    client, cookies = opener()
    for item, raw, h in prepared:
        upload_one(client, cookies, item, raw, h)
    print("HTTP_NATIVE_ANTHROPOLOGY_BATCH_COMPLETE:", len(prepared), "/", len(items), "remote-SHA256-verified", flush=True)


if __name__ == "__main__":
    main()
