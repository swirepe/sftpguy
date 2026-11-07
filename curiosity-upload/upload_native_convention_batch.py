#!/usr/bin/env python3
"""Upload verified native convention stills and frame-animated GIFs via SFTP.

One release manifest selects the original media, including split base64 GIF
staging parts. This script never fabricates animation from a static image.
"""
import base64
import hashlib
import io
import json
import pathlib
import re
import stat
import sys
import urllib.parse

import paramiko
from PIL import Image, ImageSequence

FOLDER = "ai macromastia convention and fundraiser"
HOST = "ftp.neuroky.me"
ROOT = pathlib.Path(".").resolve()
VALID_NAME = re.compile(r"20\d\d-\d\d-\d\d_[A-Za-z0-9_-]+\.(png|gif)\Z")
MAX_FILE = 40_000_000

def source_path(path):
    p = pathlib.Path(path)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError("Invalid source path: " + path)
    abs_path = (ROOT / p).resolve()
    if not abs_path.is_relative_to(ROOT):
        raise ValueError("Escaping staging root")
    return abs_path

def decode_item(item):
    name = item["name"]
    if not VALID_NAME.fullmatch(name):
        raise ValueError("Invalid output filename: " + name)
    if ("parts" in item) == ("source" in item):
        raise ValueError("Each item requires source OR parts: " + name)
    paths = [item["source"]] if "source" in item else item["parts"]
    if not paths or len(paths) > 40:
        raise ValueError("Missing or excessive chunks")
    # Parts are created at base64-aligned boundaries. Join before decode.
    b64 = "".join("".join(source_path(p).read_text("ascii").split()) for p in paths)
    raw = base64.b64decode(b64, validate=True)
    if not raw or len(raw) > MAX_FILE:
        raise ValueError("Invalid decoded size for " + name)
    if len(raw) != int(item["bytes"]):
        raise ValueError("Local length mismatch for " + name)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != item["sha256"]:
        raise ValueError("Local SHA256 mismatch for " + name)
    with Image.open(io.BytesIO(raw)) as im:
        fmt = im.format
        if name.endswith(".png"):
            if fmt != "PNG":
                raise ValueError("PNG content does not match extension: " + name)
        else:
            if fmt != "GIF":
                raise ValueError("GIF content does not match extension: " + name)
            frames = getattr(im, "n_frames", 1)
            if frames < 3:
                raise ValueError("GIF is not animated: " + name)
            hashes = set()
            for frame in ImageSequence.Iterator(im):
                hashes.add(hashlib.sha256(frame.convert("RGB").tobytes()).digest())
            if len(hashes) < 3:
                raise ValueError("GIF frames do not change: " + name)
            print(f"VALIDATED GIF: {name}, frames={frames}, unique_frames={len(hashes)}", flush=True)
    return name, raw, digest

def remote_digest(sftp, path):
    h = hashlib.sha256()
    with sftp.file(path, "rb") as file:
        while True:
            block = file.read(256 * 1024)
            if not block:
                break
            h.update(block)
    return h.hexdigest()

def url_of(name):
    return "https://ftp.neuroky.me/" + urllib.parse.quote(FOLDER + "/" + name, safe="/")

def upload_verified(sftp, name, data, digest):
    dest = FOLDER + "/" + name
    try:
        old = sftp.stat(dest)
    except FileNotFoundError:
        old = None
    if old is None:
        with sftp.file(dest, "wb") as file:
            file.write(data)
            file.flush()
        print("UPLOADED:", dest, flush=True)
    else:
        if old.st_size != len(data):
            raise RuntimeError("Existing archive file differs; refusing overwrite: " + dest)
        print("EXISTS:", dest, flush=True)
    observed = sftp.stat(dest).st_size
    if observed != len(data):
        raise RuntimeError("Remote SFTP byte count mismatch: " + dest)
    # SFTP STAT reliably works even when a new ephemeral SSH key has not yet
    # unlocked downloads. The local bytes were independently SHA256 checked.
    print(f"VERIFIED_SIZE: {url_of(name)} bytes: {len(data)} local_sha256: {digest}", flush=True)

def verify_hashes_if_unlocked(sftp, items):
    # Server's default CONTRIBUTOR_THRESHOLD is 1 MB. Do NOT attempt to
    # download until all new assets have been uploaded with this same key.
    # On a full retry, everything may already exist, leaving the fresh key
    # below the threshold; never misrepresent size-only checks as hash checks.
    first_name = items[0][0]
    try:
        first_remote_hash = remote_digest(sftp, FOLDER + "/" + first_name)
    except PermissionError:
        print("SFTP_HASH_CHECK_LOCKED: current ephemeral key has not met server's contributor threshold; all file sizes verified.", flush=True)
        return 0
    except OSError as exc:
        print("SFTP_HASH_CHECK_UNAVAILABLE:", str(exc), flush=True)
        return 0

    for idx, (name, data, digest) in enumerate(items):
        found = first_remote_hash if idx == 0 else remote_digest(sftp, FOLDER + "/" + name)
        if found != digest:
            raise RuntimeError("Remote SFTP SHA256 mismatch: " + name)
        print(f"VERIFIED_SHA256: {url_of(name)} bytes: {len(data)} sha256: {found}", flush=True)
    return len(items)

def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: upload_native_convention_batch.py MANIFEST.json")
    job = json.loads(source_path(sys.argv[1]).read_text("utf-8"))
    if job.get("folder") != FOLDER:
        raise ValueError("Unexpected destination directory")
    photos = job.get("photos", [])
    gifs = job.get("gifs", [])
    if len(photos) != 8 or len(gifs) != 2:
        raise ValueError("Release requires 8 photos and 2 native animated GIFs")
    # New GIFs first: this archive grants downloads only after the key uploads a file.
    # Existing PNGs may be readable only after this session has uploaded one new asset.
    items = gifs + photos
    names = [x["name"] for x in items]
    if len(names) != len(set(names)):
        raise ValueError("Repeated remote filenames")
    decoded = [decode_item(x) for x in items]
    print(f"VALIDATED LOCAL MEDIA: {len(photos)} original PNGs + {len(gifs)} multi-frame GIFs", flush=True)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(HOST, port=22, username="anonymous", pkey=paramiko.RSAKey.generate(2048),
                    look_for_keys=False, allow_agent=False, timeout=35, auth_timeout=35,
                    banner_timeout=35)
        with ssh.open_sftp() as sftp:
            try:
                existing = sftp.stat(FOLDER)
                if not stat.S_ISDIR(existing.st_mode):
                    raise ValueError("Destination exists but is not directory")
            except FileNotFoundError:
                sftp.mkdir(FOLDER)
            for name, data, digest in decoded:
                upload_verified(sftp, name, data, digest)
            hashes_verified = verify_hashes_if_unlocked(sftp, decoded)
    finally:
        ssh.close()
    print(f"RELEASE UPLOAD FINISHED: {len(photos)} photos + {len(gifs)} native GIFs = {len(items)} remote files, 10 sizes checked, {hashes_verified} remote SHA256 hashes checked.", flush=True)

if __name__ == "__main__":
    main()
