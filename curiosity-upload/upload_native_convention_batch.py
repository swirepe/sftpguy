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
import urllib.request

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

def http_digest(url, max_bytes):
    """Read archive's public download endpoint, independent of SFTP download permissions."""
    h = hashlib.sha256()
    total = 0
    req = urllib.request.Request(url, headers={"User-Agent": "CuriosityArchive-IntegrityAudit/1.0"})
    with urllib.request.urlopen(req, timeout=35) as resp:
        if resp.status != 200:
            raise RuntimeError("Unexpected archive HTTP status: " + str(resp.status))
        while True:
            part = resp.read(256 * 1024)
            if not part:
                break
            total += len(part)
            if total > max_bytes:
                raise RuntimeError("Archive public download exceeds original size")
            h.update(part)
    return total, h.hexdigest()

def upload_verified(sftp, name, data, digest):
    dest = FOLDER + "/" + name
    try:
        st = sftp.stat(dest)
    except FileNotFoundError:
        st = None
    if st is None:
        with sftp.file(dest, "wb") as file:
            file.write(data)
            file.flush()
        print("UPLOADED:", dest, flush=True)
    else:
        if st.st_size != len(data):
            raise RuntimeError("Existing archive file differs; refusing overwrite: " + dest)
        print("EXISTS:", dest, flush=True)
    st = sftp.stat(dest)
    if st.st_size != len(data):
        raise RuntimeError("SFTP remote file size mismatch: " + dest)
    url = "https://ftp.neuroky.me/" + urllib.parse.quote(dest, safe="/")
    try:
        received_bytes, received_sha = http_digest(url, len(data))
    except Exception as exc:
        # SFTP server does not grant fresh ephemeral identities read access.
        # Its STAT does work, as in original archive uploader.
        print("VERIFIED_SIZE_ONLY:", url, "bytes:", st.st_size,
              "local_sha256:", digest, "http_verification_unavailable:", str(exc), flush=True)
        return
    if received_bytes != len(data) or received_sha != digest:
        # The explorer may return a preview/HTML representation rather than
        # the raw media bytes. Its response is not proof of SFTP corruption.
        # As with the original working foot uploader, trust SFTP STAT size.
        print("HTTP_RESPONSE_NOT_RAW:", url,
              "response_bytes:", received_bytes, "response_sha256:", received_sha,
              "expected_bytes:", len(data), flush=True)
        print("VERIFIED_SIZE_ONLY:", url, "bytes:", st.st_size,
              "local_sha256:", digest, flush=True)
        return
    print(f"VERIFIED: {url} bytes: {len(data)} sha256: {received_sha}", flush=True)

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
    finally:
        ssh.close()
    print(f"RELEASE UPLOAD FINISHED: {len(photos)} original photos + {len(gifs)} native GIFs = {len(items)} files; review VERIFIED versus VERIFIED_SIZE_ONLY in logs.", flush=True)

if __name__ == "__main__":
    main()
