#!/usr/bin/env python3
"""Archive original generated Runway stills and genuine multi-keyframe GIFs via SFTP.

Input: one newly committed external-photo-test-*.json manifest of source URLs.
Never fabricate GIFs with Ken Burns or move the camera over a single still.
Each GIF uses >=3 independently generated source frames of changed human poses.
"""
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

HOST = "ftp.neuroky.me"
VALID_FOLDERS = {
    "do androids dream of erotic feet?",
    "ai macromastia convention and fundraiser",
    "if these artificial women can remember to eat, you can too",
    "if these artificial women can remember to do drugs, you can too",
}
VALID_NAME = re.compile(r"20\d{2}-\d{2}-\d{2}_[a-z0-9_-]+\.(png|jpg|jpeg|webp|gif)\Z")
MAX = 32_000_000

def fetch(url):
    if not url.startswith("https://"):
        raise ValueError("Source must be HTTPS")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Archive photo uploader)"})
    with urllib.request.urlopen(req, timeout=110) as resp:
        out = resp.read(MAX + 1)
    if not out or len(out) > MAX:
        raise ValueError("Source empty or over 32 MB")
    return out

def render_gif(frame_urls):
    if len(frame_urls) < 3:
        raise ValueError("Animation requires >=3 different originally generated poses")
    source_images = []
    for url in frame_urls:
        raw = fetch(url)
        with Image.open(io.BytesIO(raw)) as im:
            rgb = im.convert("RGB")
            rgb.thumbnail((1000, 1100), Image.Resampling.LANCZOS)
            source_images.append(rgb.copy())
    w = min(x.width for x in source_images)
    h = min(x.height for x in source_images)
    frames = [x.resize((w, h), Image.Resampling.LANCZOS) for x in source_images]
    # 3 separate independently generated human poses in a forward/reverse sequence.
    # This is frame animation, NOT a cropped or panned single-image animation.
    frames = frames + list(reversed(frames[1:-1]))
    hashes = {hashlib.sha256(x.tobytes()).digest() for x in frames}
    if len(hashes) < 3:
        raise ValueError("Not enough genuinely different source frames for GIF")
    frames = [im.quantize(colors=220, method=Image.Quantize.FASTOCTREE) for im in frames]
    out = io.BytesIO()
    frames[0].save(out, format="GIF", save_all=True, append_images=frames[1:],
                  duration=420, loop=0, optimize=False, disposal=2)
    raw = out.getvalue()
    with Image.open(io.BytesIO(raw)) as check:
        if check.n_frames < 3:
            raise ValueError("Rendered GIF unexpectedly not animated")
        unique = {hashlib.sha256(fr.convert("RGB").tobytes()).hexdigest()
                  for fr in ImageSequence.Iterator(check)}
        if len(unique) < 3:
            raise ValueError("GIF has fewer than 3 distinct frames")
    print(f"GENUINE_GIF: source_poses={len(frame_urls)} frames={len(frames)} unique={len(unique)} bytes={len(raw)}", flush=True)
    return raw

def read_media(item):
    name = item["name"]
    if not VALID_NAME.fullmatch(name):
        raise ValueError("Invalid filename: " + name)
    if name.endswith(".gif"):
        raw = render_gif(item["frames"])
    else:
        raw = fetch(item["url"])
        with Image.open(io.BytesIO(raw)) as im:
            if im.format not in {"PNG", "JPEG", "WEBP"}:
                raise ValueError("Not a legitimate source photograph")
            print(f"ORIGINAL_PHOTO: {name} {im.size[0]}x{im.size[1]} format={im.format} bytes={len(raw)}", flush=True)
    return raw

def remote_hash(sftp, path):
    h = hashlib.sha256()
    with sftp.file(path, "rb") as f:
        while True:
            block = f.read(262144)
            if not block:
                break
            h.update(block)
    return h.hexdigest()

def put(sftp, item, data):
    folder = item["folder"]
    if folder not in VALID_FOLDERS:
        raise ValueError("Unknown archive directory: " + folder)
    try:
        s = sftp.stat(folder)
        if not stat.S_ISDIR(s.st_mode):
            raise ValueError("Not a directory: " + folder)
    except FileNotFoundError:
        sftp.mkdir(folder)
        print("CREATED_FOLDER:", folder, flush=True)
    path = folder + "/" + item["name"]
    digest = hashlib.sha256(data).hexdigest()
    try:
        old = sftp.stat(path)
    except FileNotFoundError:
        old = None
    if old:
        if old.st_size != len(data):
            raise ValueError("Existing conflicting filename: " + path)
        print("EXISTS_SIZE_MATCH:", path, flush=True)
    else:
        with sftp.file(path, "wb") as f:
            f.write(data)
            f.flush()
        print("UPLOADED:", path, flush=True)
    actual = sftp.stat(path).st_size
    if actual != len(data):
        raise ValueError("SFTP size verification failed: " + path)
    print("VERIFIED_SIZE:", "https://" + HOST + "/" + urllib.parse.quote(path, safe="/"),
          "bytes:", actual, "local_sha256:", digest, flush=True)
    return path, digest

def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: upload_external_photo_test.py FILE.json")
    obj = json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
    items = obj["items"]
    if not (1 <= len(items) <= 30):
        raise ValueError("Invalid number of media items")
    seen = set()
    prepped = []
    for item in items:
        name = item["name"]
        key = item["folder"] + "/" + name
        if key in seen:
            raise ValueError("Duplicate destination: " + key)
        seen.add(key)
        raw = read_media(item)
        prepped.append((item, raw))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(HOST, port=22, username="anonymous",
                    pkey=paramiko.RSAKey.generate(2048),
                    look_for_keys=False, allow_agent=False,
                    timeout=35, auth_timeout=35, banner_timeout=35)
        with ssh.open_sftp() as sftp:
            uploaded = [put(sftp, item, data) for item, data in prepped]
            # Hash verification may be locked until the same public key uploads >=1 MB.
            if uploaded:
                try:
                    path, digest = uploaded[0]
                    if remote_hash(sftp, path) != digest:
                        raise RuntimeError("Remote SHA256 mismatch: " + path)
                    print("VERIFIED_SHA256:", path, flush=True)
                except PermissionError:
                    print("SHA256_LOCKED: remote read not allowed for this fresh public key", flush=True)
                except OSError as e:
                    print("SHA256_UNAVAILABLE:", str(e), flush=True)
    finally:
        ssh.close()
    print("COMPLETE:", len(prepped), "remote media files size-verified", flush=True)

if __name__ == "__main__":
    main()
