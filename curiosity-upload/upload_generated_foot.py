#!/usr/bin/env python3
"""Upload original-quality photos and GIFs through the archive's open SFTP service."""
import base64
import pathlib
import stat
import sys
import urllib.parse

import paramiko

from uploader import BASE


def upload_sftp(destination, contents):
    folder = "do androids dream of erotic feet?"
    filename = pathlib.PurePosixPath(destination).name
    if not filename or destination != folder + "/" + filename:
        raise RuntimeError("Unexpected target path: " + destination)
    host = urllib.parse.urlsplit(BASE).hostname or "ftp.neuroky.me"
    key = paramiko.RSAKey.generate(2048)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=22, username="anonymous", pkey=key,
            look_for_keys=False, allow_agent=False,
            timeout=35, auth_timeout=35, banner_timeout=35,
        )
        with client.open_sftp() as sftp:
            try:
                info = sftp.stat(folder)
                if not stat.S_ISDIR(info.st_mode):
                    raise RuntimeError("Archive destination exists but is not a directory")
            except FileNotFoundError:
                sftp.mkdir(folder)
            try:
                existing = sftp.stat(destination)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if existing.st_size != len(contents):
                    raise RuntimeError("Remote file exists with unexpected size: " + destination)
                print("SKIPPED existing verified:", destination, flush=True)
            else:
                with sftp.file(destination, "wb") as stream:
                    stream.write(contents)
                    stream.flush()
            observed = sftp.stat(destination)
            if observed.st_size != len(contents):
                raise RuntimeError(
                    "SFTP remote byte count mismatch for " + destination +
                    ": expected " + str(len(contents)) + ", got " + str(observed.st_size)
                )
            url = BASE + "/" + urllib.parse.quote(destination, safe="/")
            print("VERIFIED:", url, "bytes:", len(contents), flush=True)
    finally:
        client.close()


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: upload_generated_foot.py FILE.b64 DESTINATION")
    b64_path, destination = sys.argv[1:]
    data = base64.b64decode("".join(pathlib.Path(b64_path).read_text().split()), validate=True)
    ext = pathlib.Path(destination).suffix.lower()
    tests = {
        ".avif": len(data) >= 12 and data[4:8] == b"ftyp" and b"avif" in data[8:32],
        ".webp": len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP",
        ".png": data.startswith(b"\x89PNG\r\n\x1a\n"),
        ".jpg": data.startswith(b"\xff\xd8\xff"),
        ".jpeg": data.startswith(b"\xff\xd8\xff"),
        ".gif": data.startswith((b"GIF87a", b"GIF89a")),
    }
    if not tests.get(ext, False):
        raise RuntimeError("Media bytes do not match declared extension: " + ext)
    upload_sftp(destination, data)


if __name__ == "__main__":
    main()
