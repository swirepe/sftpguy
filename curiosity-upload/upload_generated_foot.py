#!/usr/bin/env python3
"""Upload generated feet photos/GIFs using sftpguy's HTTP explorer."""
import base64
import http.cookiejar
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

from uploader import BASE, existing_file, upload_one


def verify_remote(opener, destination, expected_bytes):
    url = BASE + "/" + urllib.parse.quote(destination, safe="/")
    req = urllib.request.Request(url, method="HEAD")
    with opener.open(req, timeout=40) as resp:
        size = resp.headers.get("Content-Length")
        if resp.status != 200 or (size is not None and int(size) != expected_bytes):
            raise RuntimeError("Remote file missing or size mismatch: " + url)
    print("VERIFIED:", url, "bytes:", expected_bytes, flush=True)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: upload_generated_foot.py FILE.b64 DESTINATION")
    b64_path, destination = sys.argv[1:]
    folder = "do androids dream of erotic feet?"
    if not destination.startswith(folder + "/"):
        raise RuntimeError("Unexpected archive destination: " + destination)
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
        raise RuntimeError("Media bytes do not match supported extension: " + ext)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.cookiejar = jar
    if existing_file(opener, destination):
        verify_remote(opener, destination, len(data))
        print("SKIPPED already archived:", destination, flush=True)
        return
    try:
        upload_one(opener, destination, data)
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
        # The explorer can save successfully, then emit a redirect containing a
        # literal question mark. urllib follows that broken redirect to a 404.
        # Verify the file rather than mistaking the redirect for an upload failure.
        verify_remote(opener, destination, len(data))
    print("SUCCESS: generated media uploaded and verified at", destination, flush=True)


if __name__ == "__main__":
    main()
