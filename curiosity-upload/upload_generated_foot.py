#!/usr/bin/env python3
"""Upload locally staged, generated media to the archive's exact requested folder."""
import base64
import http.cookiejar
import pathlib
import sys
import urllib.request

from uploader import BASE, existing_file, upload_one

def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: upload_generated_foot.py FILE.b64 DESTINATION")
    b64_path, destination = sys.argv[1:]
    folder = "do androids dream of erotic feet?"
    if not destination.startswith(folder + "/"):
        raise RuntimeError("Unexpected archive destination: " + destination)
    data = base64.b64decode(pathlib.Path(b64_path).read_text().strip(), validate=True)
    if not (data[:4] == b"RIFF" and data[8:12] == b"WEBP"):
        raise RuntimeError("Expected actual WebP bytes")
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.cookiejar = jar
    if existing_file(opener, destination):
        print("SKIPPED existing:", destination)
        return
    upload_one(opener, destination, data)
    print("SUCCESS: generated image uploaded and verified at", BASE + "/" + destination)

if __name__ == "__main__":
    main()
