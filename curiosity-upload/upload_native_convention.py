#!/usr/bin/env python3
"""Upload original AI-generated images and *genuinely animated* GIFs to the convention archive.

Unlike previous releases, GIF files are sourced from native multi-frame
animation; no zoom/pan conversion is performed.
"""
import base64
import pathlib
import stat
import sys
import urllib.parse
import paramiko

FOLDER = "ai macromastia convention and fundraiser"
HOST = "ftp.neuroky.me"

def main():
    if len(sys.argv)!=2:
        raise SystemExit("Usage: upload_native_convention.py FILE.png.b64|FILE.gif.b64")
    p = pathlib.Path(sys.argv[1])
    name = p.name
    if not name.endswith((".png.b64",".gif.b64")):
        raise RuntimeError("Only original PNG or animated GIF staging accepted")
    name=name[:-4]
    if not name or "/" in name or "\\" in name:
        raise RuntimeError("Unsafe name")
    data=base64.b64decode("".join(p.read_text(encoding="ascii").split()),validate=True)
    if name.endswith(".png"):
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise RuntimeError("PNG magic mismatch")
    else:
        if not data.startswith((b"GIF87a",b"GIF89a")):
            raise RuntimeError("GIF magic mismatch")
        # Count actual image frames; reject still photos deceptively labeled GIF.
        from PIL import Image
        import io
        im=Image.open(io.BytesIO(data))
        if getattr(im,"n_frames",1)<3:
            raise RuntimeError("GIF contains too few animation frames")
    key=paramiko.RSAKey.generate(2048)
    client=paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    path=FOLDER+"/"+name
    try:
        client.connect(HOST,port=22,username="anonymous",pkey=key,
          look_for_keys=False,allow_agent=False,timeout=35,auth_timeout=35,banner_timeout=35)
        with client.open_sftp() as sftp:
            try:
                folder=sftp.stat(FOLDER)
                if not stat.S_ISDIR(folder.st_mode):
                    raise RuntimeError("The archive destination is not a directory")
            except FileNotFoundError:
                sftp.mkdir(FOLDER)
            try:
                old=sftp.stat(path)
            except FileNotFoundError:
                old=None
            if old is not None and old.st_size!=len(data):
                raise RuntimeError("Refusing overwrite of mismatched existing file: "+path)
            if old is None:
                with sftp.file(path,"wb") as out:
                    out.write(data)
                    out.flush()
            actual=sftp.stat(path).st_size
            if actual != len(data):
                raise RuntimeError(f"Upload integrity check failed: {actual}!={len(data)}")
            url="https://ftp.neuroky.me/"+urllib.parse.quote(path,safe="/")
            print(f"VERIFIED: {url} bytes: {actual}",flush=True)
    finally:
        client.close()

if __name__=="__main__":
    main()
