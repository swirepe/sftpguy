#!/usr/bin/env python3
"""Fetch 10 original-resolution event stills and produce 2 short original-frame animated GIFs, uploading all by SFTP."""
import io, json, pathlib, re, stat, sys, urllib.request, urllib.parse
from PIL import Image, ImageEnhance, ImageFilter
import paramiko

HOST = "ftp.neuroky.me"
FOLDER = "ai macromastia convention and fundraiser"

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; CuriosityArchive/1.0)"})
    with urllib.request.urlopen(req, timeout=90) as response:
        data = response.read()
    if not (data.startswith(b"\x89PNG\r\n\x1a\n") or data.startswith(b"\xff\xd8\xff")):
        raise RuntimeError("Image download does not contain PNG/JPEG bytes")
    return data

def gif_from_original(data, direction=1):
    with Image.open(io.BytesIO(data)) as original:
        source = original.convert("RGB")
    w, h = source.size
    target_w = min(w, 1024)
    target_h = round(target_w * h / w)
    frames = []
    for i in range(18):
        t = i / 17
        zoom = 1.045 + .045*t
        sw, sh = int(w/zoom), int(h/zoom)
        cx = int((w-sw) * (.35 + .3*t if direction > 0 else .65 - .3*t))
        cy = int((h-sh) * (.3 + .25*t))
        frame = source.crop((cx, cy, cx+sw, cy+sh)).resize((target_w,target_h), Image.Resampling.LANCZOS)
        frames.append(frame.quantize(colors=192, method=Image.Quantize.MEDIANCUT))
    bio=io.BytesIO()
    frames[0].save(bio,format="GIF",save_all=True,append_images=frames[1:],duration=130,loop=0,optimize=True,disposal=2)
    result=bio.getvalue()
    if not result.startswith(b"GIF8"):
        raise RuntimeError("GIF encoding failed")
    return result

def upload(sftp, name, data):
    destination=FOLDER+"/"+name
    try:
        st=sftp.stat(destination)
    except FileNotFoundError:
        st=None
    if st is not None and st.st_size != len(data):
        raise RuntimeError(f"Refusing to overwrite mismatched remote file {destination}")
    if st is None:
        with sftp.file(destination,"wb") as fp:
            fp.write(data)
            fp.flush()
    actual=sftp.stat(destination).st_size
    if actual != len(data):
        raise RuntimeError(f"Remote size mismatch: {destination}: {actual} vs {len(data)}")
    print("VERIFIED:", "https://ftp.neuroky.me/"+urllib.parse.quote(destination,safe="/"),"bytes:",actual,flush=True)

def main():
    manifest=json.loads(pathlib.Path(sys.argv[1]).read_text())
    items=manifest["photos"]
    release_id=manifest.get("release_id",manifest.get("date","release"))
    if not re.fullmatch(r"[A-Za-z0-9_-]{4,90}",release_id):
        raise RuntimeError("Invalid release_id")
    if len(items) not in (8, 10):
        raise RuntimeError("Expected 8 distinct images (or 10 for legacy releases)")
    names=[i["filename"] for i in items]
    if len(set(names))!=10 or any("/" in n or "\\" in n or not n.endswith(".png") for n in names):
        raise RuntimeError("Invalid or duplicate filenames")
    original=[]
    for idx,item in enumerate(items):
        print(f"Downloading still {idx+1}/{len(items)}",flush=True)
        original.append(fetch(item["url"]))
    gifs=[
      (f"{release_id}_convention_opening_candid_pan.gif",gif_from_original(original[0],1)),
      (f"{release_id}_charity_luncheon_candid_pan.gif",gif_from_original(original[2],-1)),
    ]
    key=paramiko.RSAKey.generate(2048)
    ssh=paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(HOST,port=22,username="anonymous",pkey=key,look_for_keys=False,allow_agent=False,timeout=35,auth_timeout=35,banner_timeout=35)
        with ssh.open_sftp() as sftp:
            try:
                st=sftp.stat(FOLDER)
                if not stat.S_ISDIR(st.st_mode):
                    raise RuntimeError("Archive folder exists but is not a directory")
            except FileNotFoundError:
                sftp.mkdir(FOLDER)
            for item,data in zip(items,original):
                upload(sftp,item["filename"],data)
            for name,data in gifs:
                upload(sftp,name,data)
    finally:
        ssh.close()
    print(f"CONVENTION COMPLETE: verified {len(items)} photos and 2 animated GIFs.",flush=True)

if __name__=="__main__":
    main()
