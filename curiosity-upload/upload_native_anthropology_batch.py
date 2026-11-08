#!/usr/bin/env python3
"""Upload verified, high-quality native ChatGPT images to 24 independent archive folders.

Manifest: curiosity-upload/anthropology-native-batch-*.json
Parts: staging-anthropology/*.b64.partNN; each base64-aligned, no resizing or recompression.
SFTP uses a fresh ephemeral public key, with upload-first contributor gating.
"""
import base64, hashlib, io, json, pathlib, re, stat, sys, urllib.parse

import paramiko
from PIL import Image

HOST = "ftp.neuroky.me"
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
    "married to her artificial sea",
    "Artificial Moms Are Proud Of You",
    "Artificial Women Notice You From Across The Room",
    "Artificial Women Feel Uncomfortable and Want To Go Home",
    "candid monstress",
    "Artificial Women Are In Love with Art",
    "Artificial Women Are In Love with Artless Smut",
}
NAME = re.compile(r"20\d\d-\d\d-\d\d_[A-Za-z0-9_-]+\.(png|jpe?g|webp|gif)\Z")
def data_for(item):
    if item["folder"] not in ALLOWED:
        raise ValueError("Invalid archive folder: "+item["folder"])
    name=item["name"]
    if not NAME.fullmatch(name):
        raise ValueError("Invalid output filename: "+name)
    paths=item.get("parts") or [item["source"]]
    if not 1<=len(paths)<=80:
        raise ValueError("Invalid parts count for "+name)
    seg=[]
    for s in paths:
        p=pathlib.Path(s)
        if p.is_absolute() or ".." in p.parts or not str(p).startswith("staging-anthropology/"):
            raise ValueError("Invalid staged part: "+s)
        absolute=(ROOT/p).resolve()
        if not absolute.is_relative_to(ROOT):
            raise ValueError("Path escapes repository")
        seg.append("".join(absolute.read_text("ascii").split()))
    raw=base64.b64decode("".join(seg), validate=True)
    if len(raw)!=int(item["bytes"]):
        raise ValueError("Byte count differs for "+name)
    digest=hashlib.sha256(raw).hexdigest()
    if digest!=item["sha256"]:
        raise ValueError("SHA256 differs for "+name)
    with Image.open(io.BytesIO(raw)) as im:
        fmt=im.format
        if name.endswith((".jpg",".jpeg")) and fmt!="JPEG":
            raise ValueError("JPEG bytes invalid for "+name)
        if name.endswith(".png") and fmt!="PNG":
            raise ValueError("PNG bytes invalid")
        if name.endswith(".webp") and fmt!="WEBP":
            raise ValueError("WEBP bytes invalid")
        if name.endswith(".gif") and (fmt!="GIF" or getattr(im,"n_frames",1)<2):
            raise ValueError("Expected animated GIF")
        print("VALIDATED_NATIVE:",name,"size:",im.size,"format:",fmt,"bytes:",len(raw),"sha256:",digest,flush=True)
    return item,raw,digest
def remote_sha256(sftp,path):
    h=hashlib.sha256()
    with sftp.file(path,"rb") as f:
        while True:
            chunk=f.read(262144)
            if not chunk:break
            h.update(chunk)
    return h.hexdigest()
def main():
    job=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
    items=job["items"]
    if not 1<=len(items)<=30:
        raise ValueError("Unsupported number of media items")
    if len({i["folder"]+"/"+i["name"] for i in items})!=len(items):
        raise ValueError("Duplicate paths")
    prepared=[data_for(i) for i in items]
    ssh=paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(HOST,port=22,username="anonymous",pkey=paramiko.RSAKey.generate(2048),
                    look_for_keys=False,allow_agent=False,timeout=35,auth_timeout=35,banner_timeout=35)
        with ssh.open_sftp() as sftp:
            uploaded=[]
            for item,raw,digest in prepared:
                folder=item["folder"]
                try:
                    directory=sftp.stat(folder)
                    if not stat.S_ISDIR(directory.st_mode):
                        raise ValueError("Not a remote folder: "+folder)
                except FileNotFoundError:
                    sftp.mkdir(folder)
                    print("CREATED_FOLDER:",folder,flush=True)
                dest=folder+"/"+item["name"]
                try:
                    prior=sftp.stat(dest)
                except FileNotFoundError:
                    prior=None
                if prior is None:
                    with sftp.file(dest,"wb") as f:
                        f.write(raw)
                        f.flush()
                    print("UPLOADED:",dest,flush=True)
                elif prior.st_size!=len(raw):
                    raise RuntimeError("Conflicting existing file: "+dest)
                else:
                    print("ALREADY_PRESENT_SIZE_MATCH:",dest,flush=True)
                size=sftp.stat(dest).st_size
                if size!=len(raw):
                    raise RuntimeError("Remote size mismatch: "+dest)
                print("VERIFIED_SIZE: https://"+HOST+"/"+urllib.parse.quote(dest,safe="/"),
                      "bytes:",size,"local_sha256:",digest,flush=True)
                uploaded.append((dest,digest))
            try:
                path,digest=uploaded[0]
                if remote_sha256(sftp,path)!=digest:
                    raise RuntimeError("Remote SHA256 mismatch: "+path)
                print("VERIFIED_SHA256:",path,digest,flush=True)
            except PermissionError:
                print("REMOTE_READ_LOCKED: sizes independently verified but hash read denied",flush=True)
    finally:
        ssh.close()
    print("NATIVE_ANTHROPOLOGY_BATCH_COMPLETE:",len(uploaded),"/",len(prepared),"images remote-size-verified",flush=True)
if __name__=="__main__":
    main()
