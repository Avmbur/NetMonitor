"""Build a Linux installation bundle: install.sh and two binaries (run from any directory)."""
import argparse
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", default="go")
    parser.add_argument("--arch", choices=["amd64", "arm64"], default="amd64")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    dest = root / "dist" / ("netmonitor-linux-" + args.arch)
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    env = dict(os.environ, GOOS="linux", GOARCH=args.arch, CGO_ENABLED="0")
    names = []
    for binary in ["nmserver", "nmagent"]:
        name = binary + "-linux-" + args.arch
        subprocess.run([args.go, "build", "-trimpath", "-o", str(dest / name), "./cmd/" + binary],
                       cwd=root, env=env, check=True)
        names.append(name)
    data = (root / "deploy" / "install.sh").read_bytes()
    if b"\r" in data:
        raise SystemExit("CR in install.sh")
    (dest / "install.sh").write_bytes(data)
    names.append("install.sh")
    archive = dest.with_suffix(".tar.gz")
    with tarfile.open(archive, "w:gz") as bundle:
        for name in names:
            path = dest / name
            data = path.read_bytes()
            info = tarfile.TarInfo(dest.name + "/" + name)
            info.size = len(data)
            info.mtime = int(path.stat().st_mtime)
            info.mode = 0o755
            bundle.addfile(info, io.BytesIO(data))
    print(archive)

if __name__ == "__main__":
    main()
