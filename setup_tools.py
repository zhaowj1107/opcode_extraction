"""Download the pinned apktool and baksmali jars into ./tools and verify them."""
import argparse
import hashlib
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

TOOLS = {
    "apktool.jar": (
        "https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar",
        "7956EB04194300CE0D0A84AD18771EEBC94B89FB8D1DDCCE8EA4C056818646F4",
    ),
    "baksmali.jar": (
        "https://bitbucket.org/JesusFreke/smali/downloads/baksmali-2.5.2.jar",
        "D3116248CCE4F82EC5A31EB7F95EE75DAFF42DDF6EED0AB573973DC53FBAD2E5",
    ),
}


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tools-dir", type=Path, default=Path(__file__).resolve().parent / "tools")
    args = ap.parse_args()

    if shutil.which("java") is None:
        print("ERROR: java not found on PATH (Java 8+ is required by apktool).")
        return 1
    args.tools_dir.mkdir(parents=True, exist_ok=True)
    for name, (url, expected) in TOOLS.items():
        dest = args.tools_dir / name
        if not dest.is_file() or sha256_of(dest) != expected:
            print(f"downloading {name} ...")
            urllib.request.urlretrieve(url, dest)
        actual = sha256_of(dest)
        if actual != expected:
            dest.unlink()
            print(f"ERROR: {name} checksum mismatch ({actual})")
            return 1
        print(f"{name}: OK")
    for name in TOOLS:
        out = subprocess.run(["java", "-jar", str(args.tools_dir / name), "--version"],
                             capture_output=True, text=True)
        print(f"{name} --version: {(out.stdout or out.stderr).splitlines()[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
