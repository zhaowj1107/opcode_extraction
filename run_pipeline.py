"""Download APKs from AndroZoo and extract 17-category opcode sequences (.cat).

Each worker streams one APK at a time: download -> verify SHA-256 ->
apktool/baksmali smali -> symbols via the unmodified opcode_extraction_17cat
parsing/mapping -> write <SHA256>.cat -> delete the APK. Only .cat files and a
status CSV are kept. Re-running resumes; failed hashes are retried.
"""
import argparse
import csv
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
AZ_URL = "https://androzoo.uni.lu/api/download"
STATUS_FIELDS = ["sha256", "status", "seconds", "apk_bytes", "symbols", "error"]
TERMINAL = {"ok", "not_found"}
IS_WINDOWS = os.name == "nt"


def read_key(path: Path) -> str:
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line.split("=", 1)[1].strip() if "=" in line else line
    raise ValueError(f"no key in {path}")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest().upper()


def load_hashes(paths: list[Path]) -> list[str]:
    seen, ordered = set(), []
    for path in paths:
        for h in path.read_text().split():
            h = h.strip().upper()
            if h and h not in seen:
                seen.add(h)
                ordered.append(h)
    return ordered


def download(sha: str, dest: Path, key: str) -> None:
    # Never put the request URL in an error message: it contains the API key.
    for attempt in range(4):
        try:
            with requests.get(AZ_URL, params={"apikey": key, "sha256": sha}, stream=True, timeout=600) as r:
                if r.status_code == 404:
                    raise FileNotFoundError("not in AndroZoo")
                if r.status_code in (401, 403):
                    raise PermissionError(f"AndroZoo HTTP {r.status_code}: API key rejected")
                if r.status_code != 200:
                    raise IOError(f"AndroZoo HTTP {r.status_code}")
                with dest.open("wb") as f:
                    for chunk in r.iter_content(1 << 20):
                        f.write(chunk)
            if sha256_of(dest) == sha:
                return
            raise IOError("sha256 mismatch")
        except (FileNotFoundError, PermissionError):
            raise
        except Exception as exc:
            if attempt == 3:
                raise IOError(f"download failed: {type(exc).__name__}: {str(exc)[:80]}") from None
            time.sleep(30 * (attempt + 1))


def install_wrappers(tools: Path) -> str:
    """Expose the jars as `apktool` / `baksmali` commands, as the extractor expects."""
    for name in ("apktool", "baksmali"):
        jar = tools / f"{name}.jar"
        if not jar.is_file():
            sys.exit(f"ERROR: {jar} missing; run `python setup_tools.py` first.")
        if IS_WINDOWS:
            (tools / f"{name}.bat").write_text(f'@java -Xmx4g -jar "{jar}" %*\r\n')
        else:
            script = tools / name
            script.write_text(f'#!/bin/sh\nexec java -Xmx4g -jar "{jar}" "$@"\n')
            script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    os.environ["PATH"] = f"{tools}{os.pathsep}{os.environ['PATH']}"
    return "apktool.bat" if IS_WINDOWS else "apktool"


def long_path(path: str) -> str:
    # Obfuscated apps produce smali paths beyond Windows' 260-char limit.
    if IS_WINDOWS and not path.startswith("\\\\?\\"):
        return "\\\\?\\" + os.path.abspath(path)
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hash-list", type=Path, nargs="+", required=True)
    ap.add_argument("--key-file", type=Path, required=True, help="file with your own AndroZoo API key")
    ap.add_argument("--work-dir", type=Path, default=HERE / "work")
    ap.add_argument("--tools-dir", type=Path, default=HERE / "tools")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--shard", default="1/1", help="i/n: process every n-th hash starting at i (e.g. 2/4)")
    ap.add_argument("--limit", type=int, help="process at most this many hashes (for a test run)")
    args = ap.parse_args()

    shard_i, shard_n = (int(x) for x in args.shard.split("/"))
    if not 1 <= shard_i <= shard_n:
        ap.error("--shard must be i/n with 1 <= i <= n")
    key = read_key(args.key_file)
    work = args.work_dir.resolve()
    cats, staging, tmp_root, logs = work / "cats", work / "staging", work / "tmp", work / "logs"
    for d in (cats, staging, tmp_root, logs):
        d.mkdir(parents=True, exist_ok=True)

    apktool = install_wrappers(args.tools_dir.resolve())
    os.environ["TMP"] = os.environ["TEMP"] = os.environ["TMPDIR"] = str(tmp_root)
    tempfile.tempdir = str(tmp_root)
    sys.path.insert(0, str(HERE))
    os.chdir(logs)  # opcode_extraction_17cat writes apk_processing.log into the cwd
    import opcode_extraction_17cat as ext

    ext.logger.setLevel("WARNING")
    original_extract = ext.extract_dex_to_temp

    def extract_dex_to_temp(apk_path, max_retries=3, use_memory_opts=True):
        # Resources do not affect smali, so skip decoding them first; otherwise fall
        # back to the original apktool/baksmali sequence (minus the POSIX-only
        # JAVA_OPTS prefix, which the wrappers replace with -Xmx4g).
        temp_dir = tempfile.mkdtemp(prefix="smali_")
        try:
            result = subprocess.run([apktool, "d", "-r", "-f", str(apk_path), "-o", temp_dir],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900)
            if result.returncode == 0 and any(n.startswith("smali") for n in os.listdir(temp_dir)):
                return long_path(temp_dir)
        except subprocess.TimeoutExpired:
            pass
        shutil.rmtree(long_path(temp_dir), ignore_errors=True)
        fallback = original_extract(apk_path, max_retries=max_retries, use_memory_opts=False)
        return long_path(fallback) if fallback else None

    ext.extract_dex_to_temp = extract_dex_to_temp

    hashes = load_hashes(args.hash_list)
    hashes = [h for idx, h in enumerate(hashes) if idx % shard_n == shard_i - 1]
    status_path = logs / f"status_shard{shard_i}of{shard_n}.csv"
    done = set()
    if status_path.is_file():
        with status_path.open(newline="") as f:
            done = {r["sha256"] for r in csv.DictReader(f) if r["status"] in TERMINAL}
    todo = [h for h in hashes if h not in done and not (cats / f"{h}.cat").is_file()]
    if args.limit:
        todo = todo[: args.limit]
    print(f"shard {shard_i}/{shard_n}: hashes={len(hashes)} todo={len(todo)} work_dir={work}", flush=True)

    lock, stop = threading.Lock(), threading.Event()
    new_file = not status_path.is_file()
    status_f = status_path.open("a", newline="")
    writer = csv.DictWriter(status_f, fieldnames=STATUS_FIELDS)
    if new_file:
        writer.writeheader()

    def process(sha: str) -> str:
        if stop.is_set():
            return "skipped"
        started = time.monotonic()
        apk = staging / f"{sha}.apk"
        row = {"sha256": sha, "status": "ok", "apk_bytes": "", "symbols": "", "error": ""}
        try:
            download(sha, apk, key)
            row["apk_bytes"] = apk.stat().st_size
            symbols = ext.process_apk_to_symbols(str(apk))
            if not symbols:
                raise ValueError("opcode extraction failed")
            row["symbols"] = len(symbols)
            part = cats / f"{sha}.cat.part"
            part.write_text("".join(symbols))
            os.replace(part, cats / f"{sha}.cat")
        except FileNotFoundError as exc:
            row.update(status="not_found", error=str(exc))
        except PermissionError as exc:
            stop.set()
            row.update(status="auth_error", error=str(exc))
        except Exception as exc:
            row.update(status="failed", error=f"{type(exc).__name__}: {exc}"[:300])
        finally:
            apk.unlink(missing_ok=True)
        row["seconds"] = f"{time.monotonic() - started:.1f}"
        with lock:
            writer.writerow(row)
            status_f.flush()
        return row["status"]

    tally: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(process, h) for h in todo]
        for i, fut in enumerate(as_completed(futures), 1):
            s = fut.result()
            tally[s] = tally.get(s, 0) + 1
            if i % 25 == 0 or i == len(todo):
                print(f"{time.strftime('%H:%M:%S')} {i}/{len(todo)} {tally}", flush=True)
    status_f.close()
    if stop.is_set():
        print("STOPPED: AndroZoo rejected the API key. Check your key file and rerun.")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
