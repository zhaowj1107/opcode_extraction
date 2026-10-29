"""Summarize a run, sanity-check the .cat files, and optionally pack them for hand-off."""
import argparse
import csv
import socket
import zipfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hash-list", type=Path, nargs="+", required=True)
    ap.add_argument("--work-dir", type=Path, default=HERE / "work")
    ap.add_argument("--shard", default="1/1")
    ap.add_argument("--pack", action="store_true", help="zip the .cat files and status CSVs for hand-off")
    args = ap.parse_args()

    shard_i, shard_n = (int(x) for x in args.shard.split("/"))
    hashes, seen = [], set()
    for path in args.hash_list:
        for h in path.read_text().split():
            h = h.strip().upper()
            if h and h not in seen:
                seen.add(h)
                hashes.append(h)
    hashes = [h for idx, h in enumerate(hashes) if idx % shard_n == shard_i - 1]

    cats, logs = args.work_dir / "cats", args.work_dir / "logs"
    latest = {}
    for status_csv in sorted(logs.glob("status_*.csv")):
        with status_csv.open(newline="") as f:
            for row in csv.DictReader(f):
                latest[row["sha256"]] = row

    signature, bad = Counter(), []
    have = [h for h in hashes if (cats / f"{h}.cat").is_file()]
    for h in have:
        text = (cats / f"{h}.cat").read_text()
        if not text:
            bad.append((h, "empty"))
        elif "N" in text:
            # The apktool extractor never emits N; N means an androguard-style file.
            bad.append((h, "contains N (wrong extractor)"))
        signature["has X" if "X" in text else "no X"] += 1

    missing = [h for h in hashes if h not in set(have)]
    reasons = Counter(latest[h]["status"] if h in latest else "not attempted" for h in missing)
    print(f"shard {shard_i}/{shard_n}: expected={len(hashes)} cat_ok={len(have)} missing={len(missing)}")
    print(f"missing by last status: {dict(reasons)}")
    print(f".cat signature: {dict(signature)}  problems: {len(bad)}")
    for h, why in bad[:20]:
        print(f"  {h}: {why}")
    missing_path = args.work_dir / f"missing_shard{shard_i}of{shard_n}.txt"
    missing_path.write_text("\n".join(missing) + ("\n" if missing else ""))
    print(f"missing hashes written to {missing_path}")

    if args.pack:
        out = args.work_dir / f"cats_{socket.gethostname()}_shard{shard_i}of{shard_n}.zip"
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for h in have:
                zf.write(cats / f"{h}.cat", f"cats/{h}.cat")
            for status_csv in logs.glob("status_*.csv"):
                zf.write(status_csv, f"logs/{status_csv.name}")
            zf.write(missing_path, missing_path.name)
        print(f"packed {len(have)} .cat files into {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
