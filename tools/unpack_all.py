#!/usr/bin/env python3
"""Unpack a directory of ASPack-packed plugins in one process.

    tools/unpack_all.py <plugin-dir>

Writes one loadable PE per plugin into ./unpacked/.  The plugin directory is a
copy of a third-party tool's plugin set, so it is not part of this repository;
supply your own copy.
"""
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unaspack

src = sys.argv[1] if len(sys.argv) > 1 else "."
files = sorted(glob.glob(os.path.join(src, "*.dll")))
if not files:
    sys.exit(f"no .dll plugins found in {src!r}")

out = "unpacked"
os.makedirs(out, exist_ok=True)
for f in files:
    dst = os.path.join(out, os.path.basename(f))
    try:
        oep, img, pe = unaspack.unpack(f, dst, quiet=True)
        print(f"{os.path.basename(f)} OEP=0x{oep:08x}", flush=True)
    except Exception as e:
        print(f"{os.path.basename(f)} ERR {e}", flush=True)