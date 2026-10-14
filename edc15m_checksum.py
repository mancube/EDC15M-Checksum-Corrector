#!/usr/bin/env python3
"""
Checksum corrector for Bosch EDC15M calibration data ("TDI V3.1" algorithm).

Algorithm and layout recovered from one plugin of a 57-file set belonging to a
third-party Windows checksum tool; that plugin identifies itself as
"Bosch TDI V3.1".  See docs/REVERSE-ENGINEERING.md.

The flash is split into 32 kB blocks.  A block that carries a calibration
checksum repeats a 2-byte id at block+0xB7A and the same id immediately in
front of the checksum.  The checksum is a 32-bit little-endian value covering
the range [block + 0xB80, checksum_position):

    256 kB full read : checksum at 0x3FBFC, covers [0x38B80, 0x3FC00)
     32 kB partial    : checksum at 0x7BFC,  covers [0x0B80, 0x7C00)

A full read has a second checksum with fixed geometry, over the code area:

    256 kB full read : checksum at 0x13FFC, covers [0x10000, 0x14000)

Both use the same seeded 16-bit rolling algorithm with different seeds.

The original tool only recognised a block via a C3 3C 55 AA marker, which does
not exist in a 32 kB partial read, so partial files were left untouched.  Here
the block is found by its id pair, which works for both sizes.

usage:  edc15m_checksum.py [-i] [-c] FILE...
          -i              fix in place (default: write FILE with .fixed before
                          its extension, e.g. tune.fixed.bin)
          -c              check only; exit status 1 if any checksum is wrong
          --selftest [FILE]   run the built-in self-test, optionally also
                              verifying FILE
"""
import os
import sys

BLOCK = 0x8000          # block size, also the step of the block scan
ID_OFF = 0xB7A          # offset of the 2-byte block id inside a block
SLOT_LO = 0x7000        # earliest checksum slot inside a block
SLOT_STEP = 0x80
CS_START = 0xB80        # a checksum covers from block + CS_START
FULL_SIZE = 0x40000     # a full 256 kB read
M16 = 0xFFFF

# (h at entry, g at entry, subtracted from h, xored into g)
CAL_SEEDS = (0x8631, 0xEFCD, 0x8631, 0xDF9B)     # calibration block
CODE_SEEDS = (0x0000, 0x0000, 0x8631, 0xDF9B)    # code block

# A second, fixed-geometry block in a full read: the code area. The original
# plugin carries this for a different EDC15M signature, and its own scan path
# does not reach it, but the field is valid here and changes when the code area
# does. Only applied once the calibration block has been recognised, so a
# foreign file is never written to.
CODE_BLOCK = (0x10000, 0x14000, 0x13FFC, CODE_SEEDS)

# a blank word is an unwritten or padded location, not a stale checksum
ERASED = (0xFFFFFFFF, 0x00000000)


def _has_checksum(buf, pos):
    return int.from_bytes(buf[pos:pos + 4], "little") not in ERASED

# regression vector: lcg buffer, see edc15m_checksum.py --selftest
VECTOR_SEED = 0x12345678
VECTOR_LEN = 0x8000
VECTOR_CHECKSUM = 0x007BC5EB          # calibration block over [0x0B80, 0x7C00)
CODE_VECTOR_LEN = 0x14000
CODE_VECTOR_CHECKSUM = 0x2477887F    # code block over [0x10000, 0x14000)


def _rol(v, n):
    n &= 0xF
    return ((v << n) | (v >> (16 - n))) & M16 if n else v


def _ror(v, n):
    n &= 0xF
    return ((v >> n) | (v << (16 - n))) & M16 if n else v


def checksum(buf, start, end, seeds=CAL_SEEDS):
    """32-bit EDC15M TDI V3.1 checksum over buf[start:end]."""
    h_in, g_in, h_out, g_out = seeds
    h, g = h_in, g_in
    p = start
    q = start & M16
    if (q >> 15) == 1:
        q = (q - 0x8000) & M16
    elif q == 0:
        q = (q + 0x8000) & M16
    last = end - 4
    while True:
        h = (h ^ (buf[p] | (buf[p + 1] << 8))) & M16
        p += 2
        q = (q + 2) & M16
        flag = 0
        if g & 0xF:
            h = _rol(h, g & 0xF)
            flag = h & 1
        g = (g - (buf[p] | (buf[p + 1] << 8)) - flag) & M16
        p += 2
        q = (q + 2) & M16
        g = (g ^ h) & M16
        if p == last:
            break
        h = (h - (buf[p] | (buf[p + 1] << 8))) & M16
        p += 2
        q = (q + 2) & M16
        h = (q + h - 1) & M16
        g ^= buf[p] | (buf[p + 1] << 8)
        p += 2
        q = (q + 2) & M16
        if h & 0xF:
            g = _ror(g, h & 0xF)
        if p == last:
            break
    h = (h - h_out) & M16
    return ((q + h + 1) & M16) | (((g ^ g_out) & M16) << 16)


MARKER = b"\xc3\x3c\x55\xaa"  # block tag the original tool keys the id on


def _find_marker(buf):
    """0x100-aligned block tag; the two bytes after it are the reference id."""
    n = len(buf)
    for m in range(0, n - 0x100, 0x100):
        if buf[m:m + 4] == MARKER and m + 0x3FFC < n:
            return m
    return None


def _slot(buf, base, key):
    """Yield the checksum slot of one block, if it has one."""
    if key[0] == key[1]:
        return                      # a repeated byte is filler, not a block id
    for slot in range(base + SLOT_LO, base + BLOCK + 1, SLOT_STEP):
        if buf[slot - 6:slot - 4] == key:
            yield slot - 4, base + CS_START, slot, CAL_SEEDS
            return


def find_checksums(buf):
    """Yield (offset, start, end, seeds) per checksum.

    The calibration block is located by its 2-byte id, the way the original tool
    does it: normally keyed off a tagged block, and for a 32 kB partial read -
    which has no tag - off the id the last block carries itself. A full read
    Additionally gets the fixed-geometry code block, once the calibration block
    has been recognised so that a foreign file is never written to. That block
    is skipped when its field is blank: a 32 kB read padded out to 256 kB has
    no code area at all, and blank flash is not a checksum that went stale.
    """
    n = len(buf)
    blocks = list(range(0, n // BLOCK * BLOCK, BLOCK))   # complete blocks only
    if not blocks:
        return
    marker = _find_marker(buf)
    if marker is not None:
        key = bytes(buf[marker + 0x3FFA:marker + 0x3FFC])
        found = [hit for base in blocks
                 if buf[base + ID_OFF:base + ID_OFF + 2] == key
                 for hit in _slot(buf, base, key)]
    else:
        base = blocks[-1]
        found = list(_slot(buf, base, bytes(buf[base + ID_OFF:base + ID_OFF + 2])))
    if found and n == FULL_SIZE:
        start, end, pos, seeds = CODE_BLOCK
        if _has_checksum(buf, pos):
            found.append((pos, start, end, seeds))
    yield from found


def analyse(buf):
    """Per-checksum-block detail, in file order."""
    return [{"pos": pos, "start": start, "end": end,
             "stored": int.from_bytes(buf[pos:pos + 4], "little"),
             "computed": checksum(buf, start, end, seeds)}
            for pos, start, end, seeds in find_checksums(buf)]


def process(buf, fix):
    """Return (n_ok, n_mismatch); patch buf in place when fix is True."""
    ok = bad = 0
    for b in analyse(buf):
        if b["stored"] == b["computed"]:
            ok += 1
        else:
            bad += 1
            if fix:
                buf[b["pos"]:b["pos"] + 4] = b["computed"].to_bytes(4, "little")
    return ok, bad


def _vector(size=VECTOR_LEN):
    """Deterministic filler, so the vectors below pin the seeds as well."""
    buf = bytearray(size)
    x = VECTOR_SEED
    for i in range(size):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        buf[i] = (x >> 16) & 0xFF
    return buf


def selftest(path=None):
    """Algorithm self-test: regression vector plus, if given, a real read."""
    rc = 0
    for label, buf, args, expect in (
            ("calibration block", _vector(), (0xB80, 0x7C00, CAL_SEEDS),
             VECTOR_CHECKSUM),
            ("code block", _vector(CODE_VECTOR_LEN), (0x10000, 0x14000, CODE_SEEDS),
             CODE_VECTOR_CHECKSUM)):
        got = checksum(buf, *args)
        ok = got == expect
        rc |= not ok
        print(f"  regression vector, {label:17} {got:08X} expected {expect:08X} "
              f"{'ok' if ok else 'FAIL'}")
    if not path:
        return rc
    try:
        buf = bytearray(open(path, "rb").read())
    except OSError as e:
        print(f"  {path}: {e}")
        return 2
    ok_n, bad_n = process(buf, fix=False)
    rc |= bool(bad_n) or not ok_n
    print(f"  {path}: {ok_n} checksum(s) match, {bad_n} wrong "
          f"{'ok' if ok_n and not bad_n else 'FAIL'}")
    return rc


def _beside(path):
    """The corrected file's name when the original is to be left alone."""
    base, ext = os.path.splitext(path)
    return (base + ".fixed" + ext) if ext else base + ".fixed.bin"


def main(argv):
    inplace = check = False
    files = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--selftest":
            return selftest(argv[i + 1] if i + 1 < len(argv) else None)
        elif a == "-i":
            inplace = True
        elif a == "-c":
            check = True
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            files.append(a)
        i += 1
    if not files:
        print(__doc__)
        return 2

    rc = 0
    for name in files:
        try:
            buf = bytearray(open(name, "rb").read())
        except OSError as e:
            print(f"{name}: {e}")
            rc = 2
            continue
        ok, fixed = process(buf, fix=not check)
        if not (ok or fixed):
            print(f"{name}: no EDC15M TDI V3.1 checksum block found")
            rc = 2
        elif check:
            print(f"{name}: {ok} checksum(s) ok, {fixed} wrong")
            rc |= 1 if fixed else 0
        else:
            dst = name if inplace else _beside(name)
            if fixed:
                try:
                    open(dst, "wb").write(buf)
                except OSError as e:
                    print(f"{name}: cannot write {dst}: {e.strerror}")
                    rc = 2
                    continue
                print(f"{name}: {ok} ok, {fixed} corrected -> {dst}")
            else:
                print(f"{name}: {ok} checksum(s) already correct, nothing written")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))