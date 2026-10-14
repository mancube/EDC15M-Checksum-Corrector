# EDC15M checksum corrector

Corrects the calibration checksum in Bosch **EDC15M** reads so a modified tune
can be flashed back. Implements the **"TDI V3.1"** algorithm.

Runs on Linux, macOS and Windows with nothing but Python. The command line tool
has no dependencies at all; the graphical one needs PySide6.

| read | size | checksum at | covers |
|---|---|---|---|
| full flash | 256 kB | `0x3FBFC` | `[0x38B80, 0x3FC00)` |
| full flash | 256 kB | `0x13FFC` | `[0x10000, 0x14000)` |
| partial read | 32 kB | `0x7BFC` | `[0x0B80, 0x7C00)` |

The checksum is a 32-bit little-endian value. It is not the only value near the
end of a read — the 16-bit pair at `0x395CC` of a 256 kB read is calibration
data and is never modified.

Both read sizes are handled the same way. A 32 kB partial read is the last
32 kB of the full image, so the same block holds the same checksum one 32 kB
earlier; the tool finds it either way.

---

## Install

```sh
# command line only - nothing to install, Python 3.8+
python3 edc15m_checksum.py --selftest

# graphical interface
pip install PySide6
```

---

## Graphical interface

```sh
python3 edc15m_checksum_gui.py            # empty
python3 edc15m_checksum_gui.py tune.bin   # with files
```

Drop reads from your file manager onto the window or the table, or use
**Add files...** (`Ctrl+O`). Dropping a folder adds every file inside it.

Each row shows the file, its size, whether it is a full or partial read, where
the checksum is, the stored and computed values, and the result. Click a column
header to sort.

| colour | meaning |
|---|---|
| green | checksum already correct |
| red | wrong, or just corrected |
| grey | no checksum block recognised |

**Check checksums** reports without writing anything. **Correct checksums**
writes the fix. Select rows first to limit either action to those files;
with nothing selected both apply to everything listed.

Two output modes:

- **beside the file** (default) — writes `tune.fixed.bin` and leaves the
  original alone
- **overwrite in place** — rewrites the original, after a confirmation

Files whose checksum is already correct are not rewritten.

The window follows the desktop light and dark setting and repaints when it
changes.

---

## Command line

```sh
python3 edc15m_checksum.py tune.bin              # -> tune.fixed.bin
python3 edc15m_checksum.py -i tune.bin           # correct in place
python3 edc15m_checksum.py -c a.bin b.bin        # verify only, write nothing
```

| flag | effect |
|---|---|
| `-i` | correct the files in place |
| `-c` | check only, write nothing |
| `--selftest [FILE]` | run the self-test, optionally also verifying `FILE` |

Accepts any number of files. Per file it prints one line: how many checksums
were already correct, how many were corrected and where the result went.

Exit status:

| code | meaning |
|---|---|
| `0` | all checksums correct |
| `1` | at least one checksum was wrong (`-c` only) |
| `2` | a file could not be read, or held no recognisable checksum block |

Suitable for batch use:

```sh
for f in tunes/*.bin; do python3 edc15m_checksum.py -c "$f" || echo "$f needs attention"; done
```

---

## Typical workflow

1. Read the ECU. **Keep the original, unmodified read somewhere safe** — it is
   the way back if something goes wrong.
2. Edit a copy in WinOLS or ECM Titanium.
3. Correct the edited copy:
   ```sh
   python3 edc15m_checksum.py edited.bin
   ```
4. Write `edited.fixed.bin` back to the ECU.

Anything edited inside the covered window invalidates the checksum and needs
correcting; anything outside it does not. The tool always writes a new file
unless you ask it not to, so step 3 never puts the ECU at risk.

---

## How it works

The flash is divided into 32 kB blocks. A block that owns a checksum repeats a
2-byte id at `block + 0xB7A`, and the same two bytes appear immediately in front
of the checksum. Matching the pair locates the calibration block and its
checksum field; the checksum covers `[block + 0xB80, checksum position)`.

A full read may have a second checksum with fixed geometry, over the code area
at `[0x10000, 0x14000)` and stored at `0x13FFC`. It uses the same algorithm
with different seeds. It is only considered when the calibration block has been
recognised **and** something is actually stored at that address: a 32 kB partial
read padded out to 256 kB has no code area, and blank flash is not a checksum
that went stale.

The value is not a plain sum. It is a seeded 16-bit rolling checksum, four bytes
per turn, with one register rotated whenever the low nibble of the other is
non-zero, combined into a 32-bit result at the end. The derivation is in
[`docs/REVERSE-ENGINEERING.md`](docs/REVERSE-ENGINEERING.md).

Two properties worth relying on:

- **Idempotent.** The checksum bytes are outside the covered range, so correcting
  an already-correct file changes nothing.
- **Order independent of file name.** Only the contents matter.

---

## Verifying

```sh
$ python3 edc15m_checksum.py --selftest
  regression vector, calibration block 007BC5EB expected 007BC5EB ok
  regression vector, code block        2477887F expected 2477887F ok
```

The self-test needs no input file, and pins the seeds of both blocks. Given a
read with valid checksums, it also recomputes and compares them:

```sh
$ python3 edc15m_checksum.py --selftest tune.bin
  ...
  tune.bin: 2 checksum(s) match, 0 wrong ok
```

On a read whose checksum is stale it reports `FAIL` and exits non-zero, which
makes it usable as a gate:

```sh
python3 edc15m_checksum.py --selftest tune.bin || echo "not ready to flash"
```

On the reads this was developed against, the output was compared against the
original Windows Checksum Corrector for the same algorithm and matched byte for
byte.

---

## Safety

- The original read is only modified when you choose *overwrite in place* and
  confirm it. The default writes a separate file.
- A file is written in full to its destination; if the write fails the original
  is untouched and the row shows the reason.
- An unrecognised layout is reported and nothing is written. The tool does not
  guess.
- Dropping files only loads them. Nothing is corrected until you press
  **Correct checksums**.

---

## Limitations

- Only the **TDI V3.1** layout is implemented. Other Bosch EDC15M variants use
  different offsets and signatures and are not supported.
- Verified on Bosch EDC15M **0 281 010 205**, software version **7789658**. The
  layout is common to the family, but other ECUs have not been tested.
- The code-area checksum at `0x13FFC` is corrected on a 256 kB read when one is
  present. It was found to be valid and left alone by the original tool for this
  signature, so this is stricter than the tool it replaces.
- A read whose code area is blank — typically a 32 kB partial padded to 256 kB —
  is treated as having only the calibration checksum.

---

## Files

| file | |
|---|---|
| `edc15m_checksum.py` | the engine and the command line tool, no dependencies |
| `edc15m_checksum_gui.py` | the graphical interface, needs PySide6 |
| `docs/REVERSE-ENGINEERING.md` | how the algorithm was recovered, for reference |
| `docs/RELEASING.md` | the two-remote release procedure, in the source-of-truth repository only |
| `tools/unaspack.py` | ASPack unpacker used during the analysis |
| `tools/unpack_all.py` | unpacks the plugin set in one go |

`tools/` is only needed to work through the analysis. Running either interface
needs nothing but the two top-level scripts.