# Reverse engineering notes

Everything here was derived from a third-party Windows checksum tool and a set
of ECU reads. No part of that tool was executed.

**Nothing that was not written here is in this repository.** The reads used
during development are vehicle data and are not distributed; the reference tool
is someone else's commercial software and is not distributed either. Both are
described below because the algorithm was recovered from them, but without the
file names they arrived under. The unpacker in `tools/` will unpack a copy of
the reference tool again if you have one.

The ECU this targets is **Bosch 0 281 010 205, software version 7789658**.

## 1. What was analysed

The material used, none of which is tracked in this repository:

| item | note |
|---|---|
| the GUI | Delphi 7, a checksum corrector from 2005, also with a mode that talks to hardware |
| 57 plugins | one per ECU family, loaded by name on request; the set has a gap in its numbering |
| dongle driver | a Windows 98 era driver; the tool was licence-locked to it |
| a sample read | a 512 kB read shipped alongside the tool |
| a 256 kB full read | untouched, used as the starting point |
| a hand-edited copy of it | one byte pair changed, the checksum left stale |
| the reference tool's output for that copy | used as ground truth |
| a second, later 256 kB read | kept aside as an unseen input for a second check |
| the reference tool's output for that one | the two results were compared |
| six 32 kB partial reads | checksums already correct |

The GUI hard-codes a list of plugin names and loads whichever is picked, so the
ECU family name lives inside each plugin rather than in the GUI.

## 2. The plugins are packed

```
PE32
    Linker: Turbo Linker(5.0)
    Compiler: Borland C++(Builder)
    Packer: ASPack(2.12b)
```

Every plugin, and the GUI, is ASPack 2.12b: `.text`/`.data` are aPLib
compressed and the `.aspack`/`.adata` sections hold the loader stub. The
exported `Checksum` entry point therefore points into compressed data and
disassembles to nonsense.

`tools/unaspack.py` unpacks them by emulation instead of by pattern matching:

1. map the PE at its image base, write the headers and sections,
2. stub the handful of Windows APIs the stub uses (`VirtualAlloc`,
   `VirtualProtect`, `VirtualFree`, `GetModuleHandleA`, `LoadLibraryA`,
   `GetProcAddress`),
3. run from `AddressOfEntryPoint` until control leaves the stub,
4. write the resulting memory image out as a loadable PE.

Four bugs had to be fixed on the way, each of which looked like "the packer is
unbreakable" rather than an obvious mistake:

* the `GetProcAddress` stub was hand-assembled with a `je` displacement that
  skipped one byte short, so every name resolved to the wrong API;
* the stub write patched both the INT and IAT slots of the import table. The
  two arrays are adjacent, so patching `imp.address - 4` clobbered the previous
  import;
* the six API stubs were placed 0x10 bytes apart but `VirtualAlloc`'s code is
  33 bytes long, so it silently overwrote `VirtualProtect`;
* ASPack jumps into `.text` twice: once through a `mov byte [edi],0xC3; call
  edi` trampoline and once for real at the end. Stopping on the first entry
  into the image gave an incomplete unpack. The trampoline is now identified by
  recording the single-byte `0xC3` writes and clearing them once execution
  returns to the stub.

`tools/unpack_all.py <dir>` runs it over a whole plugin directory in
about two minutes.

## 3. Finding the right plugin

Once unpacked, each plugin carries its ECU name as a Borland string constant in
`.data`, alongside an identification list of matching numbers. One plugin is the
one that says **"Bosch TDI V3.1"**, and its identification list ends
`... 0x88 0x11 0x00 0x11`. For the record, the other 56 cover VAG
ME7/CR/EDC15P, Bosch ME1.5/2.x/7.x/9/M5.2/DME, Siemens MS4x/MSS5x/5WP4, Delphi
DCI, TEMIC, Marelli, Fiat DMT, Smart CDI and more.

## 4. The layout the plugin looks for

`Checksum` (`0x401D30`) calls `0x401244`, which does two passes.

**Pass 1 - find the reference id.** Scan the image in `0x100` steps for the tag
`C3 3C 55 AA`. The two bytes at `tag + 0x3FFA` and `tag + 0x3FFC` are the
reference id. In the reads used here the tag sits at `0x10000` and the id is
`23 A6`.

**Pass 2 - find the block that owns the checksum.** Walk the flash in `0x8000`
steps. A block carries the checksum when its id appears at `block + 0xB7A`.
Inside that block, step over `[block + 0x7000, block + 0x8000]` in `0x80`
increments looking for the same id at `slot - 6`; the checksum itself is the
four bytes at `slot - 4`, and the covered range is
`[block + 0xB80, slot)`.

For the 256 kB read that resolves to

```
block      = 0x38000
slot       = 0x3FC00
checksum   = 0x3FBFC, 32 bit little endian
covered    = [0x38B80, 0x3FC00)          0x7080 bytes, 3600 loop turns
```

and for the 32 kB partial read the same block relative to its own base:

```
block      = 0x00000
slot       = 0x7C00
checksum   = 0x7BFC
covered    = [0x0B80, 0x7C00)
```

Note that the 16-bit pair at `0x395CC` is **not** a checksum. It sits inside
the covered range and changes when the read is edited, but no tool ever writes
it - it is calibration data that happens to sit in the covered window.

## 5. The three code paths, and the one that applies

`Checksum` (`0x401D30`) is a dispatcher. `GetFile` (`0x401D98`) identifies the
ECU first, by looking for two signatures, and the answer selects between three
paths:

| found at | meaning |
|---|---|
| `0x8020`, 14 bytes `C3 C3 41 41 30 30 38 38 31 31 30 30 31 31` | fixed-layout variant, sets a flag at `0x40A1A4` |
| `0x38000`, 9 bytes `55 55 00 00 56 56 33 33 2E` | id-scan variant |

Every read tested carries the second signature and not the first, so the flag
stays clear and `Checksum` calls the id-scan routine `0x401244` - the path
documented in section 4 and the one this tool implements.

Two paths remain off the normal route, and both belong to the *other*
signature:

- `0x401B85` - a second pass over the blocks already discovered, for re-checking
  after an edit. Same algorithm, no new geometry.
- `0x40150D` - a fixed-layout handler for a 256 kB read, covering three blocks:

  | range | checksum at | seeds (h, g, h-out, g-out) |
  |---|---|---|
  | `[0x38B80, 0x40000)` | `0x3FFFC` | `8631 EFCF 8631 DF9B` |
  | `[0x9000, 0xF000)` | `0xEFFC` | `5CE6 D8F7 D8F7 732E` |
  | `[0x10000, 0x14000)` | `0x13FFC` | `0000 0000 8631 DF9B` |

  It also calls `0x40196F` and `0x401936`, which compare and then copy
  `buf[0x0B80 ...]` from `buf[0x38B80 ...]` over about 0x5280 bytes. Those two
  ranges differ in every read tested here (21010 of 21631 bytes), so the
  mirroring is a property of the other variant, not this one.

Of the three fixed blocks, the first two sit on `C3 C3 C3 C3` filler in these
reads and are not real checksums. **The third is real**: `[0x10000, 0x14000)`
with a checksum at `0x13FFC` recomputes to exactly the stored `7403BFF1`, and
changes when a byte inside its range does. The original tool leaves it alone for
this signature, so this tool corrects it where the original would not - see
section 8.

A second image, a different software version of the same ECU, showed why the
block cannot simply be applied to any 256 kB read. That read is a 32 kB partial
padded out to 256 kB, so its whole `[0x10000, 0x14000)` code area is blank:
`0x13FFC` holds `FF FF FF FF`. Computing a checksum there and comparing it
against blank flash reports a failure that does not exist. A field that is all
ones or all zeros is therefore treated as absent, not as stale. The original
tool never reaches this block for this signature, so it never sees the case.

## 6. The algorithm

`0x4019B3`, translated instruction by instruction. Two 16-bit registers `h`
and `g`, plus a 16-bit position counter `q`, walk the range four bytes at a
time:

```
h = 0x8631,  g = 0xEFCD
q = (uint16)start
if q >> 15:  q -= 0x8000          # wraps in 16 bits
elif q == 0: q += 0x8000

loop:
    h ^= word16(p);  p += 2;  q += 2
    if g & 0xF:  h = rol16(h, g & 0xF);  carry = h & 1
    else:        carry = 0
    g  = g - word16(p) - carry;  p += 2;  q += 2
    g ^= h
    if p == end - 4: done

    h -= word16(p);  p += 2;  q += 2
    h = q + h - 1
    g ^= word16(p);  p += 2;  q += 2
    if h & 0xF:  g = ror16(g, h & 0xF)
    if p != end - 4: loop

h -= 0x8631
h  = q + h + 1
return (uint16)h | ((uint16)(g ^ 0xDF9B) << 16)
```

The two seed constants that made the difference while reverse engineering were
`0xEFCF` and the correct `0xEFCD` - a one-bit transcription error in the
seed table is invisible until the whole 3600-turn chain is compared against a
known-good file.

Two more details worth keeping:

* the two rotate helpers are `rol ax,cl` at `0x405764` and `ror ax,cl` at
  `0x405774`, i.e. the caller pushes the count first and the value second;
* the checksum bytes are outside the covered range, so the operation is
  idempotent - re-running the tool on a corrected file changes nothing.

## 7. Validation

Against the 256 kB full read, after a byte pair was changed by hand:

| file | stored | computed | result |
|---|---|---|---|
| untouched read | `0B85A0D6` | `0B85A0D6` | verifies |
| hand-edited read | `0B85A0D6` | `FB85EDAF` | stale, corrected |
| Windows tool's output for that read | `FB85EDAF` | `FB85EDAF` | verifies |

All six 32 kB partial reads verified as already correct.

Correcting the hand-edited read with this implementation reproduced the Windows
tool's output byte for byte, which is what pins the parameters down: any wrong
constant would have to be right for every one of those files simultaneously.

A second, independent check came later. A fresh 256 kB read was passed to both
the reference tool and this implementation. Both changed the same four bytes and
the results were byte identical. That rules out the algorithm having been fitted
to the single reference it was first derived from.

None of these files are in the repository, so the reproducible check is the
built-in regression vector in `edc15m_checksum.py --selftest`; `--selftest FILE`
repeats the whole procedure against a read you supply.

## 8. The upgrade

The Windows tool finds a block only through the `C3 3C 55 AA` tag, and that tag
lives in the first part of the flash. A 32 kB partial read is the last 32 kB, so
it contains no tag and the tool reports "No Checksum Found" and does nothing.
The tag is not actually needed: the block's own id at `+0xB7A` is the same
pair, and within a 32 kB block it is unique. Keying the scan on the block id,
with the tag as the preferred source when present, makes both sizes work.

Two other reasons the replacement is an upgrade: no dongle driver and no
57-DLL runtime, and the check-only mode lets a file be verified without writing
anything.

A third is coverage. The code-area checksum described in section 5 is valid in
these reads but sits on a code path the original never takes for this
signature, so the original leaves it stale after an edit to the code area. This
tool corrects it. On every read tested here the field is already correct, so
this changes nothing about the output - it only means a read whose code area was
modified comes out right rather than one ECU rejection away from it.

## 9. Open items / risks

* Only the Bosch 0 281 010 205 / software 7789658 flavour could be tested,
  because that is the only data available. The other 56 plugins use the same
  skeleton with different geometry constants, and this tool implements only the
  TDI V3.1 constants.
* An ECU with more than one checksum block in the last 32 kB would be handled
  (the scan yields every block it finds) but is untested.
* The scan trusts the bytes at `block + 0xB7A`. On a dump where that offset is
  filler the tool reports "no checksum block found" instead of writing garbage,
  but always keep the original read.
* The reference tool was never run; its hardware mode was not needed.