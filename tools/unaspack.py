#!/usr/bin/env python3
"""Static ASPack 2.x unpacker: emulate the loader stub with unicorn, dump the OEP image."""
import sys, struct, pefile
from unicorn import *
from unicorn.x86_const import *

STUB = 0x70000000
STUB_SIZE = 0x2000
ARENA = 0x50000000
ARENA_SIZE = 0x4000000
STACK = 0x30000000
STEP_CAP = 300_000_000

# name -> stub offset inside the stub page
APIS = {
    b"VirtualAlloc": 0x100,
    b"VirtualProtect": 0x140,
    b"VirtualFree": 0x180,
    b"GetModuleHandleA": 0x1c0,
    b"LoadLibraryA": 0x200,
    b"GetProcAddress": 0x240,
}


def unpack(path, out, quiet=False):
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xfff) & ~0xfff

    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(STUB, STUB_SIZE)
    mu.mem_write(STUB, b"\xc3" * STUB_SIZE)
    mu.mem_write(STUB + 0x800, struct.pack("<I", ARENA))

    # VirtualAlloc -> bump allocator over a pre-mapped arena
    mu.mem_write(STUB + 0x100,
                 b"\x8b\x44\x24\x08"                 # mov eax, [esp+8]  (dwSize)
                 b"\x05\xff\x0f\x00\x00"             # add eax, 0xfff
                 b"\x25\x00\xf0\xff\xff"             # and eax, ~0xfff
                 b"\x8b\x0d" + struct.pack("<I", STUB + 0x800) +
                 b"\x01\xc8"                         # add eax, ecx
                 b"\x89\x05" + struct.pack("<I", STUB + 0x800) +
                 b"\x8b\xc1\xc2\x10\x00")            # mov eax, ecx ; ret 0x10
    mu.mem_write(STUB + 0x140, b"\xb8\x01\x00\x00\x00\xc2\x10\x00")   # VirtualProtect -> TRUE
    mu.mem_write(STUB + 0x180, b"\xb8\x01\x00\x00\x00\xc2\x0c\x00")   # VirtualFree    -> TRUE
    for off in (0x1c0, 0x200):                     # GetModuleHandleA / LoadLibraryA
        mu.mem_write(STUB + off, b"\xb8" + struct.pack("<I", STUB + 0x700) + b"\xc2\x04\x00")
    mu.mem_write(STUB + 0x240, b"\xc2\x08\x00")    # GetProcAddress: eax set by hook

    mu.mem_map(ARENA, ARENA_SIZE)
    mu.mem_map(base, size)
    mu.mem_map(STACK, 0x20000)
    mu.mem_write(base, pe.get_data(0, pe.OPTIONAL_HEADER.SizeOfHeaders)[:size])
    for s in pe.sections:
        d = s.get_data()
        if d:
            mu.mem_write(base + s.VirtualAddress, d)

    def poke(a, v):
        if base <= a < base + size:
            mu.mem_write(a, struct.pack("<I", v))

    for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in e.imports:
            n = (imp.name or b"").split(b"\x00")[0]
            off = APIS.get(n, 0x120)
            poke(imp.address, STUB + off)

    ep = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    mu.reg_write(UC_X86_REG_ESP, STACK + 0x10000)
    mu.reg_write(UC_X86_REG_EBP, STACK + 0x10000)

    # the ASPack stub lives in the entry-point section and everything after it
    lo = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    hi = base + size
    st = {"n": 0, "patched": set(), "was_img": False}

    def in_image(a):
        return base <= a < base + size

    def hook_code(uc, addr, size_, _):
        st["n"] += 1
        if st["n"] > STEP_CAP:
            uc.emu_stop()
            return
        if addr == STUB + 0x240:                    # GetProcAddress: resolve in python
            esp = uc.reg_read(UC_X86_REG_ESP)
            p = int.from_bytes(bytes(uc.mem_read(esp + 8, 4)), "little")
            if p < 0x10000:
                uc.emu_stop()
                return
            try:
                name = bytes(uc.mem_read(p, 64)).split(b"\x00")[0]
            except UcError:
                name = b""
            off = APIS.get(name, 0x120)
            uc.reg_write(UC_X86_REG_EAX, STUB + off)
            if not quiet:
                print(f"  GetProcAddress({name!r}) -> 0x{STUB + off:08x}")
            return
        outside = in_image(addr) and not (lo <= addr < hi)
        if outside:
            if addr in st["patched"]:
                return                          # ASPack's call-edi trampoline
            uc.emu_stop()                        # genuine jump to the original entry point
        elif st["was_img"]:
            st["patched"] = set()                # back in the stub: byte patches are undone
        st["was_img"] = outside

    def hook_mem(uc, access, addr, sz, value, _):
        if access == UC_MEM_WRITE and sz == 1 and (value & 0xff) == 0xC3 and in_image(addr):
            st["patched"].add(addr)              # ASPack's `mov byte [edi],0xC3` trampoline
        page = addr & ~0xfff
        try:
            uc.mem_map(page, 0x1000)
            uc.mem_write(page, b"\xc3" * 0x1000)
        except UcError:
            pass
        return True

    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem)

    try:
        mu.emu_start(ep, 0, 0, STEP_CAP)
    except UcError as e:
        if not quiet:
            print("emu stop:", e)

    oep = mu.reg_read(UC_X86_REG_EIP)
    img = bytearray(mu.mem_read(base, size))
    # make the memory image directly loadable: point section raw data at the RVAs
    off = pe.DOS_HEADER.e_lfanew + 4 + 20 + pe.FILE_HEADER.SizeOfOptionalHeader
    nsec = pe.FILE_HEADER.NumberOfSections
    for i in range(nsec):
        s = off + i * 40
        va = struct.unpack_from("<I", img, s + 12)[0]
        vs = struct.unpack_from("<I", img, s + 8)[0]
        struct.pack_into("<II", img, s + 16, max(vs, 1), va)       # SizeOfRawData, PointerToRawData
    struct.pack_into("<I", img, off - pe.FILE_HEADER.SizeOfOptionalHeader + 56, size)  # SizeOfImage
    open(out, "wb").write(bytes(img))
    try:
        open(out + ".arena", "wb").write(bytes(mu.mem_read(ARENA, 0x20000)))
    except UcError:
        pass
    if not quiet:
        print(f"{path}: OEP=0x{oep:08x} insns={st['n']} -> {out}")
    return oep, img, pe


if __name__ == "__main__":
    unpack(sys.argv[1], sys.argv[2])