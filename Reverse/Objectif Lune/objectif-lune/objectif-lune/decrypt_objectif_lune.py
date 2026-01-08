#!/usr/bin/env python3
"""
Objectif Lune — Mach-O arm64 keystream extractor & flag decryptor

This solver reconstructs the keystream from an embedded self-check pair (expected_data, expected_enc_data)
and decrypts flag.txt.enc by XORing the ciphertext with the recovered keystream.
Author : JG
"""

import argparse
import struct
from pathlib import Path

# Mach-O 64
MH_MAGIC_64      = 0xFEEDFACF
MH_CIGAM_64      = 0xCFFAEDFE  # byteswapped magic

# FAT (universal) magics (big-endian on disk)
FAT_MAGIC        = 0xCAFEBABE
FAT_MAGIC_64     = 0xCAFEBABF

LC_SEGMENT_64    = 0x19
LC_SYMTAB        = 0x2

CPU_TYPE_ARM64   = 0x0100000C

def be32(b, off=0): return struct.unpack_from(">I", b, off)[0]
    """Read a big-endian uint32 from bytes at the given offset."""
def le32(b, off=0): return struct.unpack_from("<I", b, off)[0]
    """Read a little-endian uint32 from bytes at the given offset."""
def u32(b, off, endian): return struct.unpack_from(endian + "I", b, off)[0]
    """Read a uint32 from bytes using the provided endianness ('<' or '>')."""
def i32(b, off, endian): return struct.unpack_from(endian + "i", b, off)[0]
    """Read a int32 from bytes using the provided endianness ('<' or '>')."""
def u64(b, off, endian): return struct.unpack_from(endian + "Q", b, off)[0]
    """Read a uint64 from bytes using the provided endianness ('<' or '>')."""

def pick_macho_slice(buf: bytes, verbose=False) -> bytes:
    """If the binary is FAT/universal, select the arm64 slice (else return input)."""
    magic = be32(buf, 0)
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return buf

    nfat = be32(buf, 4)
    off = 8
    arches = []

    if magic == FAT_MAGIC:
        for i in range(nfat):
            cputype, cpusub, offset, size, align = struct.unpack_from(">IIIII", buf, off + i*20)
            arches.append((cputype, offset, size))
    else:
        for i in range(nfat):
            cputype, cpusub, offset, size, align, rsv = struct.unpack_from(">IIQQII", buf, off + i*32)
            arches.append((cputype, offset, size))

    for ct, o, s in arches:
        if ct == CPU_TYPE_ARM64:
            if verbose:
                print(f"[v] FAT: selected arm64 slice offset=0x{o:x} size=0x{s:x}")
            return buf[o:o+s]

    ct, o, s = arches[0]
    if verbose:
        print(f"[v] FAT: arm64 not found; selected first slice cputype=0x{ct:x} offset=0x{o:x} size=0x{s:x}")
    return buf[o:o+s]

def try_parse_header(buf: bytes, endian: str):
    """Parse and sanity-check a Mach-O 64 header for a candidate endianness."""
    if len(buf) < 32:
        return None
    magic = struct.unpack_from(endian + "I", buf, 0)[0]
    if magic not in (MH_MAGIC_64, MH_CIGAM_64):
        return None

    cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
        endian + "iiIIIII", buf, 4
    )

    if ncmds <= 0 or ncmds > 2000:
        return None
    if sizeofcmds <= 0 or sizeofcmds > len(buf):
        return None
    if 32 + sizeofcmds > len(buf):
        return None

    return {"endian": endian, "cputype": cputype, "ncmds": ncmds, "sizeofcmds": sizeofcmds}

def detect_macho_endian(buf: bytes, verbose=False) -> str:
    """Determine Mach-O endianness by testing header coherence (and logging in -v)."""
    h_le = try_parse_header(buf, "<")
    h_be = try_parse_header(buf, ">")
    candidates = [h for h in (h_le, h_be) if h is not None]
    if not candidates:
        raise ValueError("Not a valid Mach-O 64 slice (cannot parse header coherently).")
    if len(candidates) == 1:
        if verbose:
            print(f"[v] endian chosen by header coherence: {candidates[0]['endian']}")
        return candidates[0]["endian"]
    if verbose:
        print("[v] both endians look coherent at header level; will disambiguate via load commands")
    return "both"

def parse_macho_64(buf: bytes, verbose=False):
    """Parse Mach-O load commands, sections and optional symbol table with strong bounds checks."""
    choice = detect_macho_endian(buf, verbose=verbose)
    endians = ["<", ">"] if choice == "both" else [choice]

    last_err = None
    for endian in endians:
        try:
            cputype = i32(buf, 4, endian)
            ncmds = u32(buf, 16, endian)
            sizeofcmds = u32(buf, 20, endian)

            if verbose:
                print(f"[v] trying endian={endian} ({'LE' if endian=='<' else 'BE'}) "
                      f"cputype=0x{cputype & 0xffffffff:x} ncmds={ncmds} sizeofcmds=0x{sizeofcmds:x}")

            off = 32
            end_off = 32 + sizeofcmds

            sections = []
            symoff = nsyms = stroff = strsize = None

            for _ in range(ncmds):
                if off + 8 > len(buf) or off + 8 > end_off:
                    raise ValueError("load command out of bounds")

                cmd, cmdsize = struct.unpack_from(endian + "II", buf, off)
                if cmdsize < 8:
                    raise ValueError("invalid cmdsize < 8")
                if off + cmdsize > len(buf) or off + cmdsize > end_off:
                    raise ValueError("load command cmdsize out of bounds")

                if cmd == LC_SEGMENT_64:
                    if cmdsize < 72:
                        raise ValueError("SEGMENT_64 cmdsize too small")

                    segname = buf[off+8:off+24].split(b"\x00", 1)[0].decode(errors="replace")
                    vmaddr  = u64(buf, off+24, endian)
                    fileoff = u64(buf, off+40, endian)
                    nsects  = u32(buf, off+64, endian)

                    if verbose:
                        print(f"[v] LC_SEGMENT_64 {segname} vmaddr=0x{vmaddr:x} fileoff=0x{fileoff:x} nsects={nsects}")

                    p = off + 72
                    for __ in range(nsects):
                        if p + 80 > off + cmdsize:
                            raise ValueError("section_64 out of bounds within segment command")
                        sectname = buf[p:p+16].split(b"\x00", 1)[0].decode(errors="replace")
                        seg      = buf[p+16:p+32].split(b"\x00", 1)[0].decode(errors="replace")
                        addr     = u64(buf, p+32, endian)
                        size     = u64(buf, p+40, endian)
                        offset   = u32(buf, p+48, endian)
                        flags    = u32(buf, p+64, endian)
                        sections.append({
                            "segname": seg, "sectname": sectname,
                            "addr": addr, "size": size, "offset": offset, "flags": flags
                        })
                        if verbose and seg in ("__DATA", "__TEXT"):
                            print(f"    [v] section {seg},{sectname} addr=0x{addr:x} size=0x{size:x} offset=0x{offset:x} flags=0x{flags:x}")
                        p += 80

                elif cmd == LC_SYMTAB:
                    if cmdsize < 24:
                        raise ValueError("SYMTAB cmdsize too small")
                    symoff, nsyms, stroff, strsize = struct.unpack_from(endian + "IIII", buf, off+8)
                    if verbose:
                        print(f"[v] LC_SYMTAB symoff=0x{symoff:x} nsyms={nsyms} stroff=0x{stroff:x} strsize=0x{strsize:x}")

                off += cmdsize

            if symoff is None:
                # Not fatal for our fallback (we can work without symbols)
                if verbose:
                    print("[v] LC_SYMTAB not found (binary may be stripped). Continuing with section-based fallback.")
                return endian, sections, None

            if symoff + nsyms*16 > len(buf):
                raise ValueError("symtab out of file bounds")
            if stroff + strsize > len(buf):
                raise ValueError("strtab out of file bounds")

            if verbose:
                print(f"[v] endian validated by load commands: {endian}")
            return endian, sections, (symoff, nsyms, stroff, strsize)

        except Exception as e:
            last_err = e
            if verbose:
                print(f"[v] endian={endian} rejected: {e}")

    raise ValueError(f"Could not parse Mach-O load commands coherently (last error: {last_err})")

def find_symbol(buf: bytes, endian: str, symtab, target: str):
    """Locate a symbol in LC_SYMTAB and return (n_sect, n_value)."""
    if symtab is None:
        raise KeyError("no symtab")
    symoff, nsyms, stroff, strsize = symtab
    for i in range(nsyms):
        base = symoff + i*16
        strx = u32(buf, base, endian)
        sect = buf[base+5]
        value = u64(buf, base+8, endian)
        if strx == 0:
            continue
        nm_off = stroff + strx
        nm_end = buf.find(b"\x00", nm_off, stroff + strsize)
        if nm_end == -1:
            continue
        name = buf[nm_off:nm_end].decode(errors="replace")
        if name == target:
            return sect, value
    raise KeyError(target)

def get_section(sections, segname: str, sectname: str):
    """Return the section dict matching (segname, sectname), or None."""
    for s in sections:
        if s["segname"] == segname and s["sectname"] == sectname:
            return s
    return None

def read_section_bytes(buf: bytes, sec, n=None) -> bytes:
    """Read raw bytes from a section using its file offset and size (optionally capped)."""
    o = sec["offset"]
    size = sec["size"]
    if o <= 0 or o >= len(buf):
        return b""
    take = size if n is None else min(size, n)
    if o + take > len(buf):
        return b""
    return buf[o:o+take]

def score_flag_candidate(pt: bytes) -> int:
    """Score a decrypted candidate based on printability and expected flag prefix."""
    # Simple scoring: printable + contains expected prefix
    s = 0
    if b"Star{" in pt:
        s += 1000
    # printable ratio
    printable = sum(1 for c in pt if 32 <= c <= 126 or c in (10, 13, 9))
    s += printable
    return s

def main():
    """CLI entrypoint: extract keystream and decrypt flag.txt.enc (symbol path or __DATA,__data fallback)."""
    ap = argparse.ArgumentParser(description="Objectif Lune — Extract keystream from Mach-O arm64 self-check and decrypt flag.txt.enc.")
    ap.add_argument("--bin", default="objectif_lune")
    ap.add_argument("--enc", default="flag.txt.enc")
    ap.add_argument("--out", default="")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    macho_raw = Path(args.bin).read_bytes()
    enc = Path(args.enc).read_bytes()

    macho = pick_macho_slice(macho_raw, verbose=args.verbose)
    endian, sections, symtab = parse_macho_64(macho, verbose=args.verbose)

    expected_p = expected_e = None

    # 1) Try symbol-based (but accept that addresses may be 0, as in your -v output)
    if symtab is not None:
        try:
            sect_p, addr_p = find_symbol(macho, endian, symtab, "_expected_data")
            sect_e, addr_e = find_symbol(macho, endian, symtab, "_expected_enc_data")
            if args.verbose:
                print(f"[v] sym _expected_data      : n_sect={sect_p} addr=0x{addr_p:x}")
                print(f"[v] sym _expected_enc_data  : n_sect={sect_e} addr=0x{addr_e:x}")

            if addr_p != 0 and addr_e != 0:
                # map by containing section ranges
                sec_p = next((s for s in sections if s["addr"] <= addr_p < s["addr"] + s["size"]), None)
                sec_e = next((s for s in sections if s["addr"] <= addr_e < s["addr"] + s["size"]), None)
                if args.verbose:
                    sp = f"{sec_p['segname']},{sec_p['sectname']}" if sec_p else "None"
                    se = f"{sec_e['segname']},{sec_e['sectname']}" if sec_e else "None"
                    print(f"[v] map _expected_data      -> {sp}")
                    print(f"[v] map _expected_enc_data  -> {se}")
                if sec_p and sec_e:
                    # read 256 bytes from each
                    op = sec_p["offset"] + (addr_p - sec_p["addr"])
                    oe = sec_e["offset"] + (addr_e - sec_e["addr"])
                    if 0 <= op <= len(macho)-256 and 0 <= oe <= len(macho)-256:
                        expected_p = macho[op:op+256]
                        expected_e = macho[oe:oe+256]
        except KeyError:
            pass

    # 2) Fallback: use __DATA,__data section directly (your -v shows size=0x200!)
    if expected_p is None or expected_e is None:
        sec = get_section(sections, "__DATA", "__data")
        if sec is None:
            raise ValueError("Fallback failed: section __DATA,__data not found.")
        blob = read_section_bytes(macho, sec, n=0x200)
        if len(blob) < 0x200:
            raise ValueError("Fallback failed: __DATA,__data is not file-backed or too small to contain 512 bytes.")
        if args.verbose:
            print(f"[v] fallback: using __DATA,__data offset=0x{sec['offset']:x} size=0x{sec['size']:x}")
        # Assume it contains two 256-byte buffers back-to-back
        a = blob[:256]
        b = blob[256:512]

        # Try both orders; select the one producing a plausible flag
        def decrypt_with(p, e):
            ks = bytes(x ^ y for x, y in zip(p, e))
            return bytes(enc[i] ^ ks[i] for i in range(len(enc)))

        cand1 = decrypt_with(a, b)
        cand2 = decrypt_with(b, a)
        s1 = score_flag_candidate(cand1)
        s2 = score_flag_candidate(cand2)

        if args.verbose:
            print(f"[v] candidate scores: order(a,b)={s1} order(b,a)={s2}")
            print(f"[v] cand1 head={cand1[:16]!r}")
            print(f"[v] cand2 head={cand2[:16]!r}")

        plain = cand1 if s1 >= s2 else cand2
    else:
        # symbol-based path
        ks = bytes(x ^ y for x, y in zip(expected_p, expected_e))
        if len(enc) > len(ks):
            raise ValueError("Encrypted flag longer than keystream (need longer keystream).")
        plain = bytes(enc[i] ^ ks[i] for i in range(len(enc)))

    if args.out:
        Path(args.out).write_bytes(plain)
        if args.verbose:
            print(f"[v] wrote plaintext to {args.out} ({len(plain)} bytes)")
    else:
        try:
            print(plain.decode("utf-8"))
        except UnicodeDecodeError:
            print(plain)

if __name__ == "__main__":
    main()
