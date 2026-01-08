# Objectif Lune — Solver (decrypt_objectif_lune.py)

This repository contains a standalone Python solver for the **Start.hackademint** reverse challenge **“Objectif Lune”**.

The challenge ships two files:

- `objectif_lune` — a Mach-O executable (arm64, macOS/iOS-style format)
- `flag.txt.enc` — an encrypted flag file

The solver extracts an embedded **known-plaintext / expected-ciphertext** pair from the Mach-O, reconstructs the **keystream** by XOR, then decrypts `flag.txt.enc`.

## Requirements

- Python 3.8+
- No third-party dependencies (stdlib only)

## Quick start

Place the three files in the same directory:

- `objectif_lune`
- `flag.txt.enc`
- `decrypt_objectif_lune.py`

Run:

```bash
python3 decrypt_objectif_lune.py
```

Verbose / proof mode:

```bash
python3 decrypt_objectif_lune.py -v
```

Write plaintext to a file:

```bash
python3 decrypt_objectif_lune.py --out flag.txt
```

## Options

- `--bin <path>`: path to the Mach-O binary (default: `objectif_lune`)
- `--enc <path>`: path to the encrypted flag (default: `flag.txt.enc`)
- `--out <path>`: write decrypted plaintext to this file (default: stdout)
- `-v, --verbose`: print parsing details (FAT slice selection, endianness checks, sections, fallback path, candidate scoring)

## Expected output

A valid run prints a `Star{...}` flag.

Example (validated):

`Star{Il_faut_faire_appel_aux_dupont_et_dupond_pour_retrouver_ce_flag!}`

## Notes

- If the Mach-O symbol table does not provide usable addresses for `_expected_data` / `_expected_enc_data` (e.g., `addr=0`), the solver falls back to extracting the 512-byte payload from `__DATA,__data` (2×256 bytes).
