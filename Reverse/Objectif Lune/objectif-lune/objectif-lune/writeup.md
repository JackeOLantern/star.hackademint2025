# Write-up — Objectif Lune (Start.hackademint)

## 1. Context and files

The challenge provides:

- `objectif_lune`: a Mach-O arm64 executable.
- `flag.txt.enc`: an encrypted flag.

Goal: recover the plaintext flag.

## 2. Core idea

The program embeds two 256-byte buffers used for a self-check:

- `expected_data` (plaintext test vector) — 256 bytes
- `expected_enc_data` (ciphertext test vector) — 256 bytes

If encryption is stream-like (or any XOR-based keystream scheme), then for each byte `i`:

- `C[i] = P[i] XOR KS[i]`

Therefore, from a known (P, C) pair:

- `KS[i] = P[i] XOR C[i]`

Once the keystream is known, decrypting the encrypted flag is immediate:

- `flag_plain[i] = flag_enc[i] XOR KS[i]`

## 3. Reverse engineering observations

### 3.1 Mach-O format constraints

The binary is Mach-O (sometimes universal/FAT). Robust parsing requires:

- optional FAT slice selection (prefer `arm64`)
- correct endianness selection (`<` vs `>`), validated by **load command bounds**

Naive parsers commonly fail by misreading `cmdsize` and running past file bounds.

### 3.2 Why the symbol-based approach may fail

Even if `_expected_data` and `_expected_enc_data` appear by name in the string table,
their resolved value can be unusable (e.g., `n_sect=0`, `addr=0`), because the symbol
is undefined/indirect/stripped.

In that case, mapping `addr → section` fails by design: address 0 is not in any section.

### 3.3 Practical recovery path used by the solver

During analysis, the Mach-O sections reveal that `__DATA,__data` is exactly `0x200` bytes:

- 0x200 = 512 bytes = 2 × 256-byte buffers

The solver therefore extracts:

- `a = __DATA,__data[0:256]`
- `b = __DATA,__data[256:512]`

The correct ordering is not assumed. It tries both:

- candidate 1: keystream = a XOR b, decrypt flag
- candidate 2: keystream = b XOR a, decrypt flag

A simple scoring heuristic selects the candidate that contains `Star{...}` and has good printability.

## 4. Solver walkthrough (decrypt_objectif_lune.py)

1. Read files (`objectif_lune`, `flag.txt.enc`).
2. If FAT, select the arm64 slice.
3. Parse Mach-O header and load commands with bounds checks.
4. Try to resolve `_expected_data` and `_expected_enc_data` from LC_SYMTAB:
   - if both addresses are non-zero and within sections, read 256 bytes each.
5. Otherwise fallback:
   - read 512 bytes from `__DATA,__data`
   - split into two 256-byte buffers
   - try both orders, score outputs, select best candidate.
6. Output plaintext flag (stdout or `--out`).

## 5. Reproduce

```bash
python3 decrypt_objectif_lune.py -v
```

Optionally:

```bash
python3 decrypt_objectif_lune.py --out flag.txt
```

## 6. Result

Recovered flag:

`Star{Il_faut_faire_appel_aux_dupont_et_dupond_pour_retrouver_ce_flag!}`
