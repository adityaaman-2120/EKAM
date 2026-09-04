# `deploy/keys/` — Ed25519 signing keys

This directory holds the **Ed25519 keypair** the integrity ledger uses to sign
batch Merkle roots and lawful-export manifests
([`ulpf/integrity/signing.py`](../../ulpf/integrity/signing.py)).

| File | Committed? | Purpose |
|------|-----------|---------|
| `ulpf_ed25519_private.pem` | **NO** (`.gitignore`) | signs artefacts — keep secret |
| `ulpf_ed25519_public.pem`  | yes | verifies signatures — distribute freely |

## Generate

```bash
ulpf keys generate --out deploy/keys/
# then point the config at the private key:
#   configs/ulpf.yaml -> integrity.signing_key_path: deploy/keys/ulpf_ed25519_private.pem
```

`generate` refuses to overwrite an existing private key unless you pass
`--overwrite` — a live key is never silently destroyed.

## Protecting the private key

`ulpf keys generate` writes the private key **unencrypted** (PKCS#8) and relies
on **filesystem permissions** to protect it.

- **On POSIX** it is `chmod 0600` (owner read/write only) automatically.
- **On Windows** `os.chmod` cannot drop group/other permission bits, so the file
  is left with the directory's inherited ACL and is **not owner-restricted**.
  `ulpf keys generate` logs a `WARNING` once when this happens. On Windows you
  must restrict the file yourself, e.g.:

  ```powershell
  icacls .\deploy\keys\ulpf_ed25519_private.pem /inheritance:r /grant:r "$env:USERNAME:(R,W)"
  ```

  or store the key in a secrets manager / vault and point the config at that
  path instead.

Regardless of platform: **never commit the private key**, and prefer a dedicated
secrets store over a file on disk for anything beyond local development.
