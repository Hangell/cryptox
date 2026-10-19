# Wycheproof AES-256-GCM vectors (curated)

- Source: <https://github.com/C2SP/wycheproof>
- File: `testvectors_v1/aes_gcm_test.json`
- Algorithm: AES-256-GCM
- Curation: a small subset of AES-256-GCM vectors (key length 64 hex chars) with
  distinct Wycheproof flags, including valid and invalid cases. Full origin file
  is ~200 KB; the curated subset keeps the repository and CI light.

The vectors are consumed by `aead/wycheproof_test.go`. Each entry carries
hex-encoded `key`, `iv`, `aad`, `msg`, `ct`, `tag`, and a `result` field
(`valid` or `invalid`).
