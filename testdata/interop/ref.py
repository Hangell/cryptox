#!/usr/bin/env python3
"""Independent reference implementation for CryptoX v2 stream and Envelope v1.

This file is written from the published specifications only
(docs/spec/stream-v2.md and docs/spec/envelope-v1.md). It does not read or
import any CryptoX Go code. It verifies the pinned golden vectors in both
directions: Go-generated ciphertext decrypts here, and re-encryption here
reproduces the Go-generated ciphertext byte-for-byte.

Dependencies: `cryptography` (pip install cryptography).
Run: python3 testdata/interop/ref.py
"""

import json
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(ROOT))

# --- v2 stream (CXS2) -------------------------------------------------------

V2_MAGIC = b"CXS2"
V2_VERSION = 0x02
V2_SUITE = 0x01
V2_SALT_LEN = 32
V2_PREFIX_LEN = 7
V2_HEADER_LEN = 4 + 1 + 1 + 1 + V2_SALT_LEN + V2_PREFIX_LEN  # 46
V2_SEGMENT = 64 * 1024
V2_TAG = 16
V2_DOMAIN = b"cryptox/v2/stream"


def v2_info(version, suite, aad):
    return V2_DOMAIN + b"\x00" + bytes([version, suite]) + b"\x00" + aad


def v2_derive(key, salt, aad):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=v2_info(V2_VERSION, V2_SUITE, aad),
    ).derive(key)


def v2_segment_iv(prefix, counter, final):
    return prefix + counter.to_bytes(4, "big") + (b"\x01" if final else b"\x00")


def v2_decrypt(ciphertext, key, aad):
    if len(ciphertext) < V2_HEADER_LEN:
        raise ValueError("truncated header")
    hdr = ciphertext[:V2_HEADER_LEN]
    if hdr[:4] != V2_MAGIC:
        raise ValueError("bad magic")
    if hdr[4] != V2_VERSION:
        raise ValueError("unsupported version")
    if hdr[5] != V2_SUITE:
        raise ValueError("unsupported suite")
    if hdr[6] != V2_SALT_LEN:
        raise ValueError("bad salt length")
    salt = hdr[7 : 7 + V2_SALT_LEN]
    prefix = hdr[7 + V2_SALT_LEN : V2_HEADER_LEN]
    g = AESGCM(v2_derive(key, salt, aad))

    body = ciphertext[V2_HEADER_LEN:]
    plaintext = bytearray()
    counter = 0
    off = 0
    while True:
        if counter >= 2**32:
            raise ValueError("counter overflow")
        seg = body[off : off + V2_SEGMENT + V2_TAG]
        if len(seg) == V2_SEGMENT + V2_TAG:
            final = (off + V2_SEGMENT + V2_TAG) == len(body)
        elif len(seg) >= V2_TAG:
            final = True
        else:
            raise ValueError("truncated or missing final segment")
        pt = g.decrypt(v2_segment_iv(prefix, counter, final), seg, None)
        plaintext += pt
        off += len(seg)
        if final:
            if off != len(body):
                raise ValueError("trailing data after final segment")
            break
        counter += 1
    return bytes(plaintext)


def v2_encrypt(plaintext, key, aad, salt, prefix):
    g = AESGCM(v2_derive(key, salt, aad))
    hdr = V2_MAGIC + bytes([V2_VERSION, V2_SUITE, V2_SALT_LEN]) + salt + prefix
    if len(plaintext) == 0:
        seg = b""
        iv = v2_segment_iv(prefix, 0, True)
        return hdr + g.encrypt(iv, seg, None)
    out = bytearray(hdr)
    chunks = [
        plaintext[i : i + V2_SEGMENT] for i in range(0, len(plaintext), V2_SEGMENT)
    ]
    for i, chunk in enumerate(chunks):
        final = i == len(chunks) - 1
        out += g.encrypt(v2_segment_iv(prefix, i, final), chunk, None)
    return bytes(out)


# --- Envelope v1 (CXE1) ------------------------------------------------------

ENV_MAGIC = b"CXE1"
ENV_VERSION = 0x01
ENV_SUITE = 0x0001
ENV_NONCE_LEN = 12
ENV_TAG = 16


def envelope_parse(data):
    if len(data) < 4 or data[:4] != ENV_MAGIC:
        raise ValueError("bad magic")
    i = 4
    if data[i] != ENV_VERSION:
        raise ValueError("unsupported version")
    i += 1
    suite = int.from_bytes(data[i : i + 2], "big")
    if suite != ENV_SUITE:
        raise ValueError("unsupported suite")
    i += 2
    kid_len = data[i]
    i += 1
    if kid_len > 64 or len(data) < i + kid_len:
        raise ValueError("bad key id length")
    kid = data[i : i + kid_len]
    i += kid_len
    aad_len = int.from_bytes(data[i : i + 2], "big")
    i += 2
    if aad_len > 65535 or len(data) < i + aad_len:
        raise ValueError("bad aad length")
    aad = data[i : i + aad_len]
    i += aad_len
    n_len = data[i]
    i += 1
    if n_len != ENV_NONCE_LEN:
        raise ValueError("bad nonce length")
    nonce = data[i : i + n_len]
    i += n_len
    header = data[:i]
    if len(data) - i < ENV_TAG:
        raise ValueError("missing tag")
    return header, nonce, data[i:]


def envelope_decrypt(ciphertext, key):
    header, nonce, body = envelope_parse(ciphertext)
    payload = AESGCM(key).decrypt(nonce, body, header)
    kid_len = header[7]
    kid = header[8 : 8 + kid_len]
    aad_len = int.from_bytes(header[8 + kid_len : 10 + kid_len], "big")
    aad = header[10 + kid_len : 10 + kid_len + aad_len]
    return payload, kid, aad


def envelope_encrypt(payload, key, key_id, aad, nonce):
    header = (
        ENV_MAGIC
        + bytes([ENV_VERSION])
        + ENV_SUITE.to_bytes(2, "big")
        + bytes([len(key_id)])
        + key_id
        + len(aad).to_bytes(2, "big")
        + aad
        + bytes([ENV_NONCE_LEN])
        + nonce
    )
    body = AESGCM(key).encrypt(nonce, payload, header)
    return header + body


def hex2b(s):
    return bytes.fromhex(s)


def main():
    v2 = json.load(open(os.path.join(REPO, "stream", "testdata", "v2-golden.json")))
    env = json.load(
        open(os.path.join(REPO, "envelope", "testdata", "envelope-v1-golden.json"))
    )

    key = hex2b(v2["key"])
    aad = hex2b(v2["aad"])
    salt = hex2b(v2["salt"])
    prefix = hex2b(v2["noncePrefix"])
    ct = hex2b(v2["ciphertext"])
    pt = hex2b(v2["plaintext"])

    assert v2_decrypt(ct, key, aad) == pt, "v2 decrypt mismatch"
    assert v2_encrypt(pt, key, aad, salt, prefix) == ct, "v2 encrypt mismatch"

    ekey = hex2b(env["key"])
    nonce = hex2b(env["nonce"])
    kid = hex2b(env["keyID"])
    eaad = hex2b(env["aad"])
    epayload = hex2b(env["payload"])
    ect = hex2b(env["ciphertext"])

    payload, gkid, gaad = envelope_decrypt(ect, ekey)
    assert payload == epayload, "envelope decrypt payload mismatch"
    assert gkid == kid, "envelope decrypt keyID mismatch"
    assert gaad == eaad, "envelope decrypt aad mismatch"
    assert envelope_encrypt(epayload, ekey, kid, eaad, nonce) == ect, (
        "envelope encrypt mismatch"
    )

    # Verify the full interop corpus (empty, segment boundaries, AAD, keyID).
    v2_corpus = json.load(
        open(os.path.join(REPO, "testdata", "interop", "v2-corpus.json"))
    )
    for entry in v2_corpus:
        k = hex2b(entry["key"])
        a = hex2b(entry["aad"])
        s = hex2b(entry["salt"])
        p = hex2b(entry["noncePrefix"])
        c = hex2b(entry["ciphertext"])
        m = hex2b(entry["plaintext"])
        assert v2_decrypt(c, k, a) == m, "v2 corpus decrypt mismatch: " + entry["name"]
        assert v2_encrypt(m, k, a, s, p) == c, "v2 corpus encrypt mismatch: " + entry["name"]

    env_corpus = json.load(
        open(os.path.join(REPO, "testdata", "interop", "envelope-corpus.json"))
    )
    for entry in env_corpus:
        k = hex2b(entry["key"])
        n = hex2b(entry["nonce"])
        kd = hex2b(entry["keyID"])
        a = hex2b(entry["aad"])
        p = hex2b(entry["payload"])
        c = hex2b(entry["ciphertext"])
        payload, gkid, gaad = envelope_decrypt(c, k)
        assert payload == p, "envelope corpus payload mismatch: " + entry["name"]
        assert gkid == kd and gaad == a, "envelope corpus meta mismatch: " + entry["name"]
        assert envelope_encrypt(p, k, kd, a, n) == c, "envelope corpus encrypt mismatch: " + entry["name"]

    print("interop OK: v2 stream and Envelope v1 match in both directions")


if __name__ == "__main__":
    sys.exit(main())
