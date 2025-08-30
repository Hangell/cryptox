# SymCrypt (Go Library)

A lightweight **encryption/decryption library** for Go, designed for large files and streaming use-cases.  
It provides simple wrappers around modern symmetric cryptography primitives (AES-GCM / AES-CTR), with support for chunked processing.

---

## Features

- 🔒 **AES-256-GCM** (authenticated encryption with integrity check)  
- ⚡ **Streaming mode** — handles large files without loading them fully into memory  
- 🧩 **Versioned file format** — allows future upgrades without breaking old data  
- 🔑 **Configurable key sizes** (16, 24, 32 bytes → AES-128/192/256)  
- 📦 Minimal dependencies — only Go standard library + `golang.org/x/crypto`  

---

## Installation

```bash
go get github.com/Hangell/cryptox
```


email: rodrigo@hangell.org
