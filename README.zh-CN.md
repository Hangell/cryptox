# CryptoX

**面向 Go 的模块化密码学 SDK — 正在开发中。**

[English](README.md) · [Português (Brasil)](README.pt-BR.md) · [简体中文](README.zh-CN.md) · [हिन्दी](README.hi.md) · [Русский](README.ru.md)

CryptoX 正从文件加密工具演进为通用密码学工具库。项目旨在提供可复用、可审计的组件，涵盖加密、密钥管理、加密存储、身份以及与成熟 E2EE 协议的集成，并独立于云服务商、传输协议、数据库和应用框架。

> **当前状态：**代码已实现随机 AES 密钥生成和旧版 v1 文件加密。v1 格式认证的是单个数据块，**而不是整个文件**，无法检测末尾完整数据块被删除的情况。需要完整文件完整性保证时，请勿使用此实现。项目不声称已通过独立安全审计或已达到生产就绪状态。

## 为什么了解 CryptoX？

- **职责明确的包：**直接导入 `keys` 和 `stream`，无需依赖通用工具包。
- **有界内存使用：**以最大 64 KiB 的数据块处理文件，而非将整个文件加载到内存。
- **依赖少：**当前库仅使用 Go 标准库，无需 CGO、强制外部服务或遥测。
- **明确的失败行为：**输入格式错误或认证失败会返回错误；仅在操作成功后才发布目标文件。
- **可验证的工程实践：**包含对抗性测试、模糊测试、数据竞争检测、静态分析及 CI 配置。

目前，CryptoX 适合用于评估架构、研究现有格式以及参与现代化改造。未来目标包括安全附件、备份、离线存储、服务间通信、设备身份和 E2EE 集成。这些是预期用例，并非已经交付的完整解决方案。目前没有经过验证的性能对比，也不保证优于其他库。

## 当前有哪些功能？

| 包 | 可用 API | 行为 |
| --- | --- | --- |
| `keys` | `GenerateKey(size int) ([]byte, error)` | 使用 `crypto/rand` 生成 16、24 或 32 字节的 AES 密钥。 |
| `stream` | `EncryptLargeFiles(infile, outfile string, key []byte) error` | 使用 AES-GCM 将文件加密为旧版 v1 格式。 |
| `stream` | `DecryptLargeFiles(infile, outfile string, key []byte) error` | 验证每个数据块并写入恢复文件；无法验证文件是否完整。 |
| `stream` | `ValidateEncryptedFile(filename string) error` | 仅检查文件头，**不**验证密文或认证标签。 |
| `utils` | 相同的四个旧版函数 | 已弃用的兼容外观层，委托给 `keys` 和 `stream`。 |

当前公开 API 接收文件路径。公开的 `io.Reader`/`io.Writer` API、流结束认证、HKDF、加密封装、安全存储、身份、棘轮、重放保护、移动端绑定和后量子支持均**尚未实现**。

源码声明的最低兼容级别为 Go 1.19。开发和部署请使用仍受维护的 Go 工具链；最低源码兼容性并非安全建议。库核心不需要 CGO，但 `go test -race` 需要受支持的平台及 C 工具链。

## 安装

### 使用本地检出版本

若要试用本文描述的具体实现，请创建独立的演示模块，并将其指向本地 CryptoX 工作副本。将 `/absolute/path/to/cryptox` 替换为真实绝对路径：

```sh
mkdir cryptox-demo
cd cryptox-demo
go mod init example.com/cryptox-demo
go mod edit -require=github.com/Hangell/cryptox@v0.0.0
go mod edit -replace=github.com/Hangell/cryptox=/absolute/path/to/cryptox
```

这里的 `v0.0.0` 只是本地模块依赖的占位版本，并不表示存在对应已发布版本。`replace` 指令让 Go 使用本地文件。

### 使用远程模块

在已有 Go 模块中运行：

```sh
go get github.com/Hangell/cryptox
```

此命令下载远程仓库中可用的版本，**不会包含尚未发布的本地修改**。请确认所选修订版本包含 `keys` 和 `stream`；现代化改造期间，包布局和格式可能变化。本文不声称已有稳定发布版，也不声称远程 CI 当前已通过。

## 示例：生成密钥、加密、验证文件头并解密

在 `cryptox-demo` 中将以下代码保存为 `main.go`，然后执行 `go run .`：

```go
package main

import (
    "bytes"
    "fmt"
    "log"
    "os"
    "path/filepath"

    "github.com/Hangell/cryptox/keys"
    "github.com/Hangell/cryptox/stream"
)

func main() {
    if err := run(); err != nil {
        log.Fatal(err)
    }
}

func run() error {
    // Use disposable data: the v1 format lacks whole-file integrity.
    dir, err := os.MkdirTemp("", "cryptox-demo-*")
    if err != nil {
        return err
    }
    defer os.RemoveAll(dir)

    input := filepath.Join(dir, "message.txt")
    encrypted := filepath.Join(dir, "message.enc")
    restored := filepath.Join(dir, "restored.txt")
    original := []byte("Hello from CryptoX!\n")
    if err := os.WriteFile(input, original, 0o600); err != nil {
        return err
    }

    // Generate a fresh AES-256 key for this file. Never log it.
    key, err := keys.GenerateKey(32)
    if err != nil {
        return err
    }
    if err := stream.EncryptLargeFiles(input, encrypted, key); err != nil {
        return err
    }
    // This checks the header only, not ciphertext integrity.
    if err := stream.ValidateEncryptedFile(encrypted); err != nil {
        return err
    }
    if err := stream.DecryptLargeFiles(encrypted, restored, key); err != nil {
        return err
    }
    recovered, err := os.ReadFile(restored)
    if err != nil {
        return err
    }
    // This comparison checks the demo, not the v1 format's security.
    if !bytes.Equal(original, recovered) {
        return fmt.Errorf("round-trip mismatch")
    }
    fmt.Println("Round trip OK")
    return nil
}
```

预期输出为 `Round trip OK`。示例使用临时测试文件，并在结束时删除。只有演示代码会完整读取少量明文以比较结果；库本身以增量方式处理文件。

密钥仅保留在本次运行的内存中。对于持久化数据，应用必须单独安全保存和恢复密钥；CryptoX 当前不提供密钥存储。丢失密钥就无法访问数据。切勿打印密钥或将其提交到版本库，也不要直接将密码用作 AES 密钥。密码派生尚未实现。每个 v1 文件应使用新密钥；API 不强制执行此策略。

现有调用方仍可导入 `github.com/Hangell/cryptox/utils` 并使用相同的函数名。新代码应使用职责明确的包。这描述的是当前兼容性，而不是对未来改造中保留旧 API 的承诺。

## 安全边界与旧版格式

```text
Header (21 bytes): "SYM1" | version=1 | "AESG" | base nonce (12 bytes)
Record: ciphertext length (uint32 LE) | ciphertext | GCM tag (16 bytes)
Nonce: random prefix (8 bytes) | chunk counter (uint32 LE)
```

长度字段包含 GCM 标签。文件头中 nonce 的最后四个字节必须为零；每条记录使用其顺序计数器。计数器在超过 `uint32` 范围之前会被拒绝，从而避免单个文件内的回绕。

- **可能接受不完整文件：**删除末尾的完整记录可能不会报错。空文件没有认证标签，也无法认证密钥。
- **元数据认证不完整：**文件头经过结构校验，但没有作为关联数据得到完整认证。
- **跨文件 nonce 碰撞：**随机前缀只有 64 位。在多个文件间复用密钥可能造成前缀碰撞。检查计数器不能消除此风险。
- **文件发布：**在目标目录创建唯一临时文件，Unix 权限为 `0600`；先同步数据并关闭文件，再重命名。失败时会尝试清理，不会主动替换目标。成功操作可能覆盖已有输出文件；请提前创建父目录并谨慎选择路径。
- **操作系统限制：**目标目录必须可信。Windows 需要适当的 ACL；重命名的原子性取决于操作系统和文件系统。目录本身未被同步，因此不保证崩溃后的持久性。进程崩溃可能留下临时文件。
- **秘密信息与威胁限制：**Go 不保证立即擦除内存。此代码无法防御已失陷的进程或操作系统、存储回滚、重放或元数据分析，也不是 E2EE 协议。

仅使用 AES-GCM 并不能使文件格式安全。替代格式必须明确认证元数据及结束标记，并接受适当审查；不能将这些属性追溯赋予 v1。

## 架构与发展方向

设计遵循模块化和六边形架构原则：使用方按需调用包；可选适配器依赖核心契约；核心独立于基础设施。仅在真实抽象边界引入接口，而非为每个函数建立接口。

| 计划组件 | 职责 |
| --- | --- |
| `aead` | 认证加密与 nonce 管理。 |
| 扩展 `keys` | 派生、用途隔离、生命周期及存储集成。 |
| 替换 `stream` | 对分帧、元数据、顺序及流结束进行认证。 |
| `envelope` | 显式版本化的加密对象格式。 |
| `securestorage` | 加密状态与可选持久化适配器。 |
| `identity` / `pki` | 设备身份、签名、凭据、证书及信任验证。 |
| `e2ee` | 经审查选定的成熟会话/群组协议适配器。 |

架构中的候选技术包括 ChaCha20-Poly1305、HKDF、X25519、Ed25519、Argon2id、MLS 以及经过审查的后量子机制。这些是待评估的技术，不是已安装功能，也不是自创协议的组合配方。CryptoX 不会实现消息服务器、用户注册、队列、推送投递或云编排。

## 路线图

[ROADMAP.md](ROADMAP.md) 规定了详细验收门槛及以下规划目标：

| 阶段 | 目标版本 | 目标 |
| --- | --- | --- |
| 0 | v0.1.0 | 安全诊断与架构基线。 |
| 1 | v0.2.0 | 密码学基础与工程控制。 |
| 2 | v0.3.0 | 安全流处理与加密封装。 |
| 3 | v0.4.0 | 密钥管理与安全存储。 |
| 4 | v0.5.0 | 身份与设备安全。 |
| 5 | v0.6.0 | 集成成熟 E2EE 协议。 |
| 6 | v0.7.0 | 跨平台与移动端集成。 |
| 7 | v0.9.0 | 安全加固与独立审查。 |
| 8 | v1.0.0 | 经验证的稳定密码学核心。 |
| 9 | v1.x / v2.x | 高级密码学功能与生态。 |

这些不是已发布版本或交付日期。已有代码与测试不能证明任何阶段已经完成。加密格式 **v1** 与 Go 模块/发布版本 **v1.0.0** 是不同概念。当前改造策略允许有文档记录的破坏性变更；即使核心发布稳定版，E2EE 和移动端功能仍可能处于实验阶段。

## 测试与 CI

请在 CryptoX 仓库目录执行。第一组命令使用 Make；第二组为直接命令，包含漏洞分析：

```sh
make check
make fuzz
```

```sh
go vet ./...
go test -race -count=1 -coverpkg=./... -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
go test ./stream -run='^$' -fuzz=FuzzDecryptV1 -fuzztime=30s -parallel=2
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

测试涵盖 `utils` 的四个函数、AES 密钥长度、数据块边界、错误密钥、无效文件头/长度、修改或重排的数据块、分段读取、短写、错误传播、临时文件清理和目标文件保留。并行用例使用独立文件。测试也明确记录了 v1 的截断限制。模糊测试检查失败时必须保持的条件，而不仅仅检查是否发生 panic。

[CI 工作流](.github/workflows/ci.yml) 配置了 push、pull request、手动和每周运行。它定义了使用 Go `stable` 的 Linux/Windows/macOS 任务，以及使用 `oldstable` 和 `1.19.13` 的额外 Linux 任务，并包含覆盖率与 JSON 产物、模糊测试和 `govulncheck`。配置存在不代表远程执行成功：请查看对应提交的运行结果。覆盖率与测试通过不能替代独立密码学审查。

## 项目文档与贡献

三个主要工程文档为：

- [AGENTS.md](AGENTS.md)：使命、强制工程规则与验收标准。
- [ARCHITECTURE.md](ARCHITECTURE.md)：目标模块、契约、信任边界与威胁模型。
- [ROADMAP.md](ROADMAP.md)：优先级、依赖、里程碑与发布门槛。

[CONTRIBUTING.md](CONTRIBUTING.md) 说明贡献检查。[THREAT_MODEL.md](THREAT_MODEL.md) 指向架构文档中维护的威胁模型。[SECURITY.md](SECURITY.md) 记录当前限制和漏洞报告流程。如果 GitHub 私密报告功能可用，请使用该功能；否则请先请求保密渠道，不要发布敏感细节。该政策不声称私密报告已启用，也不规定响应 SLA。切勿公开秘密信息或敏感利用细节。

请提交小规模、便于审查的变更：检查实现，在关键修复前加入回归/对抗性测试，运行检查，并记录安全假设及 API/格式变更。标识符和代码注释使用英文，提交信息遵循 Conventional Commits 并解释原因。行为改变时，请同步维护五种语言的 README。

## 许可证

[MIT](LICENSE) — Copyright (c) 2025 Rodrigo Rangel.
