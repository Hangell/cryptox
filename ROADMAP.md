# CryptoX — Roadmap Atualizado

**Projeto:** CryptoX
**Linguagem principal:** Go
**Arquitetura:** Modular · Security-First · Hexagonal
**Estado atual:** transição da fundação criptográfica para o formato seguro v2
**Meta principal:** `v1.0.0` — Stable Cryptographic Core

---

## Visão atual

O CryptoX deixou de ser apenas uma biblioteca experimental de criptografia de arquivos.

A base atual já possui:

- geração segura de chaves;
- AES-256-GCM;
- API AEAD com nonce gerado internamente;
- HKDF-SHA-256;
- separação de chaves por propósito;
- formato legado v1 claramente isolado;
- novo formato streaming v2;
- autenticação de terminação;
- proteção contra truncamento, reordenação, duplicação e modificação;
- API streaming baseada em `io.Reader` / `io.WriteCloser`;
- vetores externos Wycheproof;
- fuzzing;
- race detector;
- `govulncheck`;
- CI Linux, Windows e macOS;
- fuzzing prolongado agendado;
- release pipeline com SBOM, checksums e provenance;
- processo privado de vulnerabilidade;
- documentação explícita de garantias e limitações.

O principal bloqueio agora não é implementação básica.

É **validação criptográfica independente, congelamento do formato v2 e construção das camadas superiores sobre essa fundação**.

---

# Visão das fases

| Fase | Objetivo | Estado atualizado | Target |
|---|---|---|---|
| 0 | Security Audit & Architecture Baseline | 🟡 Security Review | v0.1.0 |
| 1 | Cryptographic Foundation | 🟢 Quase concluída | v0.2.0 |
| 2 | Secure Streaming & Envelope | 🟡 Em andamento | v0.3.0 |
| 3 | Key Management & Secure Storage | ⚪ Próxima grande fase | v0.4.0 |
| 4 | Identity & Device Security | ⚪ Não iniciada | v0.5.0 |
| 5 | E2EE Protocol Integration | ⚪ Não iniciada | v0.6.0 |
| 6 | Cross-Platform Integration | 🟡 Parcialmente antecipada | v0.7.0 |
| 7 | Security Hardening & External Review | 🟡 Infraestrutura antecipada | v0.9.0 |
| 8 | Stable Cryptographic Core | ⚪ Não iniciada | v1.0.0 |
| 9 | Advanced Crypto & Ecosystem | ⚪ Futuro | v1.x / v2.x |

---

# Fase 0 — Security Audit & Architecture Baseline

**Target:** `v0.1.0`
**Estado recomendado:** **Security Review**

## Já concluído

- [x] Inventário dos pacotes e APIs existentes.
- [x] Revisão do AES-GCM legado.
- [x] Análise de nonce e contador do v1.
- [x] Identificação do risco de colisão de nonce entre arquivos.
- [x] Análise do framing do v1.
- [x] Identificação de truncamento silencioso.
- [x] Análise de chunk ordering.
- [x] Avaliação de arquivos temporários.
- [x] Testes de entradas malformadas.
- [x] Fuzzing do parser legado.
- [x] Threat model inicial.
- [x] Trust boundaries.
- [x] Garantias e não-garantias documentadas.
- [x] Estrutura de pacotes definida.
- [x] ADR do formato streaming.
- [x] Design v2 definido.
- [x] Parâmetros de nonce, HKDF e segmentação definidos.
- [x] Estratégia de migração v1 → v2 definida.
- [x] API enganosa `ValidateEncryptedFile` depreciada em favor de `ValidateHeader`.

## Restante

- [ ] Obter **revisão criptográfica independente** dos parâmetros v2.
- [ ] Validar concretamente os limites multi-user/multi-key do STREAM/HS20.
- [ ] Confirmar formalmente o `domainSep`.
- [ ] Confirmar limites de uso por chave.
- [ ] Aprovar definitivamente o formato binário v2.
- [ ] Mudar ADR 0002 de proposta/revisão interna para decisão aprovada.

## Gate de saída

A Fase 0 termina quando houver:

> **aprovação independente suficiente para congelar as decisões criptográficas fundamentais do v2.**

Até lá, o código pode evoluir experimentalmente, mas o formato não deve ser declarado estável.

---

# Fase 1 — Cryptographic Foundation

**Target:** `v0.2.0`
**Estado:** **Quase concluída**

Esta fase avançou muito além do status antigo do roadmap.

## AEAD

- [x] Pacote `aead`.
- [x] AES-256-GCM.
- [x] Chave fortemente tipada de 256 bits.
- [x] Nonce aleatório de 96 bits gerado internamente.
- [x] Caller não controla nonce na API de alto nível.
- [x] AAD suportado.
- [x] Erro de autenticação identificável.
- [x] Falha de autenticação nunca retorna plaintext.
- [x] API segura para concorrência.
- [x] Material de chave redigido em `String()`.
- [x] Fuzz tests.
- [x] Wycheproof AES-256-GCM.

## Keys

- [x] Geração via `crypto/rand`.
- [x] Validação explícita dos tamanhos AES.
- [x] HKDF-SHA-256.
- [x] Domain separation.
- [x] Key-purpose separation.
- [x] Testes de derivação.
- [x] Contextos criptográficos explícitos.

## Engenharia

- [x] `gofmt`.
- [x] `go vet`.
- [x] golangci-lint.
- [x] race detector.
- [x] unit tests.
- [x] fuzzing.
- [x] fuzzing prolongado agendado.
- [x] `govulncheck`.
- [x] CI multiplataforma.
- [x] Actions pinadas por SHA.
- [x] Go 1.26 definido como baseline.
- [x] processo de vulnerability reporting.
- [x] SBOM/provenance preparados para releases.

## Restante

- [ ] Fechar revisão independente do AEAD + derivação usados pelo v2.
- [ ] Decidir se ChaCha20-Poly1305 entra nesta fase ou fica explicitamente para futura suite.
- [ ] Definir política final de erros públicos compartilhados entre os módulos.
- [ ] Congelar os contratos públicos que entrarão no primeiro release.

## Gate

> Fundação criptográfica revisada, testada e suficientemente estável para receber módulos superiores.

---

# Fase 2 — Secure Streaming & Envelope

**Target:** `v0.3.0`
**Estado:** **Em andamento**

Essa deve ser a **prioridade principal de desenvolvimento agora**.

## Streaming v2 — já implementado

- [x] Magic independente `CXS2`.
- [x] Version `0x02`.
- [x] Suite explícita.
- [x] AES-256-GCM.
- [x] HKDF-SHA-256.
- [x] Salt de 32 bytes.
- [x] Nonce prefix de 7 bytes.
- [x] Chave independente derivada por stream.
- [x] Segmentos de 64 KiB.
- [x] Counter big-endian.
- [x] Final flag autenticado.
- [x] Empty stream autenticado.
- [x] Detecção de truncamento.
- [x] Detecção de reordenação.
- [x] Detecção de duplicação.
- [x] Detecção de corrupção.
- [x] Limite de contador.
- [x] Limite estrutural de stream.
- [x] AAD ligado à derivação.
- [x] Fuzzing do v2.
- [x] API streaming pública.
- [x] `io.Reader`.
- [x] `io.WriteCloser`.
- [x] Finalização explícita.
- [x] Sem promessa falsa de whole-stream integrity antes da finalização.

## File adapters

- [x] arquivos temporários restritivos;
- [x] publicação apenas após sucesso;
- [x] preservação do destino em falha;
- [x] política de overwrite documentada;
- [x] testes de erro de publicação;
- [x] comportamento de crash/durabilidade documentado.

## Agora falta o **Envelope**

Criar pacote:

```text
envelope/
```

Responsabilidade:

```text
Envelope
├── version
├── suite
├── metadata autenticada
├── key information
├── payload / stream
└── extensões futuras
```

### Tasks

- [ ] Definir especificação `CryptoX Envelope v1`.
- [ ] Definir serialização canônica.
- [ ] Definir magic independente.
- [ ] Definir versionamento.
- [ ] Definir algorithm/suite identifiers.
- [ ] Autenticar metadata crítica.
- [ ] Estabelecer limites explícitos.
- [ ] Rejeitar versões desconhecidas.
- [ ] Rejeitar campos duplicados/ambíguos.
- [ ] Fuzzar o parser.
- [ ] Criar vetores externos.
- [ ] Publicar especificação independente da implementação.

## Interoperabilidade

Também falta fortalecer:

- [ ] implementação independente capaz de consumir v2;
- [ ] vetor compatível/verificável contra construção Tink;
- [ ] corpus binário oficial CryptoX;
- [ ] testes golden cross-version.

## Gate

> Um arquivo produzido por CryptoX deve poder ser especificado, validado e implementado por outra equipe sem consultar o código Go.

Esse é um gate importantíssimo se o CryptoX quiser um dia se tornar protocolo.

---

# Fase 3 — Key Management & Secure Storage

**Target:** `v0.4.0`
**Estado:** **Próxima grande fase**

Depois do envelope, essa seria minha próxima prioridade.

Criar:

```text
keys/
keyring/
securestorage/
```

## Key lifecycle

- [ ] `KeyID`.
- [ ] key purpose.
- [ ] key version.
- [ ] created-at.
- [ ] status.
- [ ] active.
- [ ] retired.
- [ ] revoked.
- [ ] rotation.
- [ ] import/export controlado.
- [ ] key hierarchy.
- [ ] master/root keys.
- [ ] derived keys.

Sugestão conceitual:

```text
Root Key
   │
   ├── Stream Key
   ├── Storage Key
   ├── Identity Key
   └── Session Key
```

Nunca reutilizar diretamente a mesma chave para contextos diferentes.

## Secure storage

- [ ] registro autenticado;
- [ ] envelope versionado;
- [ ] atomic write;
- [ ] corruption detection;
- [ ] migration;
- [ ] recovery;
- [ ] rollback limitations;
- [ ] transactional updates.

API conceitual:

```go
type Store interface {
    Put(...)
    Get(...)
    Delete(...)
}
```

A interface não deve conhecer banco, cloud ou filesystem específico.

## Adaptadores futuros

```text
securestorage/
    memory/
    file/
    android/
    apple/
    pkcs11/
```

---

# Fase 4 — Identity & Device Security

**Target:** `v0.5.0`

Aqui o CryptoX começa a ficar especialmente interessante para **agentes e máquinas**.

## Identity

- [ ] Ed25519.
- [ ] identidade persistente.
- [ ] DeviceID.
- [ ] AgentID.
- [ ] assinatura.
- [ ] verificação.
- [ ] credential format.
- [ ] key fingerprint.
- [ ] rotação.
- [ ] revogação.

Modelo:

```text
Identity
 ├── ID
 ├── Signing Public Key
 ├── Encryption Public Key
 ├── Device/Agent metadata
 └── Credential
```

## Key agreement

- [ ] avaliar X25519.
- [ ] definir contratos.
- [ ] derivar session keys.
- [ ] binding com identidade.

## Device/Agent lifecycle

- [ ] enrollment.
- [ ] verification.
- [ ] rotation.
- [ ] revocation.
- [ ] replacement.
- [ ] recovery.

---

# Fase 5 — E2EE Protocol Integration

**Target:** `v0.6.0`

Aqui eu mudaria ligeiramente a visão original.

Não pensaria apenas em “mensageiro”.

Pensaria em:

> **Secure sessions between cryptographic identities.**

Isso serve para:

- pessoas;
- dispositivos;
- serviços;
- agentes de IA;
- servidores;
- aplicações offline.

## Individual sessions

Avaliar bibliotecas/protocolos existentes para:

- authenticated key agreement;
- forward secrecy;
- post-compromise security;
- replay handling;
- out-of-order delivery.

- [ ] selecionar protocolo estabelecido;
- [ ] ADR;
- [ ] adapter;
- [ ] session state;
- [ ] persistent state;
- [ ] interrupted update recovery;
- [ ] replay handling;
- [ ] message counters;
- [ ] interoperability.

**Não inventar um Signal próprio.**

CryptoX deve ser uma camada que integra protocolos revisados.

## Group E2EE

- [ ] avaliar MLS;
- [ ] group membership;
- [ ] epoch;
- [ ] member addition/removal;
- [ ] state persistence;
- [ ] recovery.

---

# Fase 6 — Cross-Platform

**Target:** `v0.7.0`

Parte desta fase já começou antecipadamente.

## Já existente

- [x] Linux CI.
- [x] Windows CI.
- [x] macOS CI.

## Falta

- [ ] Linux ARM64.
- [ ] macOS ARM64 explicitamente validado.
- [ ] Android.
- [ ] iOS.
- [ ] bindings.
- [ ] shared interoperability corpus.

## Android

- [ ] gomobile ou estratégia equivalente.
- [ ] Android Keystore.
- [ ] lifecycle.
- [ ] process death.
- [ ] backup/restore semantics.

## Apple

- [ ] Swift-facing API.
- [ ] Keychain.
- [ ] Secure Enclave quando aplicável.
- [ ] lifecycle.

---

# Fase 7 — Hardening & Independent Security Review

**Target:** `v0.9.0`

A infraestrutura já começou bem antes da fase.

## Já existente

- [x] race detector;
- [x] fuzzing;
- [x] scheduled fuzzing;
- [x] static analysis;
- [x] govulncheck;
- [x] disclosure policy;
- [x] SBOM pipeline;
- [x] artifact provenance;
- [x] immutable GitHub Actions;
- [x] checksums;
- [x] least-privilege release workflow.

## Falta

- [ ] external cryptographic audit;
- [ ] API misuse review;
- [ ] envelope audit;
- [ ] key lifecycle audit;
- [ ] streaming implementation audit;
- [ ] persistence failure campaigns;
- [ ] longer fuzzing campaigns;
- [ ] branch/ruleset hardening;
- [ ] dependency review;
- [ ] remediation cycle.

Objetivo:

> Nenhum `critical` ou `high` conhecido sem decisão explícita de risco.

---

# Fase 8 — Stable Cryptographic Core

**Target:** `v1.0.0`

Eu reduziria deliberadamente o escopo do primeiro `v1`.

O `v1.0.0` **não precisa esperar E2EE, mobile ou post-quantum**.

## Escopo ideal do CryptoX 1.0

```text
cryptox
├── aead
├── keys
├── stream
├── envelope
└── securestorage
```

Com:

- AEAD estável;
- HKDF;
- key separation;
- streaming autenticado;
- envelopes versionados;
- secure storage básico;
- formatos publicados;
- interoperabilidade;
- auditoria independente;
- release assinado/provenance;
- API estável.

Identity e E2EE podem continuar experimentais.

## Gate v1.0

- [ ] API congelada.
- [ ] wire formats congelados.
- [ ] especificações publicadas.
- [ ] vetores oficiais publicados.
- [ ] auditoria externa concluída.
- [ ] findings tratados.
- [ ] supported platforms documentadas.
- [ ] release artifacts verificáveis.
- [ ] security policy final.
- [ ] migration policy.
- [ ] sem security blocker conhecido.

---

# Fase 9 — Advanced Crypto & CryptoX Protocol Ecosystem

**Target:** `v1.x / v2.x`

Aqui entram as coisas mais ambiciosas.

## Agent-to-Agent Security

Criar uma especificação baseada nos blocos anteriores:

```text
Agent A
   │
Identity
   │
Authenticated Session
   │
CryptoX Envelope
   │
Transport qualquer
   │
CryptoX Envelope
   │
Authenticated Session
   │
Identity
   │
Agent B
```

O CryptoX não precisaria controlar HTTP, MCP, WebSocket, Kafka etc.

Ele protegeria o **payload** independentemente do transporte.

Potencial aplicação:

```text
Codex ────────┐
Claude ───────┤
DeepSeek ─────┤── CryptoX Secure Agent Layer
Qwen ─────────┤
Local Agent ──┘
```

### Possibilidades futuras

- [ ] AgentID.
- [ ] agent credentials.
- [ ] signed task envelopes.
- [ ] encrypted agent messages.
- [ ] nonce/replay tracking.
- [ ] delegated credentials.
- [ ] capability tokens.
- [ ] agent key rotation.
- [ ] audit signatures.
- [ ] secure MCP payload profile.

Isso pode eventualmente justificar algo como:

**CryptoX Secure Agent Protocol Profile**

mas apenas em cima de primitives/protocolos revisados — não criando criptografia nova.

---

# Pós-quântico

Deixar deliberadamente para depois da fundação estável.

- [ ] ML-KEM.
- [ ] ML-DSA.
- [ ] hybrid key establishment.
- [ ] crypto agility.
- [ ] migration strategy.

Uma possibilidade futura:

```text
X25519 + ML-KEM
```

para key establishment híbrido.

Mas isso pertence ao futuro; não deve atrasar o `v1`.

---

# Prioridade real a partir de agora

## P0 — agora

1. **Revisão criptográfica independente do v2.**
2. **Especificação formal do CryptoX Envelope.**
3. **Interoperabilidade independente do streaming v2.**
4. **Congelar parâmetros criptográficos do v2 somente após revisão.**

## P1 — imediatamente depois

5. Implementar `envelope`.
6. Consolidar API pública v2.
7. Publicar corpus/vetores oficiais.
8. Definir release experimental `v0.2.x / v0.3.x`.

## P2 — próximo grande bloco

9. Key lifecycle.
10. Secure storage.
11. Rotation/revocation.
12. Key IDs e purpose hierarchy.

## P3

13. Identity.
14. X25519/Ed25519.
15. Device/Agent Identity.
16. Secure session adapters.

## P4

17. E2EE.
18. multi-device.
19. MLS.
20. mobile.

## P5

21. auditoria completa.
22. hardening.
23. v1.0.

---

# Linha de evolução recomendada

```text
                 CRYPTOX ATUAL
                      │
                      ▼
        Independent Crypto Review
                      │
                      ▼
              Freeze V2 Format
                      │
                      ▼
                 Envelope
                      │
                      ▼
          Key Management / Storage
                      │
                      ▼
             Stable Crypto Core
                      │
               ┌──────┴──────┐
               ▼             ▼
           Identity       CryptoX 1.0
               │
               ▼
         Secure Sessions
               │
          ┌────┴─────┐
          ▼          ▼
        E2EE      Agent-to-Agent
          │          │
          └────┬─────┘
               ▼
      Cross-platform ecosystem
               │
               ▼
         Post-Quantum Hybrid
```

---

# Estado resumido em outubro de 2026

Minha classificação atual seria:

**Engineering maturity:** alta para estágio experimental
**Cryptographic implementation:** boa base, ainda aguardando validação independente
**Testing:** forte
**CI/security tooling:** forte
**Supply-chain preparation:** forte
**Streaming:** v2 tecnicamente implementado
**Envelope:** próximo componente crítico
**Key management:** inicial
**Secure storage:** não iniciado
**Identity:** não iniciado
**E2EE:** não iniciado
**Production readiness:** ainda não
**Potencial para virar protocolo:** sim, mas somente após especificações e interoperabilidade independentes

---

# Próximo milestone recomendado

## `v0.2.0 — Cryptographic Foundation`

Eu faria este ser o **primeiro milestone formal fechado**.

Requisitos:

- AEAD ✅
- secure key generation ✅
- HKDF ✅
- key-purpose separation ✅
- vectors ✅
- fuzz ✅
- CI ✅
- security docs ✅
- release infrastructure ✅
- revisão independente dos parâmetros centrais ⏳

Depois:

## `v0.3.0 — Secure Streaming & Envelope`

Com:

- streaming v2;
- formato congelado;
- authenticated termination;
- metadata binding;
- envelope;
- specification;
- independent interoperability.

Esse milestone é o ponto em que eu começaria a enxergar o CryptoX não apenas como biblioteca, mas como **uma especificação criptográfica implementável por terceiros**.
