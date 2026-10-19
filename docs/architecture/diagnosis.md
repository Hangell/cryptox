# Diagnóstico e evolução incremental

## Estado atual (2026-10-18, commit 3a588eb)

> Reconciliado com o código no commit `3a588eb` e com as alterações locais de
> documentação. O [registro histórico](#registro-histórico) abaixo permanece
> como contexto do incremento inicial e **não** descreve o estado atual.
> Política de compatibilidade: [ARCHITECTURE.md](../../ARCHITECTURE.md).

### Inventário por pacote

| Pacote | Status | Evidência |
| --- | --- | --- |
| `keys` | implementado | `GenerateKey` (`crypto/rand`) e `DeriveKey` (HKDF-SHA-256 com `Purpose`); vetores RFC 5869. |
| `aead` | implementado | AES-256-GCM `Seal`/`Open`; vetor NIST GCM TC15 e Wycheproof. |
| `stream` | implementado (v1 e v2) | v1 legado (`EncryptLargeFiles`/`DecryptLargeFiles`/`ValidateHeader`); v2 (`NewEncryptor`/`NewDecryptor`, `EncryptFileV2`/`DecryptFileV2`) com terminação autenticada. |
| `envelope` | implementado | Envelope v1 `Seal`/`Open`; especificação em `docs/spec/envelope-v1.md`. |
| `utils` | implementado (deprecado) | Fachada de compatibilidade delegando a `keys`/`stream`. |
| `securestorage`, `identity`, `e2ee`, `pki` | ausente | Sem implementação nesta entrega. |

### Mapa de dependências

- consumidor → `utils` → `stream`/`keys` → biblioteca padrão.
- consumidor → `stream` (v2) → biblioteca padrão (`crypto/aes`, `crypto/cipher`, `crypto/hmac`, `crypto/sha256`, `crypto/rand`).
- consumidor → `aead` → biblioteca padrão.
- consumidor → `envelope` → biblioteca padrão.
- Nenhuma dependência externa, CGO, serviço obrigatório ou telemetria.

### Matriz de riscos (atual)

| Risco | Status | Evidência | Tratamento |
| --- | --- | --- | --- |
| v1: truncamento silencioso (CX-V1-001) | aberto (v1) | `TestV1TrailingTruncation` | Substituído pelo v2; v1 nunca reinterpretado como v2. |
| v1: prefixo de nonce de 64 bits (CX-V1-002) | aberto (v1) | `EncryptLargeFiles` | v2 deriva chave por stream (randomizer de 312 bits). |
| v2: parâmetros sem revisão independente | aberto (v2) | ADR 0002 + design review | Bloqueia congelamento do formato; card #71. |
| stream/envelope: sem vetor independente | aberto | corpus golden (regression pin) | Vetor Tink/externo pendente; cards #73 e #78. |
| Publicação de arquivo: durabilidade | documentado | `publication_test.go`, §7.4 | Não-garantia explicitada por plataforma. |

### Reconciliação de cards (implementações vs. granular)

Os cards granulares #19–#69 (Fases 1–2) foram entregues pelas issues e PRs já
incorporados; não devem ser duplicados:

| Cards | Entrega |
| --- | --- |
| P1.01–P1.04, P1.05–P1.15, P1.21–P1.22 | `aead` + `keys` (issues #19, #20, #21) |
| P1.16–P1.20, P1.23–P1.24 | CI, Makefile, lint, release (issues #24, #26, #27) |
| P2.01–P2.22 | streaming v2 + file adapters (issues #16, #17, #22, #23) |
| P2.23–P2.29 | Envelope v1 (PR envelope) |

Cards sobrepostos devem ser encerrados/revisados pelo codex com referência à
evidência acima; este documento não os marca como concluídos.

## Registro histórico

> Incremento inicial anterior aos testes ampliados e à configuração de CI.
> As ações e políticas abaixo descrevem aquele incremento, não o estado atual.
> Política de compatibilidade: [ARCHITECTURE.md](../../ARCHITECTURE.md).

Data: 2026-10-18. Escopo: estado local anterior à implantação do CI.

## Inventário e dependências

- `keys.GenerateKey`: chaves AES de 16, 24 e 32 bytes via `crypto/rand`.
- `stream`: arquivos AES-GCM v1, parsing binário e publicação por temporário.
- `utils`: fachada pública de compatibilidade, inicialmente sem testes próprios.
- Um módulo Go; somente biblioteca padrão, sem serviços, CGO ou dependências externas.
- Dependências: consumidor → `utils` → `stream`/`keys` → biblioteca padrão.
- Testes existentes: round trip, algumas corrupções, contador e vetor fixo.
  Fuzzing inicialmente verificava apenas ausência de panic. Sem CI.

## Matriz de riscos

| Prioridade | Evidência | Impacto / tratamento |
| --- | --- | --- |
| P0 | EOF entre registros é aceito, sem registro final autenticado | Truncamento silencioso. Inerente ao v1; exige novo formato revisado. |
| P0 | Prefixo aleatório de apenas 64 bits por arquivo | Colisões sob chave compartilhada; chave nova por arquivo é orientação operacional, não garantia imposta pela API. |
| P1 | Cabeçalho fora do AAD; arquivo vazio sem tag | Não há autenticação completa de metadados nem da chave para arquivo vazio. Manter limitação explícita. |
| P1 | Ausência de testes de contrato de `utils` e CI | Regressões não bloqueadas automaticamente; adicionar ambos. |
| P1 | Parser ligado a arquivos | Leitura fragmentada não exercitada diretamente; extrair parser interno com `io.Reader`, sem nova API pública. |
| P2 | Temporário contém plaintext antes do sucesso | `0600` em Unix; ACLs no Windows e processo comprometido exigem controles externos. |
| P2 | Rename sem sincronização do diretório | Durabilidade em queda de energia não garantida; atomicidade depende do SO/filesystem. |
| P2 | Go com garbage collector | Apagamento garantido de chaves e plaintext da memória não disponível. |

A correção prévia já inclui temporários exclusivos, contador amplo com limite uint32,
leitura completa do campo de comprimento e validação dos bytes reservados do nonce.
Esses controles não eliminam os riscos estruturais P0 do v1.

## Arquitetura-alvo

Manter um módulo e fronteiras pequenas. A fachada `utils` permanece compatível.
Isolar parsing de I/O de arquivos em `stream`; somente o adaptador de arquivo
publica o resultado após sucesso. Não expor esse parser como streaming seguro.

Introduzir `aead`, `envelope`, `securestorage`, `identity`, `e2ee` e `pki` apenas
com contrato, implementação e testes. Integrações dependem do núcleo, nunca o
inverso. Protocolos E2EE serão adaptadores de implementações estabelecidas.
Nenhuma dessas funcionalidades está implementada nesta entrega.

## Backlog por risco, dependência e valor

1. **P1, imediato:** testes de contrato de todas as funções `utils`, corrupção,
   erro de I/O, concorrência, preservação do destino e fuzzing com invariantes;
   CI multiplataforma com race detector, vet e relatórios. Sem dependências novas.
2. **P0, próximo:** avaliar construções reconhecidas de streaming, especificar v2,
   threat model detalhado, revisão criptográfica e vetores externos antes de
   congelar o formato. Depende de escolha fundamentada e revisão especializada.
3. **P1:** leitor legado isolado e migração explícita para v2. Depende do item 2;
   nunca interpretar v1 como se autenticasse o arquivo completo.
4. **P1:** análise de vulnerabilidades e SBOM por CI; processo de divulgação.
   Proveniência e assinatura dependem de definir o processo de releases.
5. **P2:** benchmarks reproduzíveis AMD64/ARM64 e contratos de envelopes/chaves;
   armazenamento opcional após núcleo e formato revisados.
6. **P2:** identidade, adaptadores E2EE, bindings mobile e auditoria independente.

## Compatibilidade e aceite

Preservar assinaturas, imports `utils` e bytes v1; testar interoperabilidade entre
fachada e implementação. Rejeitar entrada malformada sem substituir o destino.
Não usar cobertura como prova de segurança. Linux é validado localmente;
Windows/macOS dependem da execução da matriz CI. Nenhuma fase completa do roadmap
é declarada concluída: v1 continua inadequado quando integridade global é exigida.
