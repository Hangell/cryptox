# Diagnóstico e evolução incremental

> Registro histórico anterior aos testes ampliados e à configuração de CI.
> As ações e políticas abaixo descrevem aquele incremento, não obrigações futuras.
> Estado atual: [ROADMAP.md](../../ROADMAP.md#current-progress).
> Política de compatibilidade: [ARCHITECTURE.md](../../ARCHITECTURE.md#20-versioning-and-compatibility).

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
