# CryptoX

**SDK criptográfico modular para Go — em desenvolvimento.**

[English](README.md) · [Português (Brasil)](README.pt-BR.md) · [简体中文](README.zh-CN.md) · [हिन्दी](README.hi.md) · [Русский](README.ru.md)

O CryptoX está evoluindo de um utilitário de cifragem de arquivos para uma biblioteca criptográfica de propósito geral. O objetivo é oferecer componentes reutilizáveis e auditáveis para cifragem, gerenciamento de chaves, armazenamento cifrado, identidade e integração com protocolos E2EE estabelecidos, sem dependência de provedores de nuvem, transportes, bancos ou frameworks.

> **Estado atual:** o código implementa geração aleatória de chaves AES e cifragem de arquivos no formato legado v1. Esse formato autentica chunks individuais, **não o arquivo completo**. Ele não detecta a remoção de chunks finais. Não use esta implementação quando houver exigência de integridade do arquivo completo. Não há alegação de auditoria independente ou prontidão para produção.

## Por que conhecer o CryptoX?

- **Pacotes por responsabilidade:** importe `keys` e `stream` diretamente, sem depender de um pacote genérico de utilitários.
- **Memória limitada por chunk:** arquivos são processados em blocos de até 64 KiB, sem carregar todo o conteúdo na RAM.
- **Poucas dependências:** a biblioteca atual usa apenas a biblioteca padrão de Go, sem CGO, serviços obrigatórios ou telemetria.
- **Falhas explícitas:** entradas malformadas e falhas de autenticação retornam erros; o destino só é publicado após sucesso da operação.
- **Engenharia verificável:** há testes adversariais, fuzzing, detector de corridas, análise estática e configuração de CI.

Hoje, o CryptoX serve para avaliar a arquitetura, estudar o formato existente e contribuir com sua modernização. Os objetivos futuros incluem anexos seguros, backups, armazenamento offline, comunicação entre serviços, identidade de dispositivos e integrações E2EE. São casos de uso pretendidos, não soluções completas já entregues. Não há comparações verificadas de desempenho nem garantias de superioridade sobre outras bibliotecas.

## O que existe hoje?

| Pacote | API disponível | Comportamento |
| --- | --- | --- |
| `keys` | `GenerateKey(size int) ([]byte, error)` | Gera chaves AES de 16, 24 ou 32 bytes com `crypto/rand`. |
| `stream` | `EncryptLargeFiles(infile, outfile string, key []byte) error` | Cifra um arquivo com AES-GCM no formato legado v1. |
| `stream` | `DecryptLargeFiles(infile, outfile string, key []byte) error` | Verifica cada chunk e grava o arquivo recuperado; não verifica sua completude. |
| `stream` | `ValidateEncryptedFile(filename string) error` | Verifica somente o cabeçalho. **Não** verifica ciphertext nem tags. |
| `utils` | As mesmas quatro funções legadas | Fachada obsoleta de compatibilidade que delega a `keys` e `stream`. |

As APIs públicas recebem caminhos de arquivos. APIs públicas `io.Reader`/`io.Writer`, término autenticado, HKDF, envelopes, armazenamento seguro, identidades, ratchets, proteção contra replay, bindings mobile e suporte pós-quântico **não estão implementados**.

O código declara Go 1.19 como nível mínimo de compatibilidade. Use uma versão mantida do Go para desenvolver e executar aplicações; compatibilidade mínima de código não é recomendação de segurança. O núcleo não exige CGO, mas `go test -race` exige plataforma compatível e toolchain C.

## Instalação

### Usar o checkout local

Para experimentar exatamente a implementação descrita aqui, aponte um módulo de demonstração separado para seu checkout do CryptoX. Substitua `/absolute/path/to/cryptox` pelo caminho absoluto real:

```sh
mkdir cryptox-demo
cd cryptox-demo
go mod init example.com/cryptox-demo
go mod edit -require=github.com/Hangell/cryptox@v0.0.0
go mod edit -replace=github.com/Hangell/cryptox=/absolute/path/to/cryptox
```

Nesse caso, `v0.0.0` é apenas um marcador de requisito do módulo local, não uma afirmação de release publicado. A diretiva `replace` faz o Go usar seus arquivos locais.

### Usar o módulo remoto

Dentro de um módulo Go existente:

```sh
go get github.com/Hangell/cryptox
```

Esse comando baixa a versão disponível no repositório remoto, **não as alterações locais ainda não publicadas**. Confirme que a revisão escolhida contém `keys` e `stream`; pacotes e formatos podem mudar durante a modernização. Este documento não afirma a existência de release estável nem sucesso atual do CI remoto.

## Exemplo: gerar chave, cifrar, validar o cabeçalho e decifrar

Salve o código abaixo como `main.go` em `cryptox-demo` e execute `go run .`:

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

Saída esperada: `Round trip OK`. O exemplo usa arquivos descartáveis e os remove ao terminar. Apenas a demonstração lê todo o pequeno plaintext para comparar o resultado; a biblioteca processa arquivos incrementalmente.

A chave fica na memória durante essa execução. Para dados persistentes, a aplicação deve guardar e recuperar a chave separadamente de forma segura; o CryptoX ainda não oferece um cofre de chaves. Perder a chave significa perder acesso aos dados. Nunca imprima nem versione chaves, e não use senhas diretamente como chaves AES. A derivação de senhas não está implementada. Use uma chave nova por arquivo v1; a API não impõe essa política.

Consumidores existentes ainda podem importar `github.com/Hangell/cryptox/utils` e usar os mesmos nomes de função. Em código novo, prefira os pacotes específicos. Isso descreve a compatibilidade atual, não uma promessa de preservação das APIs legadas nas próximas mudanças.

## Limites de segurança e formato legado

```text
Header (21 bytes): "SYM1" | version=1 | "AESG" | base nonce (12 bytes)
Record: ciphertext length (uint32 LE) | ciphertext | GCM tag (16 bytes)
Nonce: random prefix (8 bytes) | chunk counter (uint32 LE)
```

O campo de comprimento inclui a tag GCM. Os quatro últimos bytes do nonce no cabeçalho devem ser zero; cada registro usa seu contador sequencial. Contadores são rejeitados antes de ultrapassar `uint32`, impedindo que voltem a zero dentro de um arquivo.

- **Aceitação de arquivo incompleto:** remover registros finais completos pode passar despercebido. Um arquivo vazio não tem tag e não autentica a chave.
- **Autenticação incompleta dos metadados:** o cabeçalho passa por validação estrutural, mas não é autenticado integralmente como dado associado.
- **Colisão de nonces entre arquivos:** o prefixo aleatório tem apenas 64 bits. Reutilizar uma chave entre arquivos pode causar colisões de prefixo. Verificar o contador não elimina esse risco.
- **Publicação do arquivo:** temporários exclusivos são criados no diretório de destino com modo Unix `0600`; dados são sincronizados e o arquivo é fechado antes do rename. Em falhas, a limpeza é tentada e o destino não é substituído intencionalmente. Operações bem-sucedidas podem substituir uma saída existente; crie o diretório pai antes e escolha os caminhos com cuidado.
- **Limites do sistema operacional:** use um diretório de destino confiável. Windows exige ACLs apropriadas; a atomicidade do rename depende do SO/filesystem. O diretório não é sincronizado, portanto não há garantia de durabilidade após queda. Uma interrupção do processo pode deixar temporários.
- **Limites de proteção de segredos:** Go não garante limpeza imediata da memória. Este código não protege contra processo/SO comprometido, rollback de armazenamento, replay ou análise de metadados, e não é um protocolo E2EE.

Usar AES-GCM, por si só, não torna seguro um formato de arquivo. O formato substituto precisa autenticar metadados e término explicitamente e passar por revisão adequada; essas propriedades não podem ser atribuídas retroativamente ao v1.

## Arquitetura e direção

O projeto segue princípios modulares e hexagonais: consumidores usam pacotes específicos; adaptadores opcionais dependem dos contratos do núcleo; o núcleo permanece independente de infraestrutura. Interfaces são introduzidas em fronteiras reais, não em toda função.

| Componente planejado | Responsabilidade |
| --- | --- |
| `aead` | Cifragem autenticada e gerenciamento de nonces. |
| Expansão de `keys` | Derivação, separação por finalidade, ciclo de vida e integração com armazenamento. |
| Substituição de `stream` | Enquadramento, metadados, ordenação e término autenticados. |
| `envelope` | Formatos explicitamente versionados para objetos cifrados. |
| `securestorage` | Estado cifrado e adaptadores opcionais de persistência. |
| `identity` / `pki` | Identidade de dispositivos, assinaturas, credenciais, certificados e validação de confiança. |
| `e2ee` | Adaptadores para protocolos estabelecidos de sessões/grupos, escolhidos após revisão. |

Entre as tecnologias candidatas estão ChaCha20-Poly1305, HKDF, X25519, Ed25519, Argon2id, MLS e mecanismos pós-quânticos revisados. São candidatos para avaliação, não capacidades instaladas nem uma receita de protocolo próprio. O CryptoX não implementará servidores de mensagens, cadastro de usuários, filas, entrega de push ou orquestração de nuvem.

## Roadmap

O [ROADMAP.md](ROADMAP.md) detalha os critérios de aceite e estas metas de planejamento:

| Fase | Meta | Objetivo |
| --- | --- | --- |
| 0 | v0.1.0 | Diagnóstico de segurança e base arquitetural. |
| 1 | v0.2.0 | Fundação criptográfica e controles de engenharia. |
| 2 | v0.3.0 | Streaming seguro e envelopes. |
| 3 | v0.4.0 | Gerenciamento de chaves e armazenamento seguro. |
| 4 | v0.5.0 | Identidade e segurança de dispositivos. |
| 5 | v0.6.0 | Integração com protocolos E2EE estabelecidos. |
| 6 | v0.7.0 | Integração multiplataforma e mobile. |
| 7 | v0.9.0 | Fortalecimento e revisão independente. |
| 8 | v1.0.0 | Núcleo criptográfico estável e validado. |
| 9 | v1.x / v2.x | Criptografia avançada e ecossistema. |

Essas metas não são releases publicados nem datas de entrega. Código e testes existentes não comprovam conclusão de fase. O formato cifrado **v1** é distinto da versão de módulo/release Go **v1.0.0**. A política atual de modernização permite quebras documentadas de compatibilidade; E2EE e mobile podem continuar experimentais após um release estável do núcleo.

## Testes e CI

Execute na raiz do repositório CryptoX. O primeiro bloco usa Make; o segundo apresenta comandos diretos, incluindo análise de vulnerabilidades:

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

Os testes cobrem as quatro funções de `utils`, tamanhos de chave AES, limites de chunks, chaves incorretas, cabeçalhos/comprimentos malformados, chunks modificados/reordenados, leituras fragmentadas, escritas curtas, propagação de erros, limpeza de temporários e preservação do destino. Casos paralelos usam arquivos independentes. Também há testes que registram a limitação de truncamento do v1. O fuzzing verifica invariantes de falha, não apenas ausência de panic.

O [workflow CI](.github/workflows/ci.yml) está configurado para pushes, pull requests, execução manual e semanal. Define jobs Linux/Windows/macOS com Go `stable`, jobs adicionais Linux com `oldstable` e `1.19.13`, artefatos de cobertura e JSON, fuzzing e `govulncheck`. Configuração não comprova sucesso remoto: consulte a execução do seu commit. Cobertura e testes aprovados não substituem revisão criptográfica independente.

## Documentação e contribuição

Os três documentos principais de engenharia são:

- [AGENTS.md](AGENTS.md): missão, regras obrigatórias e critérios de aceite.
- [ARCHITECTURE.md](ARCHITECTURE.md): módulos-alvo, contratos, fronteiras de confiança e modelo de ameaças.
- [ROADMAP.md](ROADMAP.md): prioridades, dependências, marcos e critérios de release.

[CONTRIBUTING.md](CONTRIBUTING.md) descreve as verificações para contribuir. [THREAT_MODEL.md](THREAT_MODEL.md) aponta para o modelo de ameaças mantido no documento de arquitetura. [SECURITY.md](SECURITY.md) documenta os limites atuais e o procedimento de relato de vulnerabilidades. Use o relato privado do GitHub se estiver disponível; caso contrário, solicite um canal confidencial sem publicar detalhes sensíveis. A política não afirma que o relato privado está habilitado nem estabelece SLA de resposta. Nunca publique segredos ou detalhes sensíveis de exploração.

Contribua com mudanças pequenas e revisáveis: examine a implementação, adicione testes de regressão/adversariais antes de correções críticas, execute as verificações e documente premissas de segurança e mudanças de API/formato. Use identificadores e comentários de código em inglês e Conventional Commits explicando o motivo. Mantenha as cinco traduções do README alinhadas quando o comportamento mudar.

## Licença

[MIT](LICENSE) — Copyright (c) 2025 Rodrigo Rangel.
