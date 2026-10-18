# Modelo inicial de ameaças — legado v1

Escopo: biblioteca local, chave fornecida pelo chamador, entrada potencialmente
hostil e diretório de saída controlado pelo chamador. Processo/OS comprometido,
ACLs inseguras e manipulação concorrente do diretório por terceiros ficam fora
das garantias. Não há protocolo de identidade ou autenticação de usuários.

| STRIDE | Ameaça e estado |
| --- | --- |
| Spoofing | Chave errada é rejeitada em chunks autenticados; arquivo vazio não comprova posse da chave. |
| Tampering | Tags por chunk rejeitam alteração e reordenação; remoção de sufixos continua possível. |
| Repudiation | Sem assinaturas ou trilha de auditoria; não há não repúdio. |
| Information disclosure | Temporários restritos em Unix; tamanho e número de chunks visíveis; memória não apagada de forma garantida. |
| Denial of service | Comprimentos limitados antes de alocar; tempo total proporcional à entrada e armazenamento sem quota própria. |
| Elevation of privilege | Nenhuma elevação solicitada; exclusividade do temporário evita seguir um `.part` previsível; diretório deve ser confiável. |

LINDDUN: ciphertexts, nomes/caminhos externos e tamanhos podem permitir vinculação,
identificação e inferência; o formato é detectável por magic bytes. Não há
não repúdio por identidade. A biblioteca não gerencia consentimento, direitos de
titulares ou retenção. Documentar esses limites reduz desconhecimento, mas não
constitui conformidade jurídica ou proteção contra observadores do filesystem.

Controles verificados: validação de cabeçalho e comprimentos, autenticação por
chunk, preservação do destino após falha e limpeza de temporários. Controles
pendentes: término e metadados autenticados no v2, estratégia de nonces revisada,
vetores de interoperabilidade externos e auditoria independente.
