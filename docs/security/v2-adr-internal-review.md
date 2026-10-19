# Internal review of ADR 0002 against Phase 0 requirements

Status: **internal (maintainer) review** — card P0 (streaming ADR review). This
document records, per criterion, whether ADR 0002 and its evidence meet the
ROADMAP Phase 0 requirements **as far as the maintainers can judge internally**.
It does **not** approve cryptographic parameters: format approval is reserved to
the independent specialist review (#71) and the ADR approval decision (#72).

Reviewed artifact:
[docs/adr/0002-streaming-construction-selection.md](../adr/0002-streaming-construction-selection.md).
Reviewed at commit `fa40380` (post P4 review fixes); the ADR text is unchanged
since `5dca04f` except for the freeze wording recorded below.

## Classification

Each criterion is classified as:

- **Aprovado internamente** — the ADR records a decision with supporting
  evidence; maintainers judge it sufficient for the experimental phase only.
- **Pendente** — the decision is recorded but depends on an external
  requirement or a later card.
- **Insuficiente** — the ADR does not yet satisfy the requirement even for the
  experimental phase.

No criterion in this review is "insuficiente"; all open items are "pendente" and
are blocked on the independent specialist review.

## Evaluation against the eight replacement-format gates (ARCHITECTURE.md §14.7)

| # | Gate | Classification | Evidence | Blocker / owner |
| --- | --- | --- | --- | --- |
| 1 | Authenticated headers, suite/version, ordering, termination, empty streams, suffix removal | Aprovado internamente | ADR §Decision and gate table; v2 (`CXS2`) implemented and tested against truncation/reorder/duplication; empty stream = one final segment | — |
| 2 | Nonce/key lifecycle, domain separation, randomness, quantitative limits | **Pendente** | ADR records random salt+prefix, per-stream HKDF key, `n ≤ 2^32`, `≤ 2^48` bytes/stream; concrete HS20 multi-user/multi-key bound not yet computed | Independent specialist review (#71) |
| 3 | Bounded framing, malformed input, unknown versions, no downgrade/reinterpretation | Aprovado internamente | ADR §Decision; v2 strict header/version/suite parsing; v2 never parsed as v1 | — |
| 4 | Plaintext-release limits | Aprovado internamente | ADR §Plaintext-release limits; transactional file adapter publishes only after final segment | — |
| 5 | Independent vectors, cross-implementation tests, mutation/property, fuzzing, review plan | **Pendente** | Internal tests, Python reference (`testdata/interop/ref.py`), golden corpus, fuzz targets exist; independent specialist review of parameters still open | Independent specialist review (#71) |
| 6 | Maintenance, licensing, dependency cost, platforms | Aprovado internamente | ADR §Evidence register; standard-library-only decision keeps core CGO-free and dependency-free | — |
| 7 | v1 migration / no-migration policy | Aprovado internamente | ADR §v1 migration; ADR 0004 + `docs/security/v1-migration.md` | — |
| 8 | Scope exclusions (replay, rollback, metadata privacy, compromised endpoints) | Aprovado internamente | ADR gate table row 8 | — |

## Evaluation against ROADMAP Phase 0 remaining items

| ROADMAP item | Classification | Blocker / owner |
| --- | --- | --- |
| Obter revisão criptográfica independente dos parâmetros v2 | **Pendente** | External specialist reviewer (#71) |
| Validar concretamente os limites multi-user/multi-key do STREAM/HS20 | **Pendente** | Independent specialist review (#71) |
| Confirmar formalmente o `domainSep` | **Pendente** | Independent specialist review (#71) |
| Confirmar limites de uso por chave | **Pendente** | Independent specialist review (#71) |
| Aprovar definitivamente o formato binário v2 | **Pendente** | Reserved to #72 (after #71) |
| Mudar ADR 0002 de proposta/revisão interna para decisão aprovada | **Pendente** | Reserved to #72 (after #71) |

## Blockers

1. **Independent specialist review (#71).** The only blocker for the pendente
   items above is a real cryptographic review by a qualified specialist. An
   automated agent review (see `docs/security/v2-independent-review.md`) does
   **not** satisfy this requirement. No in-repository maintainer can approve
   these parameters in the specialist's name.
2. **ADR approval decision (#72).** After #71, the maintainer records the
   specialist's verdict and changes ADR 0002 to the approved decision, or
   revises the construction.

## Reservation

Format approval and the ADR status change are explicitly **reserved to #71–#72**.
This internal review may close only the "review the ADR and record open
decisions" card; it does not freeze, approve, or promote the v2 format.

## Residual limitations

- Internal judgment is not a substitute for the specialist review; a criterion
  marked "aprovado internamente" remains experimental until Phase 0 exits.
- The HS20 multi-user/multi-key concrete bound is the single unresolved
  quantitative item; mechanical limits alone do not establish a per-key usage
  budget.
