# Contributing

## Start with the engineering documents

Read [AGENTS.md](AGENTS.md), [ARCHITECTURE.md](ARCHITECTURE.md), and
[ROADMAP.md](ROADMAP.md), then inspect the relevant implementation. These are the
primary sources for engineering rules, target architecture, and progress.
[SECURITY.md](SECURITY.md) defines security limitations and reporting procedures.

Keep contributions small and reviewable. Record the problem and expected behavior,
add a regression or adversarial test before critical fixes, and document the
result and remaining risks. Use English identifiers and code comments.

## Compatibility during modernization

Legacy API and format compatibility is not a release requirement during the
initial modernization. Preserve it only when useful and safe; do not retain an
unsafe capability solely for compatibility.

Document every intentional API or format break, affected callers/data, and any
migration or recovery path. If no migration is provided, say so explicitly.
Never reinterpret v1 ciphertext as having new security guarantees. A changed
cryptographic format needs an explicit identifier and security review.

The current `utils` facade is an implementation detail of the existing baseline,
not a commitment to retain that package in future releases.

## Validate the change

Run from the repository root:

```sh
make check
make fuzz
```

`make check` verifies formatting, runs `go vet`, and runs tests with race detection
and coverage. `make fuzz` runs the existing legacy-format fuzz target for 30 seconds.
See [README.md](README.md) for direct Go commands and vulnerability analysis.

For documentation-only changes, check relative links, examples, and consistency
across translations; new tests or repeated fuzzing are not required without a
behavioral change. Compile and run code examples when they change.

The configured CI targets Linux, Windows, and macOS and publishes test reports.
Configuration alone does not prove remote success or enforce branch protection.
Go 1.19 is the minimum source compatibility level; use a maintained toolchain in
real applications. Race detection requires a supported platform and C toolchain.

## Describe and submit

Use Conventional Commits, with the reason for the change in the body. A review
should explain the problem, resulting behavior, validation, compatibility impact,
and material limitations. Security-sensitive changes require specific review;
test coverage is not proof of cryptographic security.

Keep all five README translations aligned. Update roadmap progress only when
supported by implementation and validation evidence. Do not mark a phase complete
because individual preparatory tasks pass.
