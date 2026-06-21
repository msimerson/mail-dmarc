<!-- agents-version: 1 -->

# AGENTS.md

Shared instructions for coding agents working in this repository.
Tool-specific instruction files should defer to this file.

## Repository model

- This is a **single Perl distribution** (`Mail-DMARC`).
- Primary code lives in `lib/Mail/DMARC/**/*.pm`.
- CLI entry points live in `bin/` (`dmarc_receive`, `dmarc_send_reports`, `dmarc_httpd`, etc.).
- Test suites live in `t/*.t`; author-quality checks live in `xt/`.
- Runtime assets and schemas live in `share/` (INI template, SQL schemas, PSL, web UI files).
- Dependency/build metadata is maintained in `Makefile.PL`, `Build.PL`, `META.json`, and `META.yml`.

## Working agreement

- Do only what was requested. If you find adjacent issues, call them out but do not expand scope.
- Preserve backwards compatibility unless the task explicitly requires a behavior change.
- For DMARC protocol logic, align with the most recent DMARC RFCs, including 9990, 9989, 8616, and 7489.

## Source control

- Do not run history/remote-mutating commands (`git commit`, `git push`, `git tag`, PR creation) unless explicitly asked.
- Keep diffs focused and minimal; avoid broad refactors when solving targeted bugs.
- add concise single-line Conventional Commit messages in imperative mood when making changes.

## Perl coding standards

- We want code that is maintainable, idiomatic, and robust
- Place a strong emphasis on quality and correctness
- Maintain compatibility with the distribution’s effective baseline (runtime requires Perl 5.32.0).
- Use the existing style in touched files:
  - `use strict;` and `use warnings;`
  - 4-space indentation
  - mostly procedural OO style with explicit accessor methods
  - `Carp::croak`/`carp` for argument and runtime validation errors
- Follow `.perltidyrc` when formatting:
- Respect Perl::Critic rules in `xt/perlcritic.rc`:
- Prefer existing dependency patterns already used in the repo (`Config::Tiny`, `DBIx::Simple`, `HTTP::Tiny`, etc.) over introducing new stacks.
- This is production software used on thousands of servers, not a CPAN showcase. Keep dependencies trim and tidy.
- When refactors are necessary, favor making it easier to reason about the code.

## Module and architecture conventions

- Keep package boundaries consistent with `Mail::DMARC::*` naming and existing file layout.
- Preserve broker patterns:
  - `Mail::DMARC::Report::Send` dispatches protocol-specific senders.
  - `Mail::DMARC::Report::Store` dispatches backend implementations.
- Reuse existing helpers in `Mail::DMARC::Base` for config loading, DNS, IP/domain validation, and PSL handling.
- When adding configuration options, wire them through `mail-dmarc.ini` conventions and ensure defaults/fallbacks remain safe.
- When touching report persistence, keep SQLite/MySQL/PostgreSQL behavior aligned.

## Testing expectations

- For bug fixes, add a test that fails before the fix and passes after.
- Every new feature type MUST have a corresponding test file with high coverage of valid and invalid inputs.
- Prefer integration-style assertions of observable behavior over internal call-shape assertions.
- Standard local test flow:
  1. `perl Makefile.PL`
  2. `make test`
- Author checks (when relevant):
  - `AUTHOR_TESTING=1 prove xt/author-critic.t`
- Many tests are dependency-sensitive (DBD drivers, XML validators, optional modules) and may skip conditionally; preserve skip logic.

## Changelog and documentation conventions

- Changelog file is `CHANGELOG.md`.
- Keep reverse-chronological sections in this format:
  - `### Unreleased`
  - `### <version>`
  - bullet list entries starting with `- `
- Prefer terse changelog bullets with optional Conventional Commit prefixes (`feat:`, `fix:`, `doc:`, `test:`, `chore:`) and PR references when known.
- `README.md` is generated from `lib/Mail/DMARC.pm` POD (see `.release/update-readme.sh` and `.release/version_increment.sh`).
  - For durable README content changes, edit POD in `lib/Mail/DMARC.pm` first, then regenerate README.
- Keep standalone docs (`INSTALL.md`, `DEVELOP.md`, `FAQ.md`, `TODO.md`) concise, heading-driven, and command/example oriented.

## Release and versioning notes

- Version is declared in module files (`our $VERSION`) and reflected in `README.md` and `Changes.md`.
- Release scripts in `.release/` automate version bumping, README regeneration, and metadata refresh.
- Avoid manual metadata drift: if version/dependency metadata changes, keep `Makefile.PL`, `Build.PL`, and `META.*` consistent.

## Commands (repo root)

- Install deps quickly: `perl bin/install_deps.pl`
- Build metadata: `perl Makefile.PL`
- Run tests: `make test`
- Optional author critic: `AUTHOR_TESTING=1 prove xt/author-critic.t`
- Regenerate README from POD: `.release/update-readme.sh`
