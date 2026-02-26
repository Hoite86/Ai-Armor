# AI Armor (Desktop, local-first)

AI Armor is an Ubuntu-focused desktop tray app (with Windows support) that helps protect copy/paste workflows when using AI tools.

## What it does

- Watches clipboard text changes locally (Linux polling listener on this branch, Windows event listener still supported).
- Shows a smart toast when it detects:
  - sensitive data → **Protect for AI**
  - existing AI Armor tokens → **Restore details**
- Never auto-modifies clipboard; it only writes after explicit user action.
- Supports one-level in-memory **Undo** (2-minute expiry).
- Supports high-risk-only mode and per-app ignore rules.
- Includes an in-app Terms of Service acknowledgement gate with standardized liability/usage language.

## Privacy guarantees

- No accounts
- No servers
- No telemetry / analytics
- No crash upload
- No network dependency for core functionality
- No keylogging
- No OCR
- No window content scraping
- No clipboard history storage

All detection and restore operations are local.

## Architecture

Rust workspace crates:

- `core-model`: shared domain models (`EntityKind`, `DetectedEntity`, session/mapping types)
- `core-detect`: deterministic local detectors + overlap resolution + pattern suggestion helpers
- `core-tokenize`: reversible tokenization (`[[AA1:TYPE_01]]`) and restoration
- `core-crypto`: DPAPI key wrapping helpers + hashing
- `core-vault`: SQLCipher-backed encrypted session vault, TTL purge, restore matching
- `apps/desktop-tauri/src-tauri`: tray application shell, commands, Windows listener, and Linux polling listener

## Detection classes (MVP)

Built-in classes:

- EMAIL, PHONE, SSN, CARD (with Luhn), IP, URL
- JWT, Bearer, AWS key patterns, common provider/API key formats, and private key blocks
- high-entropy token heuristics for long base64-like and long hex strings
- user-defined sensitive terms
- user-defined custom patterns (built from examples via regex suggestion)

Overlap resolution priority:

`PRIVATEKEY/APIKEY/TOKEN > CARD > SSN > JWT/Bearer > EMAIL > PHONE > IP/URL > TERM`

## Custom PII builder (no raw regex required)

In Settings UI:

1. Enter a sample sensitive value (example format).
2. AI Armor suggests a regex based on that sample shape.
3. App runs a quick match test against the sample.
4. Save/update the custom pattern locally.

This supports customer-specific IDs without forcing users to author regex manually.

## Terms of Use (user-visible)

Before protection actions run, users must agree once to a local Terms notice stating that:

- AI Armor assists with preserving sensitive information but does not replace security policy or endpoint controls.
- Responsibility for safeguarding data remains with the user/operator.
- The software stores data locally on the host system.
- The software is not anti-malware software and cannot guarantee prevention of all data breaches.
- Users acknowledge the software is provided "AS IS" for assistance only, and (to the extent permitted by law) waive claims including legal action against the developer for exposure, misuse, breach, or third-party compromise.


## In-app help menu

The settings UI includes a Help section that explains:

- Protect for AI and Restore details flows
- High-risk mode behavior
- Custom rules and example-to-regex pattern creation
- Pause/ignore/purge safety controls
- Manual update process using an admin-provided website URL
- Optional signed package verification (SHA-256 + detached signature) before install

## Hardening controls

To make usage safer, AI Armor applies guardrails in the desktop command layer:

- Input-size limits for clipboard protect/restore operations.
- Settings normalization for TTL, ignored apps, and sensitive term lengths/counts.
- Custom-pattern safety checks (length limits, unsafe regex construct rejection, compile validation, and sample-match verification before save).
- Local persistence only, with no telemetry or network requirements for core logic.


## Token security model (better than changing algorithm each release)

AI Armor uses per-session uniqueness rather than "new algorithm every version" (security-by-obscurity).

- Each protect operation creates a new session id and session tag.
- Token IDs include a short per-token signature suffix derived from session id + token type + index + value.
- Without the local encrypted vault mappings, pasted tokens are not reversible to plaintext.

This gives strong practical isolation between sessions while keeping restore reliable.

## How Protect for AI works

1. Clipboard text is scanned locally.
2. Sensitive spans are replaced with stable left-to-right tokens such as `[[AA1:EMAIL_01_X9K2]]`.
3. Token mappings are saved encrypted at rest in SQLCipher vault with TTL (default: 24h).
4. Protected text is written to clipboard only after user confirms.

## How Restore details works

1. Tokens are extracted from clipboard text.
2. Session selection prefers embedded session tag (e.g., `AA1`).
3. If no tag is available, best-overlap matching against recent sessions is used.
4. Decrypted mappings are applied locally and restored text is written to clipboard.

## Build and run

### Prerequisites

- Ubuntu 22.04+ (primary target for this branch)
- Rust stable toolchain (`rustup`, `cargo`)
- Linux desktop with X11/Wayland clipboard support
- Tauri v2 Linux prerequisites (webkit2gtk + build-essential + pkg-config + libssl-dev)

### Fast path (recommended on Ubuntu/Linux)

From repo root:

```bash
./scripts/ubuntu-setup-and-build.sh
```

What this does:
1. Verifies `cargo` is installed.
2. Runs `cargo fetch` so dependencies are downloaded locally.
3. Runs core crate tests.
4. Launches AI Armor for local testing on Linux.

### Build release binary (Ubuntu/Linux)

```bash
RELEASE=1 ./scripts/ubuntu-setup-and-build.sh
```

Output binary:
- `apps/desktop-tauri/src-tauri/target/release/desktop-tauri`

### Windows packaging (optional)

For Windows installer workflows, use:

```powershell
./scripts/windows-setup-and-build.ps1 -Installer
```

### Manual commands (if preferred)

```bash
cargo fetch
cargo test -p core-detect -p core-tokenize -p core-vault
cd apps/desktop-tauri/src-tauri
cargo run
```


### Ubuntu/Linux development branch

This repository now has a dedicated branch for Ubuntu work: `ubuntu-version`.

For Linux setup on that branch:

```bash
./scripts/ubuntu-setup-and-build.sh
```

Optional modes:
- `SKIP_TESTS=1 ./scripts/ubuntu-setup-and-build.sh`
- `RELEASE=1 ./scripts/ubuntu-setup-and-build.sh`

Notes:
- Linux support is active on this branch and suitable for local testing; desktop-environment behavior may still vary.
- Core crates compile cross-platform, but clipboard/tray behavior may vary by desktop environment.


## Download and test on another machine

1. Push this repository to Git.
2. On the test machine, clone it.
3. Open a terminal in repo root and run:

```bash
./scripts/ubuntu-setup-and-build.sh
```

4. Optionally build a Linux release binary with:

```bash
RELEASE=1 ./scripts/ubuntu-setup-and-build.sh
```

This keeps setup reproducible and ensures dependencies are fetched during the build flow.

## Current limitations

- Linux listener currently uses polling-based clipboard checks (700ms) with duplicate suppression and self-write cooldown safeguards.
- Windows listener uses `WM_CLIPBOARDUPDATE` eventing and remains supported.
- macOS support is marked TODO.
- AI Armor cannot stop manual typing into AI tools; it protects **copy/paste flows**.
