# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository nature

This repo is a **design specification only** — there is no source code, no build system, no tests. Three documents:

- `README.md` — public-facing overview and rationale for TSH v4
- `docs/implementation_plan.md` — byte-level engineering blueprint (the authoritative spec when the two disagree)
- `docs/future.md` — research directions for v4.1/v5 (heuristic countermeasures, infrastructure resilience, competitive analysis)

`AGENTS.md` at the repo root is a symlink to this file — edits here apply to both.

Any task here is documentation work: clarifying the spec, fixing inconsistencies, evolving the design, or drafting an implementation plan. Do not invent commands, scripts, or code files unless the user explicitly asks for an implementation. Forward-looking research proposals belong in `docs/future.md`, not in the v4 spec documents.

## What TSH is (one paragraph)

TSH (Transparent Single-Handshake) is a TLS 1.3 censorship-evasion broker. The client appends an encrypted routing payload (ERD) to a PSK session ticket's opaque data, spoofs the SNI to a cover domain, and shrinks the padding extension to absorb the length delta. The broker decrypts the ERD, snips the appended bytes, restores SNI and padding, and forwards a **byte-identical** ClientHello to the true destination. Because `legacy_session_id` is never touched, the destination's ServerHello echo matches naturally — the broker is fully stateless after forwarding.

## Core invariant (do not violate)

> `Restore(Transform(CH₀)) ≡ CH₀`

Any spec change must preserve byte-identity restoration. Binder verification at the destination depends on it. Edits that introduce client/server ambiguity (e.g., the broker having to guess padding length) are regressions, even if they look like simplifications.

## v4 design decisions that must not be reverted

The v3 → v4 migration fixed three named flaws. If a proposed change resurrects any of them, push back:

| Decision | What it fixes |
|---|---|
| **Never modify `legacy_session_id`** | Eliminates the v3 stateful ServerHello echo patching |
| **Fresh 12-byte CSPRNG nonce per Transform** | Eliminates v3 HRR nonce reuse (RFC 8446 §4.1.2 forces same `client_random` across HRR) |
| **Explicit `P₀` (original padding length) inside the encrypted payload** | Eliminates v3 padding restoration ambiguity |
| **Full 16-byte Poly1305 tag** | Replaces v3's truncated 8-byte tag (Ferguson subkey attack); enabled by unbounded ticket space |
| **Single cover domain** | Replaces v3's length-matched domain pool; dynamic padding absorbs the delta |

## ERD layout (resolved)

The ERD uses a 2-byte **length trailer at the end** (`nonce ‖ ciphertext ‖ tag ‖ length`). The broker reads the last 2 bytes of the PSK identity opaque data to learn ERD size, then reads backward. This is now consistent across README.md §Part 1, `docs/implementation_plan.md` §2.2, and §5.1. The old header-at-offset-0 layout in §2.2 has been replaced.

## Terminology and notation conventions

- `CH₀` = Chrome's original ClientHello; `CH₁` = client-transformed (on wire); `CH₂` = broker-restored (must equal `CH₀`)
- `ERD` = Encrypted Routing Data (the appended block: nonce ‖ ciphertext ‖ tag ‖ length-trailer)
- `P₀` = original padding extension data length recorded by client, restored by broker
- `Δ_SNI = len(cover_domain) - len(target_domain)`; `Δ_total = erd_len + Δ_SNI`
- Extension type constants are written as TLS-style 4-hex (`0x0000` SNI, `0x0015` padding, `0x0029` PSK)
- Byte/bit tables use the same column layout (`Offset | Length | Field | TSH v4 Action`) — preserve it when adding rows

## Open questions left for the user (do not silently resolve)

The README §"Open Questions" lists items the author has explicitly deferred: implementation language (Go vs Rust), build order, and ECH-resurrection scheduling (v4.1 vs v5). The ERD length signaling question has been **resolved** (trailer layout). Don't pick winners for the remaining questions without asking.

## Author / attribution

Both docs carry an author byline (Bingchen Gong, @Wenri). Preserve it when restructuring.
