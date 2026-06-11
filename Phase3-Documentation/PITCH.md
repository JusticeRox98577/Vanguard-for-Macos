---
marp: true
theme: default
paginate: true
header: "Vanguard-for-macOS · hardware-anchored anti-cheat without a kernel driver"
footer: "Research submission · not affiliated with or endorsed by Riot Games or Apple"
---

<!-- _paginate: false -->
<!-- _header: "" -->
<!-- _footer: "" -->

# Vanguard-for-macOS

### Hardware-anchored anti-cheat **without** a kernel driver

A proof-of-concept arguing that Apple Silicon's trust chain — Endpoint
Security + Secure Enclave + App Attest — can deliver Vanguard-class
competitive-integrity guarantees on macOS, with no ring-0 code.

Research submission for a game-developer security team
2026

---

## The problem this solves for you

- Kernel anti-cheat (`vgc.sys`, EAC, BattlEye) is today's bar on Windows —
  and the **single reason VALORANT can't ship on macOS**. Apple effectively
  prohibits third-party kernel code.
- The result: an entire platform of players excluded by an *implementation
  detail* of the security model, not by the security requirement itself.
- "Just port it" stalls on one question: **how do you protect the client on a
  platform with no kernel driver?**

> This deck is one answer — and an honest account of where that answer stops.

---

## Thesis

**Ring 0 is mostly unnecessary on Apple Silicon — because Apple already
removed the attack surface a kernel driver exists to police.**

- No third-party kexts without notarization + explicit user approval + reboot
- SIP + signed system volume → the OS can't be silently modified
- Hardened runtime + **library validation** → foreign dylibs won't load
- **DART IOMMU** + no user PCIe on most Macs → DMA cards mostly don't apply
- Secure Boot rooted in the **Secure Enclave** → boot state is attestable

What remains is delivered to user space through two Apple-supported channels:
**Endpoint Security** (vetted kernel telemetry) and **App Attest** (hardware
trust anchor).

---

## Threat model (what we neutralize, and how)

| Vector | macOS mitigation | Status |
|---|---|---|
| Memory editing (`task_for_pid`) | ES `GET_TASK` events; deny via `AUTH_GET_TASK` | **Built** (observe) |
| dylib injection (`DYLD_INSERT_LIBRARIES`) | ES exec-env scan + library validation | **Built** |
| DMA hardware cards | DART IOMMU; no PCIe on most SKUs | **Structural** |
| Input injection (aimbot) | server-side input-vector ML | Engine/server |
| Kernel rootkit / BYOVD | SIP, no kexts, SEP-rooted Secure Boot | Platform |
| VM / HWID spoofing | App Attest can't run on a VM | **Built** |

Full per-platform analysis with residual gaps: `THREAT-MODEL.md`.

---

## Architecture — one client, two Apple channels

```
        ┌────────────────────────┐
        │   GAME CLIENT / ENGINE  │
        └───────────┬────────────┘
                    │ in-process SDK
        ┌───────────▼────────────┐
   OS ◄─┤  CLIENT SECURITY AGENT  ├─► HARDWARE
  ES    │  Phase 1: ES monitor    │   SEP / App Attest
 events │  Phase 2: SEP + attest  │   (Phase 2)
        └───────────┬────────────┘
                    │ signed telemetry + attestation
        ┌───────────▼────────────┐
        │  BACKEND TELEMETRY SVR  │  verify attestation vs Apple,
        │  trust: admit/flag/kick │  verify signed events, decide
        └────────────────────────┘
```

The **server** is the root of trust. It believes the client only after the
App Attest assertion verifies against Apple.

---

## The trust inversion

The client doesn't need to be **unbreakable**.
It needs to be **unforgeable**.

- Trust decisions live **server-side**, extended only to clients whose
  hardware attestation verifies.
- Tamper with the agent → its code signature changes → attestation breaks →
  the server stops believing it.
- This is what lets a *user-mode* agent stand in for a kernel driver: you're
  not betting the client can't be hacked; you're proving the host is genuine
  and the build is intact.

---

## What's actually built (not slideware)

**Phase 1 — Endpoint Security monitor** (C, ~415 lines, heavily commented)
- Subscribes to exec/fork/exit + the four task-port events
- Flags `DYLD_INSERT_LIBRARIES` injection and task-port access to a protected
  process; logs per-process code-signing identity
- Ships with a one-command detection test harness

**Phase 2 — SEP + App Attest chain** (Swift client + Node verifier)
- SEP key custody demo (non-exportable key, signs in-enclave)
- App Attest attestation + replay-proof per-request assertions
- Server implements Apple's cert-chain checks from scratch — *auditable, no
  WebAuthn black box*. Verifier self-test: 5/5 (replay/tamper/forgery rejected)

---

## macOS structural wins vs. Windows

| | Windows kernel AC | macOS (this approach) |
|---|---|---|
| Memory access to game | `Ob` handle-strip (ring 0) | ES `GET_TASK` / `AUTH_GET_TASK` (user space) |
| Injection defense | image-load callbacks | dyld scan + **library validation** |
| DMA cards | verify VT-d/AMD-Vi | **DART + no PCIe on most Macs** |
| Foreign code in kernel | BYOVD is a live threat | no kexts w/o Apple + reboot |
| Stability blast radius | BSOD / boot loops | one user process crashes |

The worst hardware vector on Windows — DMA cards — is **largely a non-threat
on Mac out of the box.**

---

## Honest gap analysis

What this approach does **not** solve — stated up front, because a defense you
oversell is a defense your red team stops trusting:

- **Server-side heuristics** (aimbot input ML, ESP occlusion) live in the
  *engine + backend*. We secure the client anchor; we don't replace authoritative server design.
- **Continuous runtime attestation** — App Attest is a trust *anchor*, not a
  per-frame heartbeat (and it's rate-limited).
- **Linux / SteamOS** — no ES or App Attest equivalent on a system the user
  roots. We claim **no** Linux parity. (Same boundary that keeps Vanguard off Linux.)
- **KMBox-class hardware input emulation** — a server-side problem; no client
  agent, ours or a kernel driver, fully closes it.
- **A fully compromised Apple platform** (SEP key extraction) — out of scope;
  no commercial AC survives that.

---

## Performance & privacy

**Stability** — passive, NOTIFY-only user-space sensor. Cannot panic the
kernel, cannot deadlock the system. A bug crashes *one process*, not the box.
Direct contrast with kernel-driver BSOD/boot-loop risk.

**Performance** — 7 low-frequency, process-level event types. O(1) per event,
no polling, no per-frame game hooks. Steady-state cost expected negligible
(claim to be benchmarked, not a benchmark).

**Privacy** — process metadata only (paths, pids, signing IDs, timestamps).
No file contents, keystrokes, or network payloads.
- Scope is **enforced by the OS**, not by vendor promise (subscribed event
  classes + Apple-gated entitlement).
- Runs **only with the game**; no boot-time driver.
- Local-first; only attestation results + flagged summaries leave the host.

---

## vs. a Windows kernel driver

| | `vgc.sys` (kernel) | Vanguard-for-macOS |
|---|---|---|
| Privilege | Ring 0, loads at boot | User space, runs with the game |
| Client visibility | Broad | Scoped to vetted ES events |
| Active prevention | Full | Deny task ports (`AUTH_`); designed |
| Trust anchor | TPM (bolt-on) | SEP / App Attest (native) |
| Stability risk | BSOD-class | One-process crash |
| Cross-platform | Windows only | **Windows + macOS** |
| Distribution | You ship the driver | Apple-vetted entitlement |

Not "equivalent to ring 0." **"Ring 0 is unnecessary here, and we can prove
the client is genuine."**

---

## The ask

1. **Evaluate the PoC.** Repo is buildable today; run the Phase 1 detection
   harness and the Phase 2 attestation chain on a test Mac.
2. **Pressure-test the gaps.** We believe conceding Linux, KMBox, and
   continuous attestation makes the macOS claim *stronger*. Tell us where
   we're wrong.
3. **Scope a pilot.** Next steps are well-defined: notarized System Extension
   packaging, and engine integration for the server-side pillar.

**What we want back:** an honest read from your anti-cheat team on whether the
attestation model is worth taking seriously for a macOS VALORANT.

---

<!-- _header: "" -->
<!-- _footer: "" -->

## Appendix — read deeper

- **Architecture** (pillars, platform map, full data flow): `ARCHITECTURE.md`
- **Threat model** (vector-by-vector, residual gaps): `THREAT-MODEL.md`
- **Pitch structure & perf/privacy detail**: `README.md`
- **Code**: `Phase1-ProcessMonitor/` · `Phase2-Attestation/`

Repository: `github.com/JusticeRox98577/Vanguard-for-Macos`

*Independent research. Not affiliated with, authorized by, or endorsed by Riot
Games or Apple. "Vanguard" and "VALORANT" are trademarks of Riot Games, used
here nominatively to describe interoperability and comparison.*
