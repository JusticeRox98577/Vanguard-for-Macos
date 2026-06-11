# Phase 3 — Research Submission: Hardware-Anchored Anti-Cheat on macOS

This folder is the deliverable for a game developer's security research team.
It packages the working PoC (Phase 1 and Phase 2 built) into the pitch
structure a reviewing engineer expects: problem statement, threat model,
architecture, and operational impact — with the gaps stated plainly.

| Document | Contents |
|---|---|
| **This README** | Executive summary, pitch framing, performance & privacy impact |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Cheat vectors → mitigations → honest residual gaps, per platform |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Three-pillar framework (corrected), pillar→platform map, data-flow diagram, real-vs-theoretical table |

---

## 1. Executive summary

**Problem.** Kernel-level anti-cheat (Riot Vanguard's `vgc.sys`, EAC, BattlEye)
is the current bar for competitive-integrity protection on Windows — and it is
exactly the component that prevents titles like VALORANT from shipping on
macOS, where third-party kernel code is effectively prohibited. The result: an
entire platform of potential players is excluded by an implementation detail
of the security model, not by the security requirement itself.

**Thesis.** On Apple Silicon, ring-0 access is mostly unnecessary because the
platform has already removed the attack surface a kernel driver exists to
police — no unsigned kexts, SIP and a signed system volume, library
validation, a default-on IOMMU (DART), and no user PCIe on most SKUs. What
remains is delivered to user space through two Apple-supported channels:

1. **Endpoint Security** — a vetted kernel event stream (process lifecycle,
   task-port/memory access, injection vectors) for an entitled user-space
   agent. *Demonstrated in this repo (Phase 1).*
2. **Secure Enclave + App Attest** — a hardware-rooted, Apple-co-signed proof
   that the agent is genuine, unmodified, and running on real hardware.
   *Built (Phase 2): SEP key custody, attestation, and per-request assertions,
   with a from-scratch Apple-cert-chain verifier server.*

**The inversion that makes it work.** The client agent does not need to be
*unbreakable* (no client is); it needs to be *unforgeable*. Trust decisions
live server-side and are extended only to clients whose hardware attestation
verifies. Tamper with the client and the attestation breaks — the server
simply stops believing it.

**What we are explicitly not claiming.** Not ring-0 parity, not Linux/SteamOS
support, not in-enclave detection logic, not a replacement for server-side
heuristics. See §3 of the threat model for the full non-goals list.

## 2. Threat model

Covered vector-by-vector in [THREAT-MODEL.md](THREAT-MODEL.md): memory
editing, code injection, DMA hardware, input injection, kernel rootkits/BYOVD,
and VM bypass — each with its Windows mitigation, its macOS mitigation, its
status in this PoC (**Demonstrated / Designed / External**), and its residual
gap. Highlights:

- **Memory cheats:** the macOS task-port model + hardened runtime already
  gate memory access harder than the Windows default; ES `GET_TASK` events
  make every acquisition attempt visible (built), and `AUTH_GET_TASK` can deny
  them (designed).
- **DMA cards:** largely a non-threat on most Apple Silicon Macs — no user
  PCIe slots, Thunderbolt DMA gated by DART. The worst hardware vector on
  Windows mostly doesn't exist on the Mac.
- **Honest gaps:** KMBox-class hardware input emulation (server-side problem),
  continuous runtime attestation (App Attest is a trust anchor, not a
  heartbeat), and Linux (no equivalent trust primitives; we don't claim it).

## 3. Technical architecture

Covered in [ARCHITECTURE.md](ARCHITECTURE.md): the corrected three-pillar
framework (hardware trust anchor as *key custody + attestation*, server-side
asymmetric heuristics, DMA defense as an *attestation gate*), a
capability-by-platform matrix, and the client→hardware→server data-flow
diagram. The architecture is deliberately split into:

- **What this repo proves:** the ES monitor (Phase 1, built) and the
  SEP/App Attest trust chain (Phase 2, built).
- **What the game engine/backend owns:** input-vector ML, occlusion-aware
  authoritative state — referenced, not reimplemented.

## 4. Performance & privacy impact

Operational pain points a reviewing team will ask about first:

**Stability.** The agent is a user-space process consuming NOTIFY events. It
cannot kernel-panic the machine, cannot deadlock the system (no AUTH events in
the PoC; production AUTH use is scoped to a single event type with a deadline),
and a crash of the agent is a crash of *one process* — not a BSOD-class event.
This is a direct contrast with kernel-driver anti-cheat, where a bug is a
system-stability incident (and historically has been, including boot loops
from bad updates).

**Performance.** Phase 1 subscribes to seven event types, all process-level
(exec/fork/exit/task-port) — low-frequency events by kernel standards, far
cheaper than file-I/O subscriptions. Handling is O(1) per event with no
polling, no scanning loops, and no per-frame game hooks. Expected steady-state
CPU cost is negligible; this is measurable and we state it as a claim to be
benchmarked, not a benchmark.

**Privacy.** The event scope is process metadata (paths, pids, signing
identities, timestamps) — not file contents, not keystrokes, not network
payloads. Three structural properties improve on the kernel-driver status quo:

1. **Scope is enforced by the OS, not by vendor promise.** An ES client only
   receives the event classes it subscribes to, and the entitlement itself is
   gated by Apple's vetting. Users don't have to trust the vendor's
   self-restraint; Apple's API boundary enforces it.
2. **Runs only with the game** — a user-space agent has no reason to load at
   boot (Vanguard's driver loads at boot by design).
3. **Local-first processing.** Raw events are evaluated locally; only
   attestation results and flagged-event summaries leave the machine, and the
   attestation flow is anonymous by construction (App Attest key IDs are
   per-app, per-device, and carry no Apple ID identity).

**Distribution requirement (stated honestly).** Production use requires
Apple's Endpoint Security entitlement grant — the same vetting every EDR
vendor undergoes. For a studio of Riot's size this is a process cost, not a
blocker; for the PoC, local research requires a SIP-relaxed test machine
(documented in Phase 1).

## 5. Suggested evaluation path for a reviewing team

1. Read the threat model; check our residual-gap claims against your own red
   team's experience.
2. Build and run Phase 1 on a test Mac (`Phase1-ProcessMonitor/README.md`),
   attempt task-port access and `DYLD_INSERT_LIBRARIES` injection against a
   protected target, confirm detection.
3. Review the Phase 2 design (SEP key + App Attest + server verification) and
   the data-flow diagram; evaluate the "unforgeable, not unbreakable" trust
   inversion against your server architecture.
4. Pressure-test the non-goals: we believe conceding Linux, KMBox, and
   continuous attestation makes the macOS claim *stronger*, not weaker.
