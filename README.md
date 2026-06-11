# Vanguard-for-macOS

A proof-of-concept security monitor demonstrating that Apple Silicon's
hardware trust chain (Secure Enclave, App Attest, Endpoint Security
Framework) could serve as a credible alternative to Windows kernel-level
anti-cheat on macOS.

Built as a research submission for game developers. Not a cheat, not a
bypass — the opposite.

## Goal

Show that macOS doesn't need ring 0 access to provide meaningful security
guarantees, and that Apple's attestation model is worth taking seriously.

Windows anti-cheats (Riot Vanguard, EAC, BattlEye) lean on a kernel-mode
driver to watch process memory, block injection, and enumerate what's
running. macOS deliberately closes that door. This project argues the door
was replaced with a better one: the kernel itself watches, and hands a vetted
userland client exactly the events that matter — backed by hardware
attestation that proves the client and the host are genuine.

## Phases

| Phase | Focus | Status |
|---|---|---|
| **1 — Process Monitor** | Endpoint Security client: process lifecycle, task-port (memory) access, dylib-injection detection, timestamped logging. | ✅ Implemented — [`Phase1-ProcessMonitor/`](Phase1-ProcessMonitor/) |
| **2 — Hardware Attestation** | Secure Enclave key generation + App Attest assertion, verified by a small server. Demonstrates the full client→Apple→server trust chain. | ✅ Implemented — [`Phase2-Attestation/`](Phase2-Attestation/) (server tested; client runs on-device only) |
| **3 — Documentation** | Threat model, architecture, and pitch packaging with honest gap analysis, for a game studio's security team. | 📝 Drafted — [`Phase3-Documentation/`](Phase3-Documentation/) (final pass after Phase 2 is built) |

## Repository layout

```
Vanguard-for-Macos/
├── README.md                     # this file
├── LICENSE                       # MIT
├── Phase1-ProcessMonitor/        # Phase 1 — Endpoint Security monitor (C)
│   ├── src/vanguard_monitor.c    #   the monitor, heavily commented
│   ├── entitlements/             #   the one ES entitlement, explained
│   ├── Makefile                  #   build + ad-hoc codesign + run
│   └── README.md                 #   build/run, entitlements, anti-cheat mapping
├── Phase2-Attestation/           # Phase 2 — SEP + App Attest trust chain
│   ├── client/                   #   Swift: SEP key custody + App Attest
│   ├── server/                   #   Node.js verifier (Apple cert chain checks)
│   └── README.md                 #   run both halves, honesty notes
└── Phase3-Documentation/         # Phase 3 — research submission (drafted)
    ├── README.md                 #   executive summary, pitch, perf & privacy
    ├── PITCH.md / PITCH.html      #   the slide deck (Marp source + browser-ready)
    ├── THREAT-MODEL.md           #   vectors → mitigations → honest gaps
    └── ARCHITECTURE.md           #   pillars, platform map, data-flow diagram
```

## Quick start (Phase 1)

> Requires macOS with the Xcode command line tools. See
> [`Phase1-ProcessMonitor/README.md`](Phase1-ProcessMonitor/README.md) for the
> entitlement and SIP/AMFI details — an ES client needs root, Full Disk Access,
> and the `com.apple.developer.endpoint-security.client` entitlement.

```sh
cd Phase1-ProcessMonitor
make
sudo ./build/vanguard_monitor MyGame   # "MyGame" = the process to protect
```

## What this is not

- Not a cheat, not an injector, not a SIP/AMFI bypass tool. It *detects* those
  techniques.
- Not a shipping product. It is a focused demonstration for a security-research
  audience.

## License

MIT — see [LICENSE](LICENSE).
