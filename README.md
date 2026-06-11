# Vanguard-for-macOS

> **Hardware-anchored competitive-integrity without a kernel driver.**
> A proof-of-concept research submission arguing that Apple Silicon's trust chain
> can deliver Vanguard-class anti-cheat guarantees on macOS — no ring-0 code required.

---

## The Problem

Kernel-level anti-cheat (`vgc.sys`, EAC, BattlEye) is today's bar on Windows.
It is also the **single reason titles like VALORANT cannot ship on macOS** — Apple
effectively prohibits third-party kernel code. The result: an entire platform of
players excluded by an implementation detail of the security model, not by the
security requirement itself.

The question this project answers: **how do you protect the client on a platform
with no kernel driver?**

---

## The Thesis

> Ring 0 is mostly unnecessary on Apple Silicon — because Apple already removed
> the attack surface a kernel driver exists to police.

| Windows threat | Why it needs ring 0 | macOS equivalent — no ring 0 needed |
|---|---|---|
| Memory read/write cheats | `OpenProcess` requires handle strip | Task-port model + `GET_TASK` ES events gate access |
| DLL injection | `AppInit_DLLs`, remote thread | `DYLD_INSERT_LIBRARIES` caught at exec by ES |
| Unsigned kernel code | BYOVD is a live threat | No kexts without Apple notarization + reboot |
| DMA hardware cards | Requires VT-d/AMD-Vi verification | DART IOMMU + no user PCIe on most Macs |
| Boot-state integrity | Relies on TPM (bolt-on) | Secure Boot rooted in SEP (native) |

What remains is delivered through two Apple-supported channels:

1. **Endpoint Security** — a vetted kernel event stream for an entitled user-space agent
2. **Secure Enclave + App Attest** — hardware-rooted proof that the agent is genuine and unmodified

---

## Architecture

```
        ┌────────────────────────┐
        │   GAME CLIENT / ENGINE  │
        └───────────┬────────────┘
                    │ in-process SDK
        ┌───────────▼────────────┐
   OS ◄─┤  CLIENT SECURITY AGENT  ├─► HARDWARE
  ES    │  Phase 1: ES monitor    │   SEP / App Attest
events  │  Phase 2: SEP + attest  │   (Phase 2)
        └───────────┬────────────┘
                    │ signed telemetry + attestation
        ┌───────────▼────────────┐
        │  BACKEND TELEMETRY SVR  │  verify attestation vs Apple,
        │  trust: admit/flag/kick │  verify signed events, decide
        └────────────────────────┘
```

**The trust inversion that makes it work:** the client doesn't need to be
*unbreakable* — it needs to be *unforgeable*. Trust decisions live server-side,
extended only to clients whose hardware attestation verifies. Tamper with the
agent, its code signature changes, attestation breaks, and the server stops
believing it.

---

## Project Status

| Phase | What it proves | Status |
|---|---|---|
| **Phase 1 — Process Monitor** | An entitled user-space ES client can observe every security-relevant event an anti-cheat cares about — process lifecycle, task-port (memory) access, dylib injection — with no kernel extension. | ✅ Built · awaiting Apple ES entitlement grant to run on stock macOS |
| **Phase 2 — Hardware Attestation** | The Secure Enclave generates a non-exportable key. App Attest asks Apple to certify it. The server verifies the cert chain from scratch. | ✅ SEP key custody demonstrated live · server tested 5/5 · full chain pending same entitlement grant |
| **Phase 3 — Documentation** | Threat model, architecture, and pitch deck for a game studio's security team. Honest gap analysis included. | ✅ Complete |

### What is running today, on real hardware

```
[attest-client] — Step 1: Secure Enclave key custody —
[attest-client]   SEP P-256 key generated. public key (X9.63): BD1Xsfn...
[attest-client]   private key export refused by SEP (expected) ✓
[attest-client]   enclave-signed message verifies: ✓
```

```
verifyAssertion — happy-path: valid assertion accepted ✓
  ✓ valid assertion accepted
  ✓ replayed counter rejected
  ✓ tampered clientData rejected
  ✓ wrong rpIdHash rejected
  ✓ foreign-key signature rejected
verifyAssertion: 5 passed, 0 failed
```

### What is pending Apple's entitlement grant

Both remaining blockers are the **same gate**: Apple's review of the
`com.apple.developer.endpoint-security.client` entitlement request (Phase 1)
and the `com.apple.developer.devicecheck.appattest-environment` entitlement
(Phase 2 macOS full chain). This vetting **is the trust property** — it is why
a security team can believe the agent is genuine. Once granted, both phases run
on stock, unmodified macOS with no SIP changes.

---

## Repository Layout

```
Vanguard-for-Macos/
├── README.md                              # this file
├── LICENSE                                # MIT
│
├── Phase1-ProcessMonitor/                 # Endpoint Security monitor (C)
│   ├── src/vanguard_monitor.c             #   ~415 lines, heavily commented
│   ├── entitlements/vanguard.entitlements #   single ES entitlement, clean plist
│   ├── entitlements/README.md             #   entitlement gates explained
│   ├── test/demo_detections.sh            #   generates task-port + injection alerts
│   ├── test/demo_inject.c                 #   harmless demo dylib
│   ├── Makefile                           #   build + sign + run + release target
│   └── README.md                          #   full build/run/entitlement guide
│
├── Phase2-Attestation/                    # SEP + App Attest trust chain
│   ├── client/
│   │   ├── src/AttestationClient.swift    #   SEP key custody + App Attest, 3 steps
│   │   ├── entitlements/appattest.entitlements
│   │   └── Makefile                       #   builds a signed .app bundle
│   ├── server/
│   │   ├── server.js                      #   /challenge /attest /assert /health
│   │   ├── verify.js                      #   Apple cert-chain verifier, no black box
│   │   ├── selftest.js                    #   hardware-free 5-check test suite
│   │   └── package.json
│   └── README.md                          #   run both halves, honesty notes
│
└── Phase3-Documentation/                  # Research submission
    ├── README.md                          #   executive summary, perf & privacy
    ├── PITCH.md / PITCH.html              #   13-slide deck (Marp + browser-ready)
    ├── THREAT-MODEL.md                    #   vector-by-vector with residual gaps
    └── ARCHITECTURE.md                    #   three-pillar framework + data flow
```

---

## Quick Start

### Phase 1 — Process Monitor

> Requires macOS · Xcode command-line tools · SIP disabled OR Apple-granted ES entitlement

```sh
cd Phase1-ProcessMonitor
make
sudo ./build/vanguard_monitor MyGame        # replace MyGame with the process to protect
```

Run the detection harness in a second terminal to see it fire:

```sh
./test/demo_detections.sh
```

Expected alerts:

```
[2026] ALERT GET_TASK    requester=loader  target=MyGame  <== PROTECTED PROCESS
[2026] ALERT EXEC+INJECT path=MyGame  via=DYLD_INSERT_LIBRARIES=/path/to/hook.dylib
```

See [`Phase1-ProcessMonitor/README.md`](Phase1-ProcessMonitor/README.md) for the
full entitlement and SIP/AMFI walkthrough, and the `release` target for building
with a proper Developer ID provisioning profile.

---

### Phase 2 — Hardware Attestation

**Server** (works on any machine with Node 18+):

```sh
cd Phase2-Attestation/server
npm install

# Download Apple's root CA (do not hand-copy — transcription errors break verification):
curl -o Apple_App_Attest_Root_CA.pem \
  https://www.apple.com/certificateauthority/Apple_App_Attest_Root_CA.pem

# Hardware-free self-test (5/5 — runs anywhere):
npm test

# Start the verifier:
VANGUARD_TEAM_ID=YOUR_TEAM_ID \
VANGUARD_BUNDLE_ID=com.yourteam.vanguard-attest \
  npm start
```

**Client** (Apple Silicon Mac · paid Developer account · Apple-granted entitlement):

```sh
cd Phase2-Attestation/client
make \
  APP_BUNDLE_ID=com.yourteam.vanguard-attest \
  SIGN_IDENTITY="Apple Development: you@example.com (TEAMID)" \
  PROFILE=/path/to/profile.provisionprofile

./build/VanguardAttest.app/Contents/MacOS/VanguardAttest
```

Expected output when both entitlements are granted:

```
[attest-client] — Step 1: Secure Enclave key custody —
[attest-client]   SEP P-256 key generated.
[attest-client]   private key export refused by SEP (expected) ✓
[attest-client]   enclave-signed message verifies: ✓
[attest-client] — Step 2: App Attest key + Apple-certified attestation —
[attest-client]   server verdict: ATTESTED ✓
[attest-client] — Step 3: per-request assertion (replay-proof) —
[attest-client]   server verdict: ASSERTION VALID ✓ counter=1
[attest-client] full trust chain demonstrated: SEP → Apple → server ✓
```

---

### Phase 3 — Pitch Deck

Open in any browser — no tools needed:

```sh
open Phase3-Documentation/PITCH.html    # Cmd-P → Save as PDF for a ready deck
```

Or render with Marp for highest quality:

```sh
npx @marp-team/marp-cli Phase3-Documentation/PITCH.md --pdf
```

---

## Honest Gap Analysis

This project does not claim parity with everything a kernel driver does.
Stated up front, because a defense you oversell is a defense your red team
stops trusting:

| Gap | Why it's out of scope |
|---|---|
| **Server-side heuristics** (aimbot input ML, ESP occlusion) | Lives in the game engine + backend. We secure the client anchor; authoritative server design is the studio's problem. |
| **Continuous runtime attestation** | App Attest is a trust anchor, not a per-frame heartbeat. Rate-limited by Apple's servers by design. |
| **Linux / SteamOS** | No ES or App Attest equivalent on a system the user roots. Same boundary that keeps Vanguard off Linux. |
| **KMBox-class hardware input emulation** | A server-side problem. No client agent — ours or a kernel driver — fully closes it. |
| **A fully compromised Apple platform** (SEP key extraction) | Out of scope for every commercial AC. |

---

## vs. a Windows Kernel Driver

| | `vgc.sys` (kernel) | Vanguard-for-macOS |
|---|---|---|
| Privilege | Ring 0, loads at boot | User space, runs with the game |
| Memory access defense | `Ob` handle-strip (ring 0) | ES `GET_TASK` / `AUTH_GET_TASK` |
| Injection defense | Image-load callbacks | dyld scan + library validation |
| DMA cards | Verify VT-d/AMD-Vi | DART + no PCIe on most Macs |
| Foreign kernel code | BYOVD is a live threat | No kexts without Apple + reboot |
| Trust anchor | TPM (bolt-on) | SEP / App Attest (native) |
| Stability blast radius | BSOD / boot loops | One user-process crash |
| Distribution | You ship the driver | Apple-vetted entitlement |

Not "equivalent to ring 0." **Ring 0 is unnecessary here, and we can prove the
client is genuine.**

---

## Next Steps

For a studio evaluating this for production:

1. **Run Phase 1** on a test Mac — attempt `task_for_pid` and
   `DYLD_INSERT_LIBRARIES` against a protected target, confirm detection.
2. **Review the Phase 2 server** (`verify.js`) — every Apple-spec check is
   commented and auditable. Run `npm test` to confirm the security properties.
3. **Apply for the entitlements** — the ES and App Attest macOS entitlements
   use the same Apple review process every EDR vendor goes through. For a
   studio of Riot's size this is a process cost, not a blocker.
4. **Scope the engine integration** — the next concrete steps are:
   - Wrap the ES monitor as a notarized System Extension (packaging only, no
     logic change)
   - Wire Phase 1 telemetry into the Phase 2 `clientData` envelope so each
     hardware-signed assertion carries the ES event log
   - Integrate the server verifier into the game backend's trust decisions

---

## License

MIT — see [LICENSE](LICENSE).

---

*Independent research. Not affiliated with, authorized by, or endorsed by Riot
Games or Apple. "Vanguard" and "VALORANT" are trademarks of Riot Games, used
here nominatively for comparison and interoperability description.*
