# Technical Architecture

How the client agent, the hardware security module, the OS kernel, and the
backend telemetry server fit together — and, for each piece, what is
**demonstrated** in this PoC versus **designed** on paper. The corrections from
the early framework draft (no in-enclave heuristics, no third-party PPL/HVCI,
no Linux parity, attestation as a *gate* not enforcement) are baked in here.

---

## 1. The three pillars (corrected)

### Pillar 1 — Hardware-enforced trust anchor
**Claim that survives scrutiny:** use the Secure Enclave / TPM for what it
actually provides — non-exportable key custody and a hardware-rooted
attestation that the client and host are genuine and in a known boot state.

- **macOS:** Secure Enclave (SEP) generates a non-exportable key; **App
  Attest** produces an Apple-signed assertion that the app is genuine and
  unmodified, rooted in that physical SEP. *(Phase 2 — built in this repo.)*
- **Windows:** TPM 2.0 + Measured/Secure Boot produce a quote over the boot
  measurements. *(Designed.)*
- **Explicitly NOT claimed:** running detection heuristics *inside* an enclave.
  The SEP runs only Apple-signed sepOS; Intel SGX is gone from consumer CPUs
  and deprecated; AMD SEV is VM memory encryption for cloud tenants. No
  consumer platform lets a third party execute logic in a TEE. The enclave's
  role here is **trust custody, not compute.**

### Pillar 2 — Asymmetric server-side heuristics
**Claim that survives scrutiny:** move detection the client can't be allowed to
see server-side. This is the strongest, most portable pillar and is
platform-agnostic.

- **Input-vector analysis:** ML over mouse movement/acceleration curves and
  polling cadence to separate human motor constraints from aimbot/smoothing
  output.
- **Authoritative game state:** the server withholds occluded entity data
  (line-of-sight culling) so ESP has nothing to read; all hit/position
  validation is server-authoritative.
- **Status:** **External** — belongs to the game engine + backend. This project
  feeds it trustworthy client signals; it does not implement the game logic.

### Pillar 3 — Anti-DMA
**Claim that survives scrutiny:** *verify* hardware DMA protection and lean on
the platform's IOMMU; on macOS, note the structural advantage.

- **IOMMU:** the AC can **require and attest** that Kernel DMA Protection
  (VT-d/AMD-Vi) / Apple's **DART** is enabled and refuse to launch otherwise —
  it cannot set IOMMU policy itself from user space.
- **macOS structural win:** most Apple Silicon Macs have **no user PCIe slots**
  and DART-gate Thunderbolt DMA, so commodity DMA cards mostly don't apply.
- **Moving-target memory layout:** runtime relocation/encryption of key game
  variables raises the cost for a passive scanner. Honest framing: a speed
  bump that raises attacker cost, not an elimination.
- **Status:** **Designed** (the launch-time attestation gate).

---

## 2. Pillar → platform mapping

| Capability | Windows | macOS | In this PoC |
|---|---|---|---|
| Boot-state trust | TPM 2.0 + Secure Boot quote | SEP-rooted Secure Boot + App Attest | Phase 2 ✅ built |
| Key custody | TPM-bound key | Secure Enclave non-exportable key | Phase 2 ✅ built |
| Process / memory telemetry | Kernel callbacks (driver) | **Endpoint Security** (user-space, no kext) | Phase 1 ✅ built |
| Block memory access to game | `Ob` handle-strip (ring 0) | ES `AUTH_GET_TASK` deny (user-space) | Phase 1 ✅ (observe only) |
| Injection defense | Image-load callbacks | dyld env scan + Apple **library validation** | Phase 1 ✅ built |
| DMA defense | Verify VT-d/AMD-Vi | DART + no PCIe on most SKUs | Designed |
| Input / ESP defense | Server-side ML + occlusion | Server-side ML + occlusion | External (engine) |
| Anti-VM | TPM quote | App Attest (can't run on a VM) | Phase 2 ✅ built |

The headline: macOS reaches a comparable security posture **without a kernel
driver**, because the platform already supplies vetted kernel telemetry (ES)
and a hardware trust anchor (SEP), and has pre-closed several vectors a Windows
driver exists to police.

---

## 3. Data flow

```
                          ┌──────────────────────────────────────────┐
                          │            GAME CLIENT / ENGINE           │
                          │  (renders, samples input, talks to server)│
                          └───────────────┬──────────────────────────┘
                                          │ in-process SDK calls
                                          ▼
                          ┌──────────────────────────────────────────┐
                          │        CLIENT SECURITY AGENT (this PoC)    │
                          │                                            │
   OS SECURITY APIs ◄─────┤  Phase 1: Endpoint Security client        │
   (kernel events,        │   • EXEC / FORK / EXIT                     │
    delivered to          │   • GET_TASK*  (OpenProcess analogue)      │
    user space)           │   • DYLD_INSERT_LIBRARIES scan             │
                          │                                            │
   HARDWARE ANCHOR ◄──────┤  Phase 2: Secure Enclave + App Attest      │
   (SEP / TPM 2.0)        │   • non-exportable key in SEP              │
                          │   • Apple-signed attestation assertion     │
                          └───────────────┬──────────────────────────┘
                                          │ signed telemetry + attestation
                                          ▼
                          ┌──────────────────────────────────────────┐
                          │           BACKEND TELEMETRY SERVER         │
                          │   • verifies App Attest against Apple      │
                          │   • verifies signed event stream           │
                          │   • Pillar 2 heuristics: input ML,         │
                          │     occlusion-aware authoritative state    │
                          │   • trust decision: admit / flag / kick    │
                          └──────────────────────────────────────────┘
```

Trust direction: the **server** is the root of trust for decisions. It only
believes client telemetry once the **App Attest assertion** (verified against
Apple's servers) proves the agent is a genuine, unmodified build running on
genuine Apple hardware in a known state. Compromise the client and the
attestation breaks — the server stops trusting it. This is the inversion that
makes a user-mode agent viable: the client doesn't have to be *unbreakable*, it
has to be *unforgeable*.

---

## 4. Why user-mode is sufficient on macOS (the core argument)

A reviewer will push back: "if the kernel is compromised, your ES events are
compromised too." Correct — so the argument is **not** parity with ring 0. It
is that Apple has already removed most of the ring-0 attack surface a kernel AC
exists to defend:

- **No third-party kexts** without notarization + explicit user approval + a
  reboot at lowered boot security (itself attestable).
- **SIP + signed system volume** — the OS can't be silently modified.
- **Hardened runtime + library validation** — foreign dylibs won't load.
- **DART IOMMU + no PCIe on most SKUs** — DMA cards mostly don't apply.
- **SEP-rooted Secure Boot** — the boot chain is measured and attestable.

So the client agent doesn't need to live in the kernel to be effective: it
consumes a **vetted, Apple-supported kernel event stream** from user space and
anchors its identity in **hardware**. That is a defensible, falsifiable claim —
and it is exactly what Phases 1 and 2 of this repo demonstrate end to end.

---

## 5. What is real in this PoC vs. theoretical

| Component | State |
|---|---|
| Endpoint Security monitor (exec/fork/exit, task-port, dyld injection) | **Built** — `Phase1-ProcessMonitor/` |
| Secure Enclave key + App Attest assertion + verification server | **Built** — `Phase2-Attestation/` (server tested; client runs on-device only) |
| `AUTH_GET_TASK` active *denial* of task ports | Designed; hook noted in Phase 1 source |
| Server-side input ML / occlusion culling | External to this project (engine/backend) |
| Windows TPM/VBS path | Described for completeness; not implemented |
| DMA attestation gate | Designed |

Keeping this table honest is deliberate: it is the difference between a demo a
security team can audit and a slide deck they'll discount.
