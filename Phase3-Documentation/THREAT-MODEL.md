# Threat Model

Scope: client-side cheating in a competitive online game, plus the trust
bootstrap that lets a server believe anything the client reports. This
document enumerates the cheat vectors, what neutralizes each one, on which
platform, and — explicitly — the residual gap that remains. The honest gaps
are the point: a security team trusts a proposal more when it states its own
limits.

Legend for "Status in this PoC":
- **Demonstrated** — implemented in Phase 1 / Phase 2 of this repo.
- **Designed** — architecture defined here; not built in the PoC.
- **External** — requires game-engine or server work outside this project.

---

## 1. Adversary capabilities assumed

We assume a motivated cheat developer who can:

- Run arbitrary **user-mode** code on their own machine.
- Buy commercial cheats (subscription DMA firmware, HWID spoofers, kernel
  cheats sold for Windows).
- On Windows: load a **signed-but-malicious or vulnerable kernel driver**
  (BYOVD — bring your own vulnerable driver) to reach ring 0.
- Attach **DMA hardware** over PCIe/Thunderbolt to read memory without the
  host CPU's involvement.
- Inject code into the game process (DLL/dylib injection).
- Feed **synthetic input** to the OS input stack (aimbot/triggerbot).
- Run the game inside a **VM** to hide tooling on the host.

We do **not** assume the adversary can break Apple's Secure Enclave, forge an
Apple-signed boot chain, or extract a non-exportable SEP key. If that bar is
cleared, the platform's entire security model is void — and so is every
competitor's.

---

## 2. Vector-by-vector analysis

### 2.1 Memory editing (read/write game memory from another process)
The foundation of ESP, aimbots that read entity tables, and god-mode hacks.

| | Windows | macOS |
|---|---|---|
| Mechanism | `OpenProcess` + `ReadProcessMemory` / `WriteProcessMemory` | `task_for_pid` → task port → `mach_vm_read/write` |
| Mitigation | Kernel AC hooks `Ob` callbacks to strip/deny handles to the protected process | **Endpoint Security** `GET_TASK` events; upgrade to `AUTH_GET_TASK` to **deny** the task port to non-allowlisted requesters |
| Status in this PoC | — | **Demonstrated** (observe) / **Designed** (deny) — see `Phase1-ProcessMonitor` |
| Residual gap | A ring-0 driver can read physical memory directly, bypassing handle checks | On macOS, obtaining a task port to a hardened-runtime, non-`get-task-allow` process already requires either the target's consent or root; SIP + the hardened runtime shrink this surface substantially, but a root-level compromise still defeats it |

macOS note: the hardened runtime + lack of `com.apple.security.get-task-allow`
means even root cannot trivially get a task port to a properly signed app
without tripping the very ES events we monitor. This is materially stronger
than the Windows default and is the cleanest single win for the macOS pitch.

### 2.2 Code injection (DLL / dylib)
Load attacker code into the game's address space to hook rendering, input, or
networking.

| | Windows | macOS |
|---|---|---|
| Mechanism | `CreateRemoteThread`, `SetWindowsHookEx`, AppInit_DLLs, manual mapping | `DYLD_INSERT_LIBRARIES`, dlopen via a task port |
| Mitigation | Kernel AC watches image-load callbacks | ES `EXEC` env scan flags `DYLD_INSERT_LIBRARIES`; hardened runtime + library validation reject unsigned/foreign dylibs at load |
| Status in this PoC | — | **Demonstrated** (`DYLD_INSERT_LIBRARIES` detection in Phase 1) |
| Residual gap | Manual mapping can evade image-load callbacks | Apple's **library validation** (part of the hardened runtime) already blocks loading dylibs not signed by the same Team ID or Apple — injection via dyld is largely closed *by the platform* before our monitor even fires; our value is telemetry + catching mis-signed launches |

### 2.3 DMA hardware cheats
A PCIe/Thunderbolt card (or a second PC) reads game memory directly. Defeats
all client-side software because the host CPU never sees the access.

| | Windows | macOS |
|---|---|---|
| Mechanism | FPGA DMA card in a PCIe slot maps and scans physical RAM | Same, via PCIe (Mac Pro) or Thunderbolt |
| Mitigation | Require **Kernel DMA Protection** (VT-d/AMD-Vi IOMMU) be enabled; *verify*, refuse to launch if off | Apple's **DART** IOMMU gates all device DMA by default; most Macs have **no user-accessible PCIe slots** at all |
| Status in this PoC | **Designed** (attestation gate) | **Designed** (attestation gate) |
| Residual gap | The AC can only *verify* IOMMU state, not enforce policy — and a determined attacker can target a machine where firmware DMA protection is weak | On Apple Silicon laptops/Mini/Studio/iMac there is no PCIe slot and Thunderbolt DMA is DART-gated, so commodity DMA cards are **largely a non-threat out of the box**. The Apple Silicon **Mac Pro** has slots (still behind DART) and is the one edge case |

This is the clearest structural advantage of the macOS target and should be
stated plainly: **the platform Riot can't ship VALORANT on today is also the
platform where the worst hardware-cheat vector mostly doesn't exist.**

### 2.4 Input injection (aimbot / triggerbot / scripts)
Synthetic mouse/keyboard events that no client-side scanner can cleanly
distinguish from a real device.

| | Windows | macOS |
|---|---|---|
| Mechanism | `SendInput`, virtual HID, hardware "KMBox" relays | `CGEvent` injection, virtual HID |
| Mitigation | **Server-side input-vector ML** on movement/accel curves + polling cadence | Same — this is platform-agnostic |
| Status in this PoC | **External** (server/engine) | **External** (server/engine) |
| Residual gap | Hardware input emulators (KMBox + a second PC running the aimbot) produce physically-plausible motion and are the hardest case; ML raises cost but does not fully close it. This vector is **fundamentally server-side** and not something a client agent — ours or a kernel driver — can solve alone |

### 2.5 Kernel rootkits / BYOVD
Attacker reaches ring 0 to hide processes, spoof scans, or read memory under
the AC.

| | Windows | macOS |
|---|---|---|
| Mechanism | Load a vulnerable signed driver, escalate to kernel | Load a malicious kext |
| Mitigation | TPM-measured Secure Boot + driver blocklist; kernel AC at ring 0 | **SIP**, **signed system volume**, and **no third-party kexts without explicit Apple notarization + user approval + a reboot**; Secure Boot rooted in the SEP |
| Status in this PoC | **External** (platform) | **Leveraged** (platform) |
| Residual gap | BYOVD remains a live, actively-exploited path on Windows; this is a core reason Vanguard runs in the kernel | On Apple Silicon, loading unapproved kernel code requires lowering boot security to "Reduced/Permissive," which is itself measurable and attestable. The bar is far higher than Windows — but a 0-day in the SEP or boot chain would still collapse the model (assumed out of scope, §1) |

### 2.6 VM / hypervisor bypass
Run the game in a guest while cheats run on the host, invisible to the guest.

| | Windows | macOS |
|---|---|---|
| Mitigation | Hardware attestation (TPM quote) proves boot measurements; AC can refuse to run virtualized | **App Attest** assertion is rooted in the physical SEP of a genuine Apple device; a VM cannot produce a valid Apple-signed hardware attestation |
| Status in this PoC | **Designed** | **Demonstrated** (Phase 2 attestation chain) |
| Residual gap | Attestation proves "genuine hardware in a known state," not "no cheat present" — it raises the floor (no trivial VM farming / no spoofed HWID) but is one layer, not the whole defense |

---

## 3. What this project explicitly does NOT solve

Stated up front so the gap analysis is credible:

1. **Server-side game logic.** ESP defeated by line-of-sight occlusion and
   aimbots defeated by input ML both live in the **game engine + backend**,
   not in this client agent. This project secures the *client trust anchor and
   local telemetry*; it does not replace authoritative server design.
2. **Continuous runtime attestation.** App Attest proves app integrity at
   assertion time and is rate-limited; it is not a per-frame heartbeat of
   "the process is still clean." It anchors trust; it does not continuously
   re-prove it.
3. **Linux / SteamOS.** There is no Endpoint Security or App Attest equivalent
   on an open system where the user holds root. We do **not** claim Linux
   parity. This is the same boundary that keeps Vanguard off Linux, stated
   honestly rather than papered over.
4. **A fully compromised Apple platform.** SEP key extraction or a forged boot
   chain is out of scope (§1); no commercial anti-cheat survives that.
5. **Hardware input emulators (KMBox-class).** Best mitigated server-side;
   neither this project nor a kernel driver fully closes it client-side.

---

## 4. Net assessment vs. a Windows kernel driver

A kernel driver (vgc.sys) buys **breadth of client-side visibility and active
ring-0 enforcement** at the cost of system stability risk, privacy surface,
and zero cross-platform reach. The macOS model trades that breadth for a
platform that has **already removed most of the attack surface** the driver
exists to police (no unsigned kexts, library validation, DART IOMMU, no PCIe
on most SKUs), plus a **hardware-rooted attestation** the driver approach bolts
on via TPM. The result is not "equivalent to ring 0" — it is "ring 0 is mostly
unnecessary here, and we can prove the client is genuine." See
[ARCHITECTURE.md](ARCHITECTURE.md) for the full data flow.
