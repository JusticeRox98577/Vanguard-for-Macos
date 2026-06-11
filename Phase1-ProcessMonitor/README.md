# Phase 1 — System-Wide Process Monitor (Endpoint Security)

A userland process monitor built on Apple's **Endpoint Security (ES)**
framework. It proves the core Phase-1 claim: on Apple Silicon you can observe
the security-relevant events an anti-cheat cares about — process launches,
task-port (memory) access, and dylib injection — **without a kernel
extension** and **without ring-0 access**. One Apple-issued entitlement, run
as root, is enough.

This is the macOS counterpart to what Windows products like Riot Vanguard do
with a kernel-mode driver — except here the kernel does the watching and hands
us vetted events through a stable, Apple-supported API.

---

## What it monitors

| Event(s) | ES event type | Why an anti-cheat cares |
|---|---|---|
| Process launch | `NOTIFY_EXEC` | Baseline telemetry + the binary's **code-signing identity** at launch (Apple-platform vs. ad-hoc/unsigned). |
| Process spawn | `NOTIFY_FORK` | Reconstruct the process tree; spot staged loaders. |
| Process exit | `NOTIFY_EXIT` | Close out lifecycle / age pids. |
| Task-port access | `NOTIFY_GET_TASK`, `NOTIFY_GET_TASK_READ`, `NOTIFY_GET_TASK_INSPECT`, `NOTIFY_GET_TASK_NAME` | macOS equivalent of `OpenProcess`. Acquiring a target's **task port** is how memory cheats read/write game memory. |
| dylib injection | scanned in `NOTIFY_EXEC` env | Detects `DYLD_INSERT_LIBRARIES` (and `DYLD_*` path overrides) — the macOS "DLL injection". |

### Mapping to Windows anti-cheat concepts

| Windows / Vanguard concept | macOS equivalent this tool watches |
|---|---|
| `OpenProcess(PROCESS_VM_READ/WRITE)` | `task_for_pid` → `GET_TASK` / `GET_TASK_READ` |
| `WriteProcessMemory` cheat | requires a task port first → caught at `GET_TASK` |
| DLL injection (`CreateRemoteThread`, AppInit_DLLs) | `DYLD_INSERT_LIBRARIES` at exec |
| Kernel driver enumerating processes | `NOTIFY_EXEC` / `FORK` / `EXIT` stream |
| Driver checking image signatures | `codesigning_flags` + Team ID/Signing ID per process |

The monitor is **passive**: it subscribes only to `NOTIFY` events, so it can
never block or deadlock the system. The source notes inline where a production
build would upgrade `GET_TASK` to the `AUTH_` variant to *deny* task-port
access to the protected process instead of merely logging it.

---

## Entitlements & runtime requirements

Running an ES client has four gates. Missing any one produces a specific error
that the program prints on startup.

1. **Entitlement** `com.apple.developer.endpoint-security.client`
   (in `entitlements/vanguard.entitlements`). The binary must be code-signed
   with it, or `es_new_client()` returns `ERR_NOT_ENTITLED`.
   - On a **stock, SIP-enabled Mac** this entitlement is *managed*: Apple must
     grant it to your Developer account and embed it in a provisioning
     profile, or the binary must be Apple-signed. This is the same gate every
     third-party EDR/anti-cheat vendor goes through.
2. **Root** — ES clients must run as `root` (`sudo`), else `ERR_NOT_PRIVILEGED`.
3. **Full Disk Access (TCC)** — grant it to the binary in
   *System Settings → Privacy & Security → Full Disk Access*, else
   `ERR_NOT_PERMITTED`.
4. **Code signature present** — even ad-hoc (`codesign -s -`) is fine for local
   research; the entitlement just has to be attached.

---

## Build

> Requires macOS (Apple Silicon or Intel) with the Xcode command line tools.
> It will not build on Linux — it links the system `libEndpointSecurity`.

```sh
cd Phase1-ProcessMonitor
make            # compile + ad-hoc sign with the ES entitlement
```

Artifacts land in `build/vanguard_monitor`, already signed. Verify the
entitlement stuck:

```sh
codesign --display --entitlements - build/vanguard_monitor
```

## Running locally (research machine)

Because the ES entitlement is managed, a self-signed build is only accepted if
you relax platform enforcement. **Do this only on a dedicated test Mac.**

1. Boot into **recoveryOS** (hold the power button on Apple Silicon) →
   *Utilities → Terminal*:
   ```sh
   csrutil disable                 # turn off System Integrity Protection
   ```
   For self-signed *entitled* binaries you also disable AMFI library
   validation; the exact `nvram boot-args` (e.g. `amfi_get_out_of_my_way=1`)
   vary by macOS version — see Apple's platform notes. Reboot.
2. Grant the built binary **Full Disk Access** (step 3 above).
3. Run:
   ```sh
   sudo ./build/vanguard_monitor                 # log all task-port access
   sudo ./build/vanguard_monitor MyGame          # escalate access to "MyGame" to ALERT
   # or simply:
   make run TARGET=MyGame
   ```

A properly provisioned (Apple-granted) build skips the SIP/AMFI steps entirely
and runs on stock macOS — that is the production path and the whole point of
the pitch.

## Running on stock macOS (Apple-granted entitlement, no SIP changes)

This is the production path — and the credible one for a game-studio pitch:
"runs on an unmodified Mac" beats "works once you disable SIP."

1. **Request the entitlement.** Apply for `com.apple.developer.endpoint-security.client`
   via Apple's [Endpoint Security request form](https://developer.apple.com/contact/request/system-extension/).
   Approval typically takes a few days. Once granted, it attaches to your Team.
2. **Make a provisioning profile.** In the Developer portal, create an App ID
   (e.g. `com.yourteam.vanguard-monitor`) with the Endpoint Security
   capability, then generate and download a provisioning profile for it that
   includes the entitlement.
3. **Build the signed bundle.** A restricted entitlement must be authorized by
   an *embedded provisioning profile*, which a bare executable can't carry — so
   the `release` target wraps the binary in a `.app`:
   ```sh
   make release \
     SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
     PROFILE=~/Downloads/Vanguard_Monitor.provisionprofile \
     APP_BUNDLE_ID=com.yourteam.vanguard-monitor
   sudo build/Vanguard.app/Contents/MacOS/vanguard_monitor MyGame
   ```

**Honest caveat on distribution form.** A Developer-ID-signed bundle run as
root (above) is right for development and a local demo. For shipping to end
users (gamers), the fully-supported delivery vehicle is a **notarized System
Extension** hosted by a container app that activates it via the
`SystemExtensions` framework — that's a further packaging step, not a change to
the monitor logic. Ask and we can scaffold it.

---

## Example output

```
[vanguard] Phase 1 process monitor starting...
[vanguard] protecting target matching: "MyGame"
[vanguard] subscribed to 7 event types. monitoring... (Ctrl-C to stop)
[2026-06-11T10:55:21.314] INFO  EXEC        pid=4412 ppid=1 path=/Applications/MyGame.app/Contents/MacOS/MyGame  signing=[valid team=A1B2C3D4E5 id=com.studio.mygame]
[2026-06-11T10:55:24.008] INFO  EXEC        pid=4490 ppid=4471 path=/Users/dev/cheat/loader  signing=[INVALID adhoc  team=(none) id=loader]
[2026-06-11T10:55:24.140] ALERT EXEC+INJECT pid=4501 ppid=4490 path=/Applications/MyGame.app/Contents/MacOS/MyGame  signing=[valid ...]  via=DYLD_INSERT_LIBRARIES=/Users/dev/cheat/hook.dylib
[2026-06-11T10:55:31.870] ALERT GET_TASK        requester=4490(/Users/dev/cheat/loader) target=4412(/Applications/MyGame.app/Contents/MacOS/MyGame)  requester-signing=[INVALID adhoc team=(none) id=loader]  <== PROTECTED PROCESS
```

Severity tags: `INFO ` (telemetry) · `WATCH` (task-port access to some other
process) · `ALERT` (injection, or task-port access to the protected process).

---

## See it react (test harness)

`test/demo_detections.sh` generates the two headline detections so you can
watch the monitor fire. Use two terminals:

```sh
# Terminal A — run the monitor, protecting a process named "vgtarget"
make
sudo ./build/vanguard_monitor vgtarget

# Terminal B — trigger the detections
./test/demo_detections.sh
```

The script (safe: a harmless demo dylib + a renamed copy of `/bin/sleep`) does
two things and you should see one `ALERT` in Terminal A for each:

1. **Task-port access** — runs `vmmap` against the protected process
   (`task_for_pid`, the `OpenProcess` analogue) →
   `ALERT GET_TASK ... <== PROTECTED PROCESS`.
2. **dylib injection** — execs a binary with `DYLD_INSERT_LIBRARIES` set →
   `ALERT EXEC+INJECT ... via=DYLD_INSERT_LIBRARIES=...`.

Note it copies the binaries off the sealed system volume on purpose: SIP
strips `DYLD_*` from platform binaries, so the injection must target a
non-system binary to be observable (a useful real-world caveat in itself).

## Files

```
Phase1-ProcessMonitor/
├── src/vanguard_monitor.c            # the monitor (heavily commented)
├── entitlements/vanguard.entitlements# the one ES entitlement, explained
├── Makefile                          # build + ad-hoc codesign + run
├── test/
│   ├── demo_detections.sh            # generate task-port + injection alerts
│   └── demo_inject.c                 # harmless demo dylib for the injection test
└── README.md                         # this file
```

## Limitations (full analysis lands in Phase 3)

- The ES entitlement is gated by Apple; this is a feature (vetting) and a
  friction point (you must be approved). Honest tradeoff vs. a Windows driver
  you ship yourself.
- This phase only *observes*. Active prevention requires `AUTH_` events
  (hook noted in the source).
- It does not yet attest *who* is running — that the host and the monitor are
  genuine. That trust anchor is **Phase 2** (Secure Enclave + App Attest).
