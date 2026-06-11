# Phase 4 — System Extension: Production Distribution Path

## What this phase is

Phase 1 proved that Endpoint Security (ES) event monitoring works: `vanguard_monitor.c` subscribes to ES events, classifies them, and emits alerts. But it can only be shipped as a raw CLI binary that requires:

- Root privileges (`sudo`) at every launch
- Full Disk Access granted manually in System Settings
- SIP relaxation for self-signed Developer ID builds

None of those conditions are acceptable in a shipped game client.

Phase 4 repackages the **same ES detection logic** as a **notarized macOS System Extension**. Once the user approves it once in System Settings, it runs as a background daemon controlled by launchd — no root prompt, no SIP flag, no manual permissions toggle.

---

## System Extension lifecycle

```
1. Install
   User downloads and opens Vanguard.app (the container app).
   AppDelegate calls SMAppService.mainApp.register().
   macOS records the extension as "pending approval."

2. User approves (once per machine)
   macOS shows a banner in System Settings → Privacy & Security → Security.
   The user clicks "Allow" and authenticates.
   This step happens exactly once; reboots and re-launches skip it.

3. SMAppService activates
   launchd starts VanguardExtension.appex as a background daemon.
   The extension calls NSExtensionMain() and waits for XPC connections.

4. Extension runs as a daemon
   The extension subscribes to ES events via es_new_client / es_subscribe.
   It maintains an in-memory ring buffer of the last 1 000 alerts.
   It exposes the VanguardXPCProtocol interface over a Mach XPC service.

5. Game client connects via XPC
   The game engine SDK (or the container app) opens an NSXPCConnection
   to "com.yourcompany.Vanguard.Extension.xpc".
   It calls startMonitoring(target:reply:), polls getAlerts(), etc.
   The extension continues running whether or not the container app is open.

6. Deactivation
   The container app calls SMAppService.mainApp.unregister() from an
   "Uninstall" menu item.  launchd stops the extension immediately.
```

---

## What changes from Phase 1

| | Phase 1 (CLI) | Phase 4 (System Extension) |
|---|---|---|
| **Delivery** | Raw binary, run manually | Bundled in a notarized .app |
| **Privileges** | Root required every launch | Approved once; runs as daemon |
| **SIP** | Must be relaxed for self-signed | Not required (notarized) |
| **Start/stop** | Shell signals / process kill | XPC: `startMonitoring` / `stopMonitoring` |
| **IPC** | stdout JSON lines | XPC: typed Swift protocol |
| **ES logic** | `handle_event()` in C | Same logic, ported to Swift `handleESEvent()` |
| **Alert storage** | Ephemeral stdout | In-memory ring buffer (1 000 entries) |
| **Distribution** | Internal only | Mac App Store or notarized direct download |

The detection rules and severity classification are identical. The only architectural change is the delivery mechanism and IPC layer.

---

## File structure

```
Phase4-SystemExtension/
├── README.md                   ← this file
├── Makefile                    ← explains the Xcode build; prints instructions
├── Protocol/
│   └── VanguardXPC.swift       ← shared XPC protocol (added to both targets)
├── Extension/
│   └── VanguardExtension.swift ← System Extension: ES monitor + XPC service
└── Container/
    └── AppDelegate.swift       ← Container app: SMAppService activation
```

---

## What you need to build it

### Xcode project (not committed)

The `.xcodeproj` is not committed to this repository because it embeds
signing certificates and team IDs. Create it manually:

**Target 1 — Vanguard (macOS App)**

- Type: macOS App
- Bundle ID: `com.yourcompany.Vanguard`
- Deployment target: macOS 13.0
- Sources: `Container/AppDelegate.swift`, `Protocol/VanguardXPC.swift`
- Linked frameworks: `ServiceManagement.framework`
- Embed: `VanguardExtension.appex` (drag the extension target into the Embed System Extensions build phase)

**Target 2 — VanguardExtension (System Extension)**

- Type: System Extension
- Bundle ID: `com.yourcompany.Vanguard.Extension`
- Deployment target: macOS 13.0
- Sources: `Extension/VanguardExtension.swift`, `Protocol/VanguardXPC.swift`
- Linked frameworks: `EndpointSecurity.framework`
- Info.plist additions:

```xml
<key>NSExtension</key>
<dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.system-extension.endpoint-security</string>
    <key>NSExtensionPrincipalClass</key>
    <string>$(PRODUCT_MODULE_NAME).ExtensionDelegate</string>
    <key>NSExtensionAttributes</key>
    <dict>
        <key>ESSendingMachServiceName</key>
        <string>com.yourcompany.Vanguard.Extension.xpc</string>
    </dict>
</dict>
```

### Entitlements

**Extension target** (`VanguardExtension.entitlements`):

```xml
<key>com.apple.developer.endpoint-security.client</key>
<true/>
```

> **Important:** Apple grants the `endpoint-security.client` entitlement manually. Submit a request at [developer.apple.com](https://developer.apple.com/contact/request/system-extension/) describing your anti-cheat use case. Approval typically takes 1–2 weeks.

**Container app target** (`Vanguard.entitlements`):

```xml
<key>com.apple.developer.system-extension.install</key>
<true/>
```

### Provisioning profiles

- A **Developer ID Application** profile for the container app that includes the `system-extension.install` entitlement.
- A **System Extension** provisioning profile for the extension that includes the `endpoint-security.client` entitlement. This profile must be created after Apple grants the entitlement.

### Notarization

After archiving in Xcode (Product → Archive → Distribute App → Developer ID):

```sh
xcrun notarytool submit Vanguard.zip \
    --apple-id  your@email.com \
    --team-id   YOURTEAMID \
    --password  <app-specific-password> \
    --wait

xcrun stapler staple Vanguard.app
```

Notarization replaces the SIP relaxation required in Phase 1. Once Apple's notarization ticket is stapled, the extension's `endpoint-security.client` entitlement is trusted on any Mac running macOS 13+.

---

## Completing the ES stub

`VanguardExtension.swift` contains `// ES_CLIENT_STUB:` comments marking every location where the real Endpoint Security calls go. The stub compiles cleanly but does not subscribe to any events.

To complete the implementation:

1. Copy the event type list and severity classification from `Phase1-ProcessMonitor/src/vanguard_monitor.c` → `handle_event()`.
2. Replace each `// ES_CLIENT_STUB:` block with the corresponding ES API call (requires linking `EndpointSecurity.framework` and the granted entitlement).
3. The `handleESEvent(_:)` method already implements the ring buffer push and dropped-event tracking — only the `es_message_t` field extraction needs to be filled in.

---

## Notes

- The container app has no visible window. It runs as a menu bar extra or a pure background process. All user interaction is through the one-time System Settings approval prompt.
- The XPC Mach service name (`com.yourcompany.Vanguard.Extension.xpc`) must match in three places: the extension's Info.plist, the `NSXPCListener` initialiser in `VanguardExtension.swift`, and the `NSXPCConnection` initialiser in `AppDelegate.swift`.
- `SMAppService` requires macOS 13.0. For macOS 12 support use `SMExtensionErrorCode` from the older `SystemExtensions` framework, but SMAppService is the recommended path going forward.
