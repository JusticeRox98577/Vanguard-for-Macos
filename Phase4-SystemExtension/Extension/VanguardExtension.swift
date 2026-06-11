// VanguardExtension.swift
// Phase 4 — System Extension: Endpoint Security monitor + XPC service
//
// ---------------------------------------------------------------------------
// SYSTEM EXTENSION LIFECYCLE — why this file exists
// ---------------------------------------------------------------------------
//
// Phase 1 shipped vanguard_monitor as a CLI binary.  It worked, but had three
// distribution blockers:
//
//   1. Required `sudo` (root UID) at every launch.
//   2. Required SIP relaxation for a self-signed ES entitlement.
//   3. Had no supervised start/stop — the game engine couldn't control it.
//
// A System Extension (introduced in macOS 10.15) solves all three:
//
//   • The extension binary is signed with a Developer ID + the
//     com.apple.developer.endpoint-security.client entitlement, then
//     notarized.  Apple's notarization ticket replaces SIP relaxation.
//
//   • The extension runs as a long-lived daemon managed by launchd, not by
//     the user.  It starts once after SMAppService.register() and stays
//     resident across reboots without a sudo prompt.
//
//   • The game engine (or container app) communicates via XPC — a structured,
//     privilege-separated IPC mechanism baked into macOS.  XPC replaces the
//     ad-hoc stdout/signal interface from Phase 1.
//
// SMAppService replaces the old LaunchDaemon + kextload workflow:
//   SMAppService.mainApp.register()  →  launchd activates the extension
//   SMAppService.mainApp.unregister() →  launchd deactivates it
//
// The extension must NOT contain a traditional main() that loops forever.
// Instead it calls NSExtensionMain() which hands control to the OS; launchd
// delivers XPC connections as they arrive.
//
// ---------------------------------------------------------------------------
// BUILD REQUIREMENTS (set in Xcode, not here)
// ---------------------------------------------------------------------------
//
//   Target type  : System Extension
//   Bundle ID    : com.yourcompany.Vanguard.Extension
//   Entitlements : com.apple.developer.endpoint-security.client  = YES
//                  com.apple.security.application-groups          = [shared group]
//   Info.plist keys:
//       NSExtension / NSExtensionPointIdentifier
//           = com.apple.system-extension.endpoint-security   (macOS 12+)
//       NSExtensionPrincipalClass = $(PRODUCT_MODULE_NAME).ExtensionDelegate

import Foundation
import EndpointSecurity   // links -lEndpointSecurity; add to Other Linker Flags
import SystemExtensions   // for OSSystemExtensionRequest type visibility

// ---------------------------------------------------------------------------
// MARK: - Ring buffer
// ---------------------------------------------------------------------------

/// A fixed-capacity FIFO that overwrites the oldest entry when full.
/// Access must be serialised by the caller (ExtensionDelegate uses alertQueue).
final class RingBuffer<T> {
    private var storage: [T]
    private var head: Int = 0   // index of the next write slot
    private var count: Int = 0
    let capacity: Int

    init(capacity: Int) {
        self.capacity = capacity
        storage = []
        storage.reserveCapacity(capacity)
    }

    func push(_ element: T) {
        if storage.count < capacity {
            storage.append(element)
        } else {
            storage[head] = element
        }
        head = (head + 1) % capacity
        count = min(count + 1, capacity)
    }

    /// Returns all elements in insertion order (oldest first).
    func snapshot() -> [T] {
        guard !storage.isEmpty else { return [] }
        if storage.count < capacity {
            return Array(storage)
        }
        // head points to the oldest entry after a wrap-around
        let tail = storage[head...] + storage[..<head]
        return Array(tail)
    }

    var droppedCount: Int { max(0, count - capacity) }
}

// ---------------------------------------------------------------------------
// MARK: - Extension delegate (principal class)
// ---------------------------------------------------------------------------

/// The principal class of the System Extension target.
///
/// NSExtensionMain (called at the bottom of this file) instantiates this
/// class and registers it as the XPC listener delegate.  From that point on
/// the OS drives all activity through XPC messages.
final class ExtensionDelegate: NSObject, NSXPCListenerDelegate, VanguardXPCProtocol {

    // ------------------------------------------------------------------
    // MARK: State

    /// XPC listener bound to the Mach service name declared in Info.plist.
    private let listener: NSXPCListener

    /// ES client handle — nil when monitoring is not active.
    /// Wrapped in a class box so it can be mutated from a closure.
    private var esClient: OpaquePointer? = nil   // es_client_t *

    /// The bundle ID (or path) of the game being monitored.
    private var monitoredTarget: String = ""

    /// Cumulative event counter (includes dropped events).
    private var totalEventCount: Int = 0

    /// Events dropped because the ring buffer was full.
    private var droppedCount: Int = 0

    /// SHA-256 hex of the last telemetry batch; empty until first flush.
    private var lastTelemetryHash: String = ""

    /// Serialises all reads and writes to the ring buffer and counters.
    private let alertQueue = DispatchQueue(label: "com.vanguard.extension.alerts",
                                           qos: .utility)

    /// In-memory ring buffer — last 1 000 alerts, oldest first.
    private let alertBuffer = RingBuffer<[String: String]>(capacity: 1_000)

    // ------------------------------------------------------------------
    // MARK: Init

    override init() {
        // The Mach service name must match:
        //   • The NSExtension / NSExtensionAttributes / ESSendingMachServiceName
        //     key in the extension's Info.plist
        //   • The machServiceName passed to NSXPCConnection in the container app
        listener = NSXPCListener(machServiceName: "com.yourcompany.Vanguard.Extension.xpc")
        super.init()
        listener.delegate = self
        listener.resume()
    }

    // ------------------------------------------------------------------
    // MARK: NSXPCListenerDelegate

    /// Called by the OS each time a new XPC client (container app or game SDK)
    /// opens a connection to the extension's Mach service.
    func listener(_ listener: NSXPCListener,
                  shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {

        // Describe the interface the remote proxy will expose.
        // The container app sets the same interface on its end so both sides
        // agree on the method signatures before any messages are sent.
        newConnection.exportedInterface = NSXPCInterface(with: VanguardXPCProtocol.self)
        newConnection.exportedObject    = self

        // Optional: validate the connecting process (code signature, team ID)
        // before accepting.  For now we accept any local connection.
        newConnection.resume()
        return true
    }

    // ------------------------------------------------------------------
    // MARK: VanguardXPCProtocol — startMonitoring

    func startMonitoring(target: String, reply: @escaping (Bool, String) -> Void) {
        alertQueue.async { [weak self] in
            guard let self else { reply(false, "Extension deallocated"); return }

            if self.esClient != nil {
                reply(false, "Already monitoring '\(self.monitoredTarget)'")
                return
            }

            self.monitoredTarget  = target
            self.totalEventCount  = 0
            self.droppedCount     = 0
            self.lastTelemetryHash = ""

            // ----------------------------------------------------------
            // ES_CLIENT_STUB: call es_new_client here
            //
            // Production code (requires Xcode + entitlement to compile):
            //
            //   var client: OpaquePointer?
            //   let result = es_new_client(&client) { [weak self] _, event in
            //       self?.handleESEvent(event)
            //   }
            //   guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            //       let msg = "es_new_client failed: \(result.rawValue)"
            //       reply(false, msg)
            //       return
            //   }
            //   self.esClient = client
            // ----------------------------------------------------------

            // ----------------------------------------------------------
            // ES_CLIENT_STUB: call es_subscribe here
            //
            // Subscribe to the same event types as Phase 1:
            //
            //   let events: [es_event_type_t] = [
            //       ES_EVENT_TYPE_NOTIFY_EXEC,
            //       ES_EVENT_TYPE_NOTIFY_FORK,
            //       ES_EVENT_TYPE_NOTIFY_EXIT,
            //       ES_EVENT_TYPE_NOTIFY_OPEN,
            //       ES_EVENT_TYPE_NOTIFY_WRITE,
            //       ES_EVENT_TYPE_NOTIFY_MMAP,
            //       ES_EVENT_TYPE_NOTIFY_SIGNAL,
            //   ]
            //   let subResult = es_subscribe(client!, events, UInt32(events.count))
            //   guard subResult == ES_RETURN_SUCCESS else {
            //       es_delete_client(client!)
            //       self.esClient = nil
            //       reply(false, "es_subscribe failed: \(subResult.rawValue)")
            //       return
            //   }
            // ----------------------------------------------------------

            reply(true, "Monitoring started (stub) for target: '\(target)'")
        }
    }

    // ------------------------------------------------------------------
    // MARK: VanguardXPCProtocol — stopMonitoring

    func stopMonitoring(reply: @escaping (Bool) -> Void) {
        alertQueue.async { [weak self] in
            guard let self else { reply(false); return }

            guard self.esClient != nil else {
                reply(false)
                return
            }

            // ----------------------------------------------------------
            // ES_CLIENT_STUB: call es_unsubscribe_all + es_delete_client
            //
            //   es_unsubscribe_all(self.esClient!)
            //   es_delete_client(self.esClient!)
            //   self.esClient = nil
            // ----------------------------------------------------------

            self.esClient = nil
            reply(true)
        }
    }

    // ------------------------------------------------------------------
    // MARK: VanguardXPCProtocol — getAlerts

    func getAlerts(reply: @escaping ([[String: String]]) -> Void) {
        alertQueue.async { [weak self] in
            guard let self else { reply([]); return }
            reply(self.alertBuffer.snapshot())
        }
    }

    // ------------------------------------------------------------------
    // MARK: VanguardXPCProtocol — getStatus

    func getStatus(reply: @escaping ([String: Any]) -> Void) {
        alertQueue.async { [weak self] in
            guard let self else { reply([:]); return }
            let status: [String: Any] = [
                VanguardStatusKey.running:       self.esClient != nil,
                VanguardStatusKey.target:        self.monitoredTarget,
                VanguardStatusKey.eventCount:    self.totalEventCount,
                VanguardStatusKey.droppedCount:  self.droppedCount,
                VanguardStatusKey.telemetryHash: self.lastTelemetryHash,
            ]
            reply(status)
        }
    }

    // ------------------------------------------------------------------
    // MARK: ES event handler (called from the ES event callback)

    /// Translate a raw ES event into a `[String: String]` alert dict and
    /// push it onto the ring buffer.
    ///
    /// This method runs on the internal ES dispatch queue created by
    /// `es_new_client`.  All mutations go through `alertQueue.async` so
    /// there is no data race with XPC reads.
    ///
    /// Phase 1 reference: see vanguard_monitor.c → handle_event() for the
    /// severity classification logic that should be ported here.
    private func handleESEvent(_ event: UnsafePointer<es_message_t>) {
        // ------------------------------------------------------------------
        // ES_CLIENT_STUB: translate es_message_t fields to the alert dict
        //
        // let eventType = String(cString: es_event_type_to_string(event.pointee.event_type))
        // let pid       = String(event.pointee.process.pointee.audit_token.val.5)
        // let path      = String(cString: event.pointee.process.pointee.executable
        //                          .pointee.path.data)
        // let severity  = classifySeverity(event)   // port from Phase 1 logic
        // ------------------------------------------------------------------

        let alert: [String: String] = [
            VanguardAlertKey.timestamp: ISO8601DateFormatter().string(from: Date()),
            VanguardAlertKey.severity:  "medium",        // STUB — replace with real value
            VanguardAlertKey.eventType: "ES_EVENT_TYPE_STUB",
            VanguardAlertKey.pid:       "0",
            VanguardAlertKey.path:      "/stub/path",
            VanguardAlertKey.detail:    "ES_CLIENT_STUB: real event data goes here",
        ]

        alertQueue.async { [weak self] in
            guard let self else { return }
            self.totalEventCount += 1

            // Ring buffer push — if the buffer was already full the oldest
            // entry is silently discarded and droppedCount incremented.
            let wasFull = self.alertBuffer.snapshot().count == self.alertBuffer.capacity
            self.alertBuffer.push(alert)
            if wasFull { self.droppedCount += 1 }
        }
    }
}

// ---------------------------------------------------------------------------
// MARK: - Entry point
// ---------------------------------------------------------------------------
// System Extensions must call NSExtensionMain rather than defining a
// traditional @main struct or top-level main() function.  NSExtensionMain
// sets up the run loop, instantiates the principal class declared in
// Info.plist (NSExtensionPrincipalClass), and waits for XPC activity.
//
// In the Xcode project:
//   • Set "Extension Safe API Only" = NO (we need ES framework access)
//   • Remove any @main attribute from this file
//   • Add an Info.plist entry: NSExtensionPrincipalClass =
//       $(PRODUCT_MODULE_NAME).ExtensionDelegate

// Suppress the Swift compiler's requirement for a @main type.
// The real entry point is provided by the NSExtensionMain C symbol below.
extension ExtensionDelegate {
    static func extensionMain() {
        let delegate = ExtensionDelegate()
        // Retain the delegate for the lifetime of the process.
        // NSExtensionMain's run loop keeps the process alive.
        withExtendedLifetime(delegate) {
            // NSExtensionMain() is a C function; call it via the shim below.
            // In a real Xcode project this is handled automatically by the
            // "NSExtension" target template — you do not write a main.swift.
            RunLoop.main.run()
        }
    }
}

// Shim so this file compiles as a library target in isolation.
// In the real Xcode System Extension target, delete the lines below and let
// the template's generated main.m call NSExtensionMain().
//
// func main() {
//     ExtensionDelegate.extensionMain()
// }
