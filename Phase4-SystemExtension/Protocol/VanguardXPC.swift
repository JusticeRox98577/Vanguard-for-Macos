// VanguardXPC.swift
// Phase 4 — Shared XPC Protocol Definition
//
// This file is compiled into BOTH targets:
//   • VanguardApp      (container app)  — uses it to build the NSXPCConnection proxy
//   • VanguardExtension (system ext)    — uses it to declare conformance
//
// Keeping the protocol in a shared location means both sides stay in sync
// automatically; a mismatch would cause XPC to silently drop calls.
//
// Why @objc?
//   NSXPCConnection uses Objective-C runtime introspection to set up the
//   message bridge. The protocol must be @objc so its selectors are visible
//   to the ObjC runtime even though both sides are written in Swift.

import Foundation

// ---------------------------------------------------------------------------
// MARK: - Alert dictionary key constants
// ---------------------------------------------------------------------------
// Using string constants rather than embedding literals everywhere reduces the
// risk of typos that would silently produce empty values on the other side of
// the XPC boundary.

public enum VanguardAlertKey {
    /// ISO-8601 timestamp of when the ES event was received
    public static let timestamp  = "timestamp"
    /// "low" | "medium" | "high" | "critical"
    public static let severity   = "severity"
    /// ES event type name, e.g. "ES_EVENT_TYPE_NOTIFY_EXEC"
    public static let eventType  = "event_type"
    /// Decimal string of the originating process ID
    public static let pid        = "pid"
    /// Absolute path of the process or file involved
    public static let path       = "path"
    /// Human-readable detail string; may contain rule match info
    public static let detail     = "detail"
}

// ---------------------------------------------------------------------------
// MARK: - Status dictionary key constants
// ---------------------------------------------------------------------------

public enum VanguardStatusKey {
    /// Bool — whether the ES client is currently subscribed
    public static let running        = "running"
    /// String — bundle ID or path of the monitored game target
    public static let target         = "target"
    /// Int — total ES events processed since startMonitoring was called
    public static let eventCount     = "event_count"
    /// Int — events dropped because the ring buffer was full or ES back-pressured
    public static let droppedCount   = "dropped_count"
    /// String — SHA-256 hex digest of the last telemetry batch sent upstream;
    ///          empty string when no batch has been sent yet
    public static let telemetryHash  = "telemetry_hash"
}

// ---------------------------------------------------------------------------
// MARK: - XPC Protocol
// ---------------------------------------------------------------------------

/// The interface exposed by the System Extension to the container app (and,
/// transitively, to the game engine SDK).
///
/// All methods are asynchronous: the extension enqueues work on its own queue
/// and calls the reply block when done.  NSXPCConnection serialises the reply
/// block back to the caller's process automatically.
///
/// Thread safety: the extension implementation is responsible for
/// synchronising access to shared state before invoking reply blocks.
@objc public protocol VanguardXPCProtocol {

    // -----------------------------------------------------------------------
    // MARK: Control
    // -----------------------------------------------------------------------

    /// Subscribe the Endpoint Security client to the event stream for `target`.
    ///
    /// - Parameters:
    ///   - target: Bundle identifier of the game process to monitor (e.g.
    ///             "com.example.MyGame").  Pass an empty string to monitor
    ///             all processes (requires additional entitlements).
    ///   - reply:  Called exactly once.
    ///             • `success` is `true` when the ES client is now running.
    ///             • `message` carries a human-readable status string, or an
    ///               error description when `success` is `false`.
    func startMonitoring(target: String, reply: @escaping (Bool, String) -> Void)

    /// Unsubscribe the ES client and release its resources.
    ///
    /// - Parameter reply: Called exactly once with `true` on success.
    ///   Returns `false` if the client was not running.
    func stopMonitoring(reply: @escaping (Bool) -> Void)

    // -----------------------------------------------------------------------
    // MARK: Data retrieval
    // -----------------------------------------------------------------------

    /// Return the current contents of the alert ring buffer.
    ///
    /// Each element is a `[String: String]` dictionary whose keys are defined
    /// in `VanguardAlertKey`.  The array is ordered oldest-first and contains
    /// at most 1 000 entries (the ring buffer capacity).
    ///
    /// - Parameter reply: Called with a snapshot of the buffer.  The snapshot
    ///   is taken under a lock so it is self-consistent.
    func getAlerts(reply: @escaping ([[String: String]]) -> Void)

    /// Return a status dictionary for the running extension.
    ///
    /// Keys are defined in `VanguardStatusKey`.  The dictionary is typed
    /// `[String: Any]` because it mixes Bool, Int, and String values; the
    /// caller is responsible for casting individual values.
    ///
    /// - Parameter reply: Called with the current status snapshot.
    func getStatus(reply: @escaping ([String: Any]) -> Void)
}
