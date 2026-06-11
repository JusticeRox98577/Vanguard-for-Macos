// AppDelegate.swift
// Phase 4 — Container App: SMAppService activation of the System Extension
//
// ---------------------------------------------------------------------------
// USER-FACING APPROVAL UX — why this exists and what the user sees
// ---------------------------------------------------------------------------
//
// macOS 13+ (Ventura) requires explicit user consent before any System
// Extension becomes active.  This is a deliberate security gate: a malicious
// app cannot silently install a privileged daemon.
//
// The flow from the user's perspective:
//
//   1. User launches Vanguard (the container app) for the first time.
//   2. AppDelegate calls SMAppService.mainApp.register().
//   3. macOS returns .requiresApproval — the extension is PENDING.
//   4. AppDelegate shows an NSAlert directing the user to:
//         System Settings → Privacy & Security → Security
//      where a banner reads "System software from [your team] was blocked."
//   5. The user clicks "Allow" and authenticates with Touch ID / password.
//   6. SMAppService.mainApp.status transitions to .enabled.
//   7. launchd activates VanguardExtension as a background daemon.
//   8. The game engine SDK can now open an XPC connection to the extension.
//
// This prompt appears AT MOST ONCE PER MACHINE.  After the user approves,
// re-launching the container app or rebooting does not show the prompt again;
// SMAppService.status returns .enabled immediately.
//
// ---------------------------------------------------------------------------
// BUILD REQUIREMENTS (set in Xcode, not here)
// ---------------------------------------------------------------------------
//
//   Target type  : macOS App (container)
//   Bundle ID    : com.yourcompany.Vanguard
//   Entitlements : com.apple.security.app-sandbox = YES (if sandboxed)
//                  com.apple.developer.system-extension.install = YES
//   Info.plist   : NSSystemAdministrationUsageDescription — explain why the
//                  extension needs elevated trust (shown on first launch)
//   Deployment target : macOS 13.0 (SMAppService requires 13+)

import Cocoa
import ServiceManagement   // SMAppService lives here

@main
final class AppDelegate: NSObject, NSApplicationDelegate {

    // ------------------------------------------------------------------
    // MARK: - NSApplicationDelegate

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Request activation of the System Extension bundled inside the
        // container app's Contents/Library/SystemExtensions/ directory.
        //
        // register() is idempotent: if the extension is already enabled
        // (e.g. on subsequent launches) it returns immediately with no UI.
        requestActivation()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // The container app is intentionally minimal — it has no windows.
        // The extension runs as a daemon regardless of whether the container
        // app is open.  Return false so the app stays alive in the menu bar
        // (or as a background process) to handle SMAppService status queries.
        return false
    }

    // ------------------------------------------------------------------
    // MARK: - Extension lifecycle

    /// Register (activate) the bundled System Extension via SMAppService.
    ///
    /// Call this once on first launch.  On subsequent launches the extension
    /// is already running and this call returns immediately.
    func requestActivation() {
        let service = SMAppService.mainApp

        // SMAppService.register() is synchronous for the registration step
        // but the actual activation (user approval) is asynchronous.
        do {
            try service.register()
            // Reaching this line means registration was submitted successfully.
            // The extension may not be running yet if approval is still pending.
            checkStatusAfterRegistration()
        } catch let error as NSError {
            // Common error codes:
            //   kSMErrorAlreadyRegistered (22) — not a real error; extension
            //     is already registered (enabled or pending).
            //   kSMErrorAuthorizationFailure — user declined SIP-level prompt.
            if error.domain == SMAppService.errorDomain,
               error.code   == kSMAppServiceErrorCode_AlreadyRegistered {
                // Normal path on second+ launch.
                checkStatusAfterRegistration()
            } else {
                showErrorAlert(message: "Failed to register Vanguard System Extension.",
                               detail: error.localizedDescription)
            }
        }
    }

    /// Inspect the current SMAppService status and react accordingly.
    private func checkStatusAfterRegistration() {
        switch SMAppService.mainApp.status {

        case .enabled:
            // Happy path — extension is running.  The game engine SDK can now
            // open an XPC connection to "com.yourcompany.Vanguard.Extension.xpc".
            NSLog("[Vanguard] System Extension is active.")

        case .requiresApproval:
            // The extension has been registered but the user has not yet
            // approved it in System Settings.  Show guidance.
            showApprovalRequiredAlert()

        case .notFound:
            // The extension bundle is missing from the app's
            // Contents/Library/SystemExtensions/ directory.
            // This is a packaging error, not a user error.
            showErrorAlert(
                message: "System Extension bundle not found.",
                detail:  "Please reinstall Vanguard. The extension binary is missing from the application bundle.")

        case .notRegistered:
            // register() succeeded but launchd has not activated it yet.
            // This is a transient state; no action needed.
            NSLog("[Vanguard] System Extension registered; waiting for launchd activation.")

        @unknown default:
            NSLog("[Vanguard] Unknown SMAppService status: \(SMAppService.mainApp.status.rawValue)")
        }
    }

    /// Deactivate and unregister the System Extension.
    ///
    /// Call this from an "Uninstall Vanguard" menu action.  After this call
    /// the extension stops running immediately and launchd will not restart it.
    /// The user will need to approve it again if they re-install.
    func deactivateExtension() {
        Task {
            do {
                try await SMAppService.mainApp.unregister()
                NSLog("[Vanguard] System Extension successfully unregistered.")
            } catch {
                NSLog("[Vanguard] Failed to unregister extension: \(error.localizedDescription)")
            }
        }
    }

    // ------------------------------------------------------------------
    // MARK: - XPC connection (convenience helper for callers)

    /// Build a ready-to-use proxy object for sending XPC messages to the
    /// running System Extension.
    ///
    /// The game engine SDK would call this to obtain a `VanguardXPCProtocol`
    /// proxy, then call `startMonitoring(target:reply:)` etc.
    ///
    /// - Returns: A proxy conforming to `VanguardXPCProtocol`, or nil if the
    ///   connection cannot be established (e.g. extension not yet active).
    func makeXPCProxy() -> VanguardXPCProtocol? {
        // The machServiceName must match:
        //   • NSXPCListener(machServiceName:) in VanguardExtension.swift
        //   • The ESSendingMachServiceName key in the extension's Info.plist
        let connection = NSXPCConnection(
            machServiceName: "com.yourcompany.Vanguard.Extension.xpc",
            options: []
        )
        connection.remoteObjectInterface = NSXPCInterface(with: VanguardXPCProtocol.self)
        connection.resume()

        return connection.remoteObjectProxyWithErrorHandler { error in
            NSLog("[Vanguard] XPC connection error: \(error.localizedDescription)")
        } as? VanguardXPCProtocol
    }

    // ------------------------------------------------------------------
    // MARK: - Alert helpers

    /// Show a modal alert asking the user to approve the extension in
    /// System Settings.  This is triggered once, on first launch.
    private func showApprovalRequiredAlert() {
        DispatchQueue.main.async {
            let alert              = NSAlert()
            alert.messageText      = "Approve Vanguard in System Settings"
            alert.informativeText  =
                "To protect your game sessions, Vanguard needs approval as a " +
                "System Extension.\n\n" +
                "1. Open System Settings → Privacy & Security → Security.\n" +
                "2. Find the message about Vanguard and click Allow.\n" +
                "3. Authenticate with your password or Touch ID.\n\n" +
                "This prompt appears only once. After approval, Vanguard " +
                "starts automatically and requires no further interaction."
            alert.addButton(withTitle: "Open System Settings")
            alert.addButton(withTitle: "Later")
            alert.alertStyle = .informational

            if alert.runModal() == .alertFirstButtonReturn {
                // Deep-link directly to the Security pane so the user does
                // not have to navigate manually.
                if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Security") {
                    NSWorkspace.shared.open(url)
                }
            }
        }
    }

    /// Show a generic error alert for unrecoverable failures.
    private func showErrorAlert(message: String, detail: String) {
        DispatchQueue.main.async {
            let alert             = NSAlert()
            alert.messageText     = message
            alert.informativeText = detail
            alert.alertStyle      = .critical
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    }
}

// ---------------------------------------------------------------------------
// MARK: - SMAppService error code shim
// ---------------------------------------------------------------------------
// SMAppService.errorDomain constants are not exported as Swift symbols in all
// SDK versions.  Define the raw value here to avoid a compile-time dependency
// on a specific macOS SDK patch level.

private let kSMAppServiceErrorCode_AlreadyRegistered: Int = 22
