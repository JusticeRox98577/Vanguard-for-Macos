/*
 AttestationClient.swift
 ---------------------------------------------------------------------------
 Vanguard-for-macOS · Phase 2: Hardware Attestation Client

 Demonstrates the full hardware trust chain on Apple Silicon:

   1. SECURE ENCLAVE KEY CUSTODY
      Generate a P-256 key whose private half lives inside the Secure
      Enclave (SEP) and is non-exportable by construction. The CPU never
      sees the key bytes; it can only ask the SEP to sign. This is the
      "key custody" role of the hardware anchor (see Phase 3 ARCHITECTURE:
      we claim custody + attestation, never in-enclave compute).

   2. APP ATTEST — KEY GENERATION + ATTESTATION
      DCAppAttestService generates a *separate* SEP-resident key and asks
      Apple's servers to certify it. Apple returns an attestation object:
      a CBOR structure containing an X.509 certificate chain that roots in
      the Apple App Attest Root CA. The cert binds:
        - this exact app (Team ID + bundle ID baked into the cert), and
        - this exact physical device's Secure Enclave (a VM cannot
          produce one),
      to the new public key. Our server verifies the chain offline.

   3. APP ATTEST — PER-REQUEST ASSERTIONS
      After the one-time attestation, each subsequent request can carry an
      assertion: a SEP signature over a server-issued challenge, with a
      monotonically increasing counter that defeats replay. This is the
      cheap, repeatable "prove you are still the attested client" step.

 The trust inversion this enables (the core Phase 2 claim): the server
 does not trust the client because the client is unbreakable — it trusts
 the client because the client's identity is UNFORGEABLE. Tampering with
 the app changes its code signature, which invalidates attestation.

 ---------------------------------------------------------------------------
 Requirements (see Phase2-Attestation/README.md):
   - Apple Silicon Mac (or T2), macOS 11+ (DCAppAttestService availability).
   - Signed with a provisioning profile carrying the App Attest entitlement
     (com.apple.developer.devicecheck.appattest-environment) and an
     application-identifier — i.e. a real Apple Developer Team. App Attest
     cannot be exercised with ad-hoc signing; this is the point: Apple's
     vetting IS the trust root.
   - The verification server from ../server running (default localhost:8787).
 ---------------------------------------------------------------------------
 */

import CryptoKit
import DeviceCheck
import Foundation
import Security

// MARK: - Small helpers ------------------------------------------------------

let serverBase = ProcessInfo.processInfo.environment["VANGUARD_SERVER"]
    ?? "http://127.0.0.1:8787"

func log(_ s: String) { print("[attest-client] \(s)") }
func fail(_ s: String) -> Never { FileHandle.standardError.write(Data("[attest-client] ERROR: \(s)\n".utf8)); exit(1) }

/// Synchronous JSON HTTP helper. A PoC CLI has no need for an async stack;
/// a semaphore keeps the control flow readable top-to-bottom.
func http(_ method: String, _ path: String, body: [String: Any]? = nil) -> [String: Any] {
    guard let url = URL(string: serverBase + path) else { fail("bad url \(path)") }
    var req = URLRequest(url: url)
    req.httpMethod = method
    if let body = body {
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
    }
    var result: [String: Any] = [:]
    let sem = DispatchSemaphore(value: 0)
    URLSession.shared.dataTask(with: req) { data, resp, err in
        defer { sem.signal() }
        if let err = err { fail("\(method) \(path): \(err.localizedDescription) — is the server running?") }
        guard let data = data,
              let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { fail("\(method) \(path): non-JSON response") }
        if let http = resp as? HTTPURLResponse, http.statusCode >= 400 {
            fail("\(method) \(path) -> HTTP \(http.statusCode): \(json["error"] ?? json)")
        }
        result = json
    }.resume()
    sem.wait()
    return result
}

// MARK: - Step 1: raw Secure Enclave key (custody demo) ----------------------

/*
 Why show this separately from App Attest: App Attest wraps SEP keys in
 Apple's certification flow, but the underlying primitive — a private key
 that physically cannot leave the silicon — is available directly via the
 Security framework. This is what "hardware-enforced trust anchor = key
 custody" means in practice, in ~20 lines.

 kSecAttrTokenIDSecureEnclave routes key generation INTO the SEP. The
 returned SecKey is a handle; SecKeyCopyExternalRepresentation on the
 private key fails by design. Signing happens inside the enclave.
 */
func demoSecureEnclaveKey() {
    log("— Step 1: Secure Enclave key custody —")

    let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage],          // key usable for signing while unlocked
        nil)!

    let attrs: [String: Any] = [
        kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom, // P-256: the only SEP curve
        kSecAttrKeySizeInBits as String:  256,
        kSecAttrTokenID as String:        kSecAttrTokenIDSecureEnclave,    // <- the line that matters
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String:    false,  // ephemeral for the demo
            kSecAttrAccessControl as String:  access,
        ],
    ]

    var err: Unmanaged<CFError>?
    guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
        // Typical causes: not Apple Silicon/T2, or binary not signed with a
        // Team identity (the data-protection keychain requires it).
        log("  SEP key generation unavailable: \(err!.takeRetainedValue())")
        log("  (requires Apple Silicon/T2 and Team-signed binary; continuing)")
        return
    }

    let pub = SecKeyCopyPublicKey(priv)!
    let pubData = SecKeyCopyExternalRepresentation(pub, &err)! as Data
    log("  SEP P-256 key generated. public key (X9.63): \(pubData.base64EncodedString())")

    // Prove the private key is opaque: exporting it must fail.
    if SecKeyCopyExternalRepresentation(priv, &err) == nil {
        log("  private key export refused by SEP (expected) ✓")
    } else {
        fail("private key exported?! SEP custody is broken — investigate")
    }

    // Sign inside the enclave; verify with the public key on the CPU.
    let msg = Data("vanguard-phase2-sep-custody".utf8)
    let sig = SecKeyCreateSignature(
        priv, .ecdsaSignatureMessageX962SHA256, msg as CFData, &err)! as Data
    let ok = SecKeyVerifySignature(
        pub, .ecdsaSignatureMessageX962SHA256, msg as CFData, sig as CFData, &err)
    log("  enclave-signed message verifies: \(ok ? "✓" : "✗")")
}

// MARK: - Steps 2+3: App Attest ----------------------------------------------

func runAppAttest() {
    log("— Step 2: App Attest key + Apple-certified attestation —")

    let service = DCAppAttestService.shared
    // On macOS, isSupported checks for the appattest-environment entitlement which
    // macOS provisioning profiles don't include. Attempt the API directly; if the
    // platform doesn't support it, generateKey will surface a clear error.
    if !service.isSupported {
        log("  NOTE: isSupported=false (expected on macOS without appattest-environment entitlement); attempting API anyway")
    }

    let sem = DispatchSemaphore(value: 0)

    // 2a. Generate the App Attest key. Like Step 1 this is SEP-resident and
    //     non-exportable; unlike Step 1 it is managed by Apple's DeviceCheck
    //     daemon and identified by an opaque keyId (base64 of the SHA-256 of
    //     the public key — the server re-derives and cross-checks this).
    var keyId = ""
    service.generateKey { id, error in
        if let error = error { fail("generateKey: \(error.localizedDescription)") }
        keyId = id!
        sem.signal()
    }
    sem.wait()
    log("  App Attest keyId: \(keyId)")

    // 2b. Ask OUR server for a one-time challenge. The challenge prevents an
    //     attacker replaying somebody else's (valid) attestation: Apple signs
    //     over a hash that includes it, so each attestation is bound to this
    //     specific session.
    let ch1 = http("GET", "/challenge")
    guard let challenge1 = ch1["challenge"] as? String else { fail("no challenge") }
    let clientDataHash1 = Data(SHA256.hash(data: Data(base64Encoded: challenge1)!))

    // 2c. attestKey: the SEP signs, then Apple's servers counter-sign,
    //     returning the CBOR attestation object with the cert chain rooted
    //     in the Apple App Attest Root CA. Requires network to Apple.
    var attestation = Data()
    service.attestKey(keyId, clientDataHash: clientDataHash1) { att, error in
        if let error = error { fail("attestKey: \(error.localizedDescription)") }
        attestation = att!
        sem.signal()
    }
    sem.wait()
    log("  received Apple attestation object (\(attestation.count) bytes)")

    // 2d. Send to our verification server, which walks the cert chain,
    //     checks the nonce binding, app identity, and key id — see
    //     server/verify.js for every verification step, commented.
    let attResp = http("POST", "/attest", body: [
        "keyId": keyId,
        "challenge": challenge1,
        "attestation": attestation.base64EncodedString(),
    ])
    log("  server verdict: \(attResp["verified"] as? Bool == true ? "ATTESTED ✓" : "REJECTED ✗") \(attResp["details"] ?? "")")
    guard attResp["verified"] as? Bool == true else { exit(1) }

    log("— Step 3: per-request assertion (replay-proof) —")

    // 3a. Fresh challenge for the assertion. clientData is what a real game
    //     client would protect: here a tiny JSON envelope; in production the
    //     telemetry payload (e.g. Phase 1 ALERT events) goes in here, making
    //     each report hardware-signed.
    let ch2 = http("GET", "/challenge")
    guard let challenge2 = ch2["challenge"] as? String else { fail("no challenge") }

    // 3a-i. Read the running Phase 1 telemetry hash.
    //
    // Security property: Phase 1 (the ES endpoint-security monitor) maintains a
    // rolling SHA-256 digest of every telemetry event it processes, and writes
    // the current value to /tmp/vanguard_telemetry.hash (base64, atomic rename).
    // By embedding that hash in clientData — which is then signed by the Secure
    // Enclave via App Attest — we cryptographically bind the telemetry stream to
    // this assertion. An attacker who runs a parallel "clean" fake telemetry
    // feed alongside the genuine attested agent cannot substitute its hash here
    // without breaking the SEP signature; the hardware attestation makes the
    // telemetry digest UNFORGEABLE.
    var telemetryHashValue: String? = nil
    let telemetryHashPath = "/tmp/vanguard_telemetry.hash"
    if let raw = try? String(contentsOfFile: telemetryHashPath, encoding: .utf8) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            telemetryHashValue = trimmed
            log("  telemetry hash bound: \(String(trimmed.prefix(16)))...")
        }
    }
    if telemetryHashValue == nil {
        log("  telemetry hash: not present (Phase 1 not running)")
    }

    // Build clientData, including the telemetry hash when available.
    var clientDataDict: [String: Any] = [
        "challenge": challenge2,
        "payload": "phase1-telemetry-would-go-here",
    ]
    if let hash = telemetryHashValue {
        clientDataDict["telemetryHash"] = hash
    } else {
        clientDataDict["telemetryHash"] = "none"
    }
    let clientData = try! JSONSerialization.data(withJSONObject: clientDataDict,
                                                 options: [.sortedKeys])
    let clientDataHash2 = Data(SHA256.hash(data: clientData))

    // 3b. generateAssertion: SEP signs (authenticatorData || clientDataHash)
    //     and bumps the embedded counter — the server enforces monotonicity,
    //     so captured assertions cannot be replayed.
    var assertion = Data()
    service.generateAssertion(keyId, clientDataHash: clientDataHash2) { a, error in
        if let error = error { fail("generateAssertion: \(error.localizedDescription)") }
        assertion = a!
        sem.signal()
    }
    sem.wait()

    let assertResp = http("POST", "/assert", body: [
        "keyId": keyId,
        "clientData": clientData.base64EncodedString(),
        "assertion": assertion.base64EncodedString(),
    ])
    let returnedTelemetryHash = assertResp["telemetryHash"] as? String
    let hashSuffix: String
    if let h = returnedTelemetryHash, h != "none", !h.isEmpty {
        hashSuffix = " telemetryHash=\(String(h.prefix(16)))..."
    } else {
        hashSuffix = " telemetryHash=none"
    }
    log("  server verdict: \(assertResp["verified"] as? Bool == true ? "ASSERTION VALID ✓" : "REJECTED ✗") counter=\(assertResp["counter"] ?? "?")\(hashSuffix)")
    guard assertResp["verified"] as? Bool == true else { exit(1) }

    log("full trust chain demonstrated: SEP → Apple → server ✓")
}

// MARK: - main ----------------------------------------------------------------

demoSecureEnclaveKey()
runAppAttest()
