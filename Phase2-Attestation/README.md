# Phase 2 — Hardware Attestation (Secure Enclave + App Attest)

The trust anchor for the whole project. Phase 1 proves macOS can *observe*
the right events from user space; Phase 2 proves the server can *believe* a
user-space client, because the client's identity is rooted in the Secure
Enclave and co-signed by Apple. It demonstrates the full chain end to end:

```
Secure Enclave (device)  →  Apple App Attest servers  →  your verification server
   non-exportable key         certifies the key            walks the cert chain,
   signs challenges            (X.509 chain to             checks nonce, app id,
                               Apple Root CA)              and replay counter
```

**The core idea — "unforgeable, not unbreakable":** the server doesn't trust
the client because the client can't be hacked. It trusts the client because
the client can *prove* it is a genuine, unmodified build running on genuine
Apple hardware. Tamper with the app and its code signature changes, which
breaks attestation, and the server stops trusting it. That inversion is what
lets a user-mode agent stand in for a kernel driver.

---

## Layout

```
Phase2-Attestation/
├── client/                         # Swift, runs on the Mac
│   ├── src/AttestationClient.swift  #   SEP key custody + App Attest, commented
│   ├── entitlements/appattest.entitlements
│   └── Makefile                     #   builds a signed .app bundle
└── server/                         # Node.js verifier (stdlib + cbor only)
    ├── server.js                    #   /challenge, /attest, /assert
    ├── verify.js                    #   the Apple-spec verification steps
    └── package.json
```

## What the client does (3 steps)

1. **Secure Enclave key custody** — generates a raw P-256 key with
   `kSecAttrTokenIDSecureEnclave`, proves the private key *cannot be exported*,
   and signs a message inside the enclave. This is the hardware-anchor
   primitive in ~20 lines, independent of App Attest.
2. **App Attest attestation** — `DCAppAttestService.generateKey` +
   `attestKey` against a server challenge, producing Apple's CBOR attestation
   object (cert chain → Apple App Attest Root CA). The server verifies it.
3. **Per-request assertion** — `generateAssertion` signs a fresh challenge +
   payload with a monotonic counter; the server verifies the signature and
   rejects any counter that doesn't advance (replay defense). In production
   the **Phase 1 telemetry** would ride inside this signed `clientData`.

## What the server verifies (`verify.js`, every step commented)

For **attestation**: fmt is `apple-appattest`; leaf←intermediate←Apple root
chain; the nonce extension equals `SHA256(SHA256(authData ‖ clientDataHash))`
bound to *our* challenge; `keyId == SHA256(leaf public key)`; `rpIdHash ==
SHA256("TeamID.bundleID")`; the AAGUID matches the environment; `signCount == 0`.
For **assertions**: ECDSA signature over `SHA256(authData ‖ SHA256(clientData))`
with the attested key, matching app id, and a strictly-increasing counter.

---

## Running it

### Server (works anywhere with Node 18+)

```sh
cd server
npm install                       # pulls the one dependency: cbor

# Pin Apple's real trust root (required for /attest; download, don't hand-copy):
curl -o Apple_App_Attest_Root_CA.pem \
  https://www.apple.com/certificateauthority/Apple_App_Attest_Root_CA.pem

VANGUARD_TEAM_ID=ABCDE12345 \
VANGUARD_BUNDLE_ID=com.yourteam.vanguard-attest \
VANGUARD_ENV=development \
  npm start                       # listens on 127.0.0.1:8787
```

`GET /health` and `/challenge` work immediately. `/attest` needs the root CA
PEM present and the Team/bundle to match the client's signing identity.

**Hardware-free self-test** (no Mac, no Apple account):

```sh
npm test          # node selftest.js
```

This exercises `verifyAssertion` with a synthetic P-256 key standing in for
the Secure Enclave and asserts the security properties hold: a valid assertion
is accepted and advances the counter, while **replay, tampered clientData, a
wrong-app rpIdHash, and a foreign-key signature are all rejected**. (The
*attestation* path can't be self-tested — only a real SEP can mint an
attestation object — so it's verified on-device per below.)

### Client (requires a real Apple Developer Team + Apple Silicon/T2 Mac)

App Attest is **not** exercisable with ad-hoc signing — that restriction *is*
the security property. You need:

- An Apple Silicon (or T2) Mac, macOS 11+.
- A paid Apple Developer account; an App ID with **App Attest** capability.
- A provisioning profile for that App ID carrying the
  `com.apple.developer.devicecheck.appattest-environment` entitlement.

```sh
cd client
make \
  APP_BUNDLE_ID=com.yourteam.vanguard-attest \
  SIGN_IDENTITY="Apple Development: you@example.com (XXXXXXXXXX)" \
  PROFILE=/path/to/Vanguard_Attest.provisionprofile
VANGUARD_SERVER=http://127.0.0.1:8787 make run
```

Expected output (abridged):

```
[attest-client] — Step 1: Secure Enclave key custody —
[attest-client]   private key export refused by SEP (expected) ✓
[attest-client]   enclave-signed message verifies: ✓
[attest-client] — Step 2: App Attest key + Apple-certified attestation —
[attest-client]   server verdict: ATTESTED ✓ ...
[attest-client] — Step 3: per-request assertion (replay-proof) —
[attest-client]   server verdict: ASSERTION VALID ✓ counter=1
[attest-client] full trust chain demonstrated: SEP → Apple → server ✓
```

---

## Status & honesty notes

- **Server:** complete and tested. `npm test` runs a real-crypto self-test of
  the assertion verifier (valid accepted; replay/tamper/wrong-app/foreign-key
  rejected — all passing), and the live endpoints (`/health`, `/challenge`,
  one-time-challenge enforcement, error paths) are verified. The verification
  logic implements Apple's documented server-side checks with no WebAuthn
  black-box library, so each step is auditable. The *attestation* crypto path
  exercises once a real attestation object reaches it (on-device).
- **Client:** complete; **builds and runs only on macOS with a real Team
  identity** (DeviceCheck/CryptoKit/Security are macOS frameworks, and App
  Attest requires Apple-issued provisioning). It cannot be compiled or run in
  a Linux CI container — that's a property of the platform, not a gap in the
  code.
- The pinned **Apple App Attest Root CA** in `verify.js` should be checked
  against Apple's published certificate before any real use.
- This anchors trust at a point in time; it is **not** a continuous runtime
  heartbeat (see the Phase 3 threat model's non-goals).
