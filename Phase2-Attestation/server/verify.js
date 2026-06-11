/*
 * verify.js
 * ---------------------------------------------------------------------------
 * The cryptographic core of Phase 2: verifying an Apple App Attest
 * *attestation* and the cheaper follow-up *assertions*, with every step
 * Apple's spec mandates spelled out and commented.
 *
 * Reference: Apple, "Validating Apps That Connect to Your Server"
 * (App Attest). We implement the server-side checks 1..N from that doc.
 *
 * Design note: this uses Node's built-in `crypto` for X.509/ECDSA and the
 * `cbor` package only to decode the attestation/auth-data blobs. We do NOT
 * pull in a kitchen-sink WebAuthn library, so each check is visible and
 * auditable — appropriate for something pitched to a security team.
 * ---------------------------------------------------------------------------
 */

import crypto from "node:crypto";
import cbor from "cbor";

/*
 * Apple App Attest Root CA — the trust anchor every attestation chains to.
 * Source: https://www.apple.com/certificateauthority/  (Apple App Attest Root CA).
 * Pin it here rather than trusting the system store: we want to validate
 * against THIS specific root and nothing else. Operators should verify this
 * PEM against Apple's published certificate before relying on it.
 */
export const APPLE_APP_ATTEST_ROOT_CA = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEA3Qal/F1Ofqdz4Tbz+xPYzaA9Ovs8eD/95LU
oj0OQjOLP6e/vF7yL5oON9pdfQ5G
-----END CERTIFICATE-----`;

// OID for the Apple-defined certificate extension carrying the nonce.
const APPLE_NONCE_OID = "1.2.840.113635.100.8.2";

/* Small DER helpers ------------------------------------------------------- */

// SHA-256 convenience.
const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest();

/*
 * Parse the WebAuthn-style authenticator data that App Attest reuses.
 * Layout (App Attest variant):
 *   rpIdHash            32 bytes  (== SHA-256 of "TeamID.bundleID")
 *   flags                1 byte
 *   signCount            4 bytes  (the replay counter; 0 at attestation)
 *   attestedCredData   variable  (present only in the attestation)
 *     aaguid            16 bytes  ("appattestdevelop" or "appattest" + 0s)
 *     credIdLen          2 bytes
 *     credId         credIdLen    (== the keyId)
 *     credPublicKey  variable     (COSE-encoded P-256 public key)
 */
function parseAuthData(authData) {
  let o = 0;
  const rpIdHash = authData.subarray(o, (o += 32));
  const flags = authData[o++];
  const signCount = authData.readUInt32BE(o); o += 4;

  const out = { rpIdHash, flags, signCount };
  // Bit 6 (0x40) = attested credential data present.
  if (flags & 0x40) {
    const aaguid = authData.subarray(o, (o += 16));
    const credIdLen = authData.readUInt16BE(o); o += 2;
    const credId = authData.subarray(o, (o += credIdLen));
    const credPublicKey = authData.subarray(o); // remainder = COSE key
    Object.assign(out, { aaguid, credId, credPublicKey });
  }
  return out;
}

/* Convert a COSE_Key (EC2 P-256) into a Node KeyObject for verification. */
function coseToPublicKey(coseBuf) {
  const m = cbor.decodeFirstSync(coseBuf);
  // COSE labels: -2 = x, -3 = y for EC2 keys.
  const x = m.get(-2);
  const y = m.get(-3);
  // Build an uncompressed EC point (0x04 || X || Y) and wrap as JWK.
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: x.toString("base64url"),
    y: y.toString("base64url"),
  };
  return crypto.createPublicKey({ key: jwk, format: "jwk" });
}

/*
 * verifyAttestation
 * -------------------------------------------------------------------------
 * Validate a one-time attestation object. Returns { credPublicKey (PEM-ish
 * KeyObject), signCount, receipt } on success; throws on any failed check.
 *
 *   attestationB64 : base64 of the CBOR attestation from attestKey()
 *   challengeB64   : the base64 challenge WE issued for this attestation
 *   expected       : { teamId, bundleId, env: "development"|"production",
 *                      keyId }
 */
export function verifyAttestation(attestationB64, challengeB64, expected) {
  const attestation = cbor.decodeFirstSync(Buffer.from(attestationB64, "base64"));

  // Step 0: shape. fmt MUST be "apple-appattest".
  if (attestation.fmt !== "apple-appattest")
    throw new Error(`unexpected attestation fmt: ${attestation.fmt}`);
  const { x5c, receipt } = attestation.attStmt;
  const authData = attestation.authData;

  // --- Step 1: build the certificate chain and verify it to Apple's root ---
  // x5c = [ leaf (credCert), intermediate ]. We verify leaf<-intermediate<-root.
  const leaf = new crypto.X509Certificate(x5c[0]);
  const intermediate = new crypto.X509Certificate(x5c[1]);
  const root = new crypto.X509Certificate(APPLE_APP_ATTEST_ROOT_CA);

  if (!leaf.verify(intermediate.publicKey))
    throw new Error("leaf cert not signed by intermediate");
  if (!intermediate.verify(root.publicKey))
    throw new Error("intermediate cert not signed by Apple App Attest root");
  // (Apple's leaf/intermediate carry no useful validity-window surprises, but
  //  a production server should also check notBefore/notAfter here.)

  // --- Step 2: recompute and check the nonce -------------------------------
  // nonce = SHA-256( authData || SHA-256(clientDataHash) ).
  // Our client used clientDataHash = SHA-256(challenge bytes), so:
  const clientDataHash = sha256(Buffer.from(challengeB64, "base64"));
  const expectedNonce = sha256(Buffer.concat([authData, clientDataHash]));

  // Apple embeds SHA-256(nonce) inside a cert extension (a DER-wrapped
  // OCTET STRING inside a SEQUENCE) on the leaf. Extract and compare.
  const ext = leaf.raw; // we search the DER for the OID's payload below
  const embeddedNonceHash = extractAppleNonce(leaf);
  if (!embeddedNonceHash)
    throw new Error("apple nonce extension not found on leaf cert");
  if (!crypto.timingSafeEqual(embeddedNonceHash, sha256(expectedNonce)))
    throw new Error("nonce mismatch — attestation not bound to our challenge (replay?)");
  void ext;

  // --- Step 3: keyId must equal SHA-256(leaf public key) -------------------
  // The credId in authData and the caller-supplied keyId must both equal the
  // SHA-256 of the leaf cert's public key (App Attest's key identity rule).
  const leafPubDer = leaf.publicKey.export({ type: "spki", format: "der" });
  // App Attest hashes the raw EC point, not SPKI; pull the 65-byte point out
  // of the SPKI DER (last 65 bytes for uncompressed P-256).
  const ecPoint = leafPubDer.subarray(leafPubDer.length - 65);
  const keyIdFromCert = sha256(ecPoint);
  const parsed = parseAuthData(authData);
  if (!crypto.timingSafeEqual(parsed.credId, keyIdFromCert))
    throw new Error("credId != SHA256(leaf public key)");
  if (expected.keyId &&
      !crypto.timingSafeEqual(Buffer.from(expected.keyId, "base64"), keyIdFromCert))
    throw new Error("client keyId does not match attested key");

  // --- Step 4: rpIdHash must equal SHA-256("TeamID.bundleID") --------------
  const appId = `${expected.teamId}.${expected.bundleId}`;
  if (!crypto.timingSafeEqual(parsed.rpIdHash, sha256(Buffer.from(appId))))
    throw new Error(`rpIdHash != SHA256("${appId}") — wrong app/team`);

  // --- Step 5: aaguid must match the environment ---------------------------
  // "appattestdevelop" for development; "appattest\0\0\0\0\0\0\0" for prod.
  const aaguidStr = parsed.aaguid.toString("latin1").replace(/\0+$/, "");
  const wantAaguid = expected.env === "production" ? "appattest" : "appattestdevelop";
  if (aaguidStr !== wantAaguid)
    throw new Error(`aaguid "${aaguidStr}" != expected "${wantAaguid}" for env ${expected.env}`);

  // --- Step 6: signCount starts at 0 ---------------------------------------
  if (parsed.signCount !== 0)
    throw new Error(`attestation signCount must be 0, got ${parsed.signCount}`);

  // Success: hand back the public key (for future assertions), the starting
  // counter, and the receipt (Apple's signed proof, usable to query fraud
  // metrics / risk later — out of scope for the PoC).
  return {
    publicKey: leaf.publicKey,
    signCount: parsed.signCount,
    keyId: keyIdFromCert.toString("base64"),
    receipt,
  };
}

/*
 * verifyAssertion
 * -------------------------------------------------------------------------
 * Validate a per-request assertion against the public key we stored at
 * attestation time. Enforces the monotonic counter to defeat replay.
 *
 *   assertionB64  : base64 from generateAssertion()
 *   clientDataB64 : the exact clientData bytes the client signed
 *   stored        : { publicKey (KeyObject), signCount (last seen),
 *                     teamId, bundleId }
 * Returns { signCount } (the new counter) or throws.
 */
export function verifyAssertion(assertionB64, clientDataB64, stored) {
  const assertion = cbor.decodeFirstSync(Buffer.from(assertionB64, "base64"));
  const { signature, authenticatorData } = assertion;
  const clientData = Buffer.from(clientDataB64, "base64");

  // Step 1: nonce = SHA-256( authenticatorData || SHA-256(clientData) ).
  const clientDataHash = sha256(clientData);
  const nonce = sha256(Buffer.concat([authenticatorData, clientDataHash]));

  // Step 2: verify the SEP's ECDSA signature over that nonce with the
  // attested public key.
  const ok = crypto.verify(
    "sha256",
    nonce,
    { key: stored.publicKey, dsaEncoding: "der" },
    signature,
  );
  if (!ok) throw new Error("assertion signature invalid");

  // Step 3: rpIdHash in the assertion's authData must still match the app.
  const parsed = parseAuthData(authenticatorData);
  const appId = `${stored.teamId}.${stored.bundleId}`;
  if (!crypto.timingSafeEqual(parsed.rpIdHash, sha256(Buffer.from(appId))))
    throw new Error("assertion rpIdHash mismatch");

  // Step 4: counter MUST be strictly greater than the last value we stored.
  // This is what makes captured assertions un-replayable.
  if (parsed.signCount <= stored.signCount)
    throw new Error(
      `replay/counter regression: got ${parsed.signCount}, have ${stored.signCount}`,
    );

  return { signCount: parsed.signCount };
}

/*
 * Extract Apple's nonce hash from the leaf certificate's custom extension
 * (OID 1.2.840.113635.100.8.2). Node's X509Certificate doesn't expose
 * arbitrary extensions, so we locate the OID in the DER and read the
 * 32-byte OCTET STRING that follows the wrapping SEQUENCE. This is a
 * deliberately small, dependency-free DER scan.
 */
function extractAppleNonce(leafCert) {
  const der = leafCert.raw;
  // DER encoding of the OID 1.2.840.113635.100.8.2:
  const oidBytes = Buffer.from([
    0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02,
  ]);
  const idx = der.indexOf(oidBytes);
  if (idx < 0) return null;
  // After the OID comes an OCTET STRING (0x04) wrapping the extension value,
  // which itself is: SEQUENCE { [1] { OCTET STRING <32-byte nonce hash> } }.
  // Scan forward for the first 32-byte OCTET STRING (0x04 0x20 ...).
  for (let i = idx; i < der.length - 34; i++) {
    if (der[i] === 0x04 && der[i + 1] === 0x20) {
      return der.subarray(i + 2, i + 2 + 32);
    }
  }
  return null;
}
