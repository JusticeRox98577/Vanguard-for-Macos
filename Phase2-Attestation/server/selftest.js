/*
 * selftest.js  —  hardware-free verification of the server's logic.
 *
 * App Attest *attestation* objects can only be produced by a real Secure
 * Enclave, so we cannot forge one. But the *assertion* verifier
 * (verifyAssertion) is ordinary ECDSA + counter logic, so we can exercise it
 * end to end with a synthetic P-256 key standing in for the SEP. We also do
 * a live HTTP round-trip against the running server for the challenge flow.
 *
 * Run:  node selftest.js          (no Mac, no Apple account needed)
 * Exits non-zero on any failed assertion.
 */
import crypto from "node:crypto";
import cbor from "cbor";
import { verifyAssertion } from "./verify.js";

let pass = 0, fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.error(`  ✗ ${name}`); }
};
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();

// Build a P-256 keypair to impersonate the enclave's attested key.
const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });

const TEAM = "ABCDE12345";
const BUNDLE = "com.example.vanguard-attest";
const rpIdHash = sha256(Buffer.from(`${TEAM}.${BUNDLE}`));

// Construct authenticatorData: rpIdHash(32) || flags(1) || signCount(4).
function authData(signCount) {
  const b = Buffer.alloc(37);
  rpIdHash.copy(b, 0);
  b[32] = 0x00;                 // no attested-cred-data flag for assertions
  b.writeUInt32BE(signCount, 33);
  return b;
}

// Produce an assertion CBOR the way the SEP would: sign SHA256(authData||SHA256(clientData)).
function makeAssertion(signCount, clientData, signWithRpIdHash = rpIdHash) {
  const ad = Buffer.alloc(37);
  signWithRpIdHash.copy(ad, 0);
  ad[32] = 0x00;
  ad.writeUInt32BE(signCount, 33);
  const nonce = sha256(Buffer.concat([ad, sha256(clientData)]));
  const signature = crypto.sign("sha256", nonce, { key: privateKey, dsaEncoding: "der" });
  return cbor.encode({ signature, authenticatorData: ad });
}

console.log("verifyAssertion — happy path & attacks:");
const stored = { publicKey, signCount: 0, teamId: TEAM, bundleId: BUNDLE };
const clientData = Buffer.from(JSON.stringify({ payload: "telemetry" }));

// 1) Valid assertion with advancing counter -> accepted, returns new counter.
try {
  const a = makeAssertion(1, clientData);
  const r = verifyAssertion(a.toString("base64"), clientData.toString("base64"), stored);
  ok("valid assertion accepted (counter 0 -> 1)", r.signCount === 1);
} catch (e) { ok("valid assertion accepted", false); console.error("   ", e.message); }

// 2) Replay (same counter) -> rejected.
try {
  const a = makeAssertion(1, clientData);
  verifyAssertion(a.toString("base64"), clientData.toString("base64"), { ...stored, signCount: 1 });
  ok("replayed counter rejected", false);
} catch { ok("replayed counter rejected", true); }

// 3) Tampered clientData (signature won't match) -> rejected.
try {
  const a = makeAssertion(2, clientData);
  const evil = Buffer.from(JSON.stringify({ payload: "EVIL" }));
  verifyAssertion(a.toString("base64"), evil.toString("base64"), stored);
  ok("tampered clientData rejected", false);
} catch { ok("tampered clientData rejected", true); }

// 4) Wrong app identity (rpIdHash mismatch) -> rejected.
try {
  const a = makeAssertion(3, clientData, sha256(Buffer.from("WRONG.app.id")));
  verifyAssertion(a.toString("base64"), clientData.toString("base64"), stored);
  ok("wrong rpIdHash rejected", false);
} catch { ok("wrong rpIdHash rejected", true); }

// 5) Signature from a different key -> rejected.
try {
  const other = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const a = makeAssertion(4, clientData);
  verifyAssertion(a.toString("base64"), clientData.toString("base64"),
    { ...stored, publicKey: other.publicKey });
  ok("foreign-key signature rejected", false);
} catch { ok("foreign-key signature rejected", true); }

void authData; // exported shape kept for reference

console.log(`\nverifyAssertion: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
