/*
 * server.js
 * ---------------------------------------------------------------------------
 * Phase 2 verification server. A deliberately tiny HTTP service (Node stdlib
 * only, plus verify.js) that demonstrates the server half of the trust chain:
 *
 *   GET  /challenge  -> issue a one-time random challenge (anti-replay)
 *   POST /attest     -> verify an Apple App Attest attestation, remember the
 *                       attested public key + counter for this keyId
 *   POST /assert     -> verify a per-request assertion against that key,
 *                       enforcing the monotonic counter
 *
 * State is in-memory (a Map) because this is a PoC. A real deployment would
 * persist keyId -> {publicKey, signCount} in a database and bind challenges
 * to sessions. Configure expected app identity via env:
 *
 *   VANGUARD_TEAM_ID   your 10-char Apple Team ID         (required for /attest)
 *   VANGUARD_BUNDLE_ID your app bundle id                 (required for /attest)
 *   VANGUARD_ENV       "development" (default) | "production"
 *   PORT               listen port                         (default 8787)
 * ---------------------------------------------------------------------------
 */

import http from "node:http";
import crypto from "node:crypto";
import { verifyAttestation, verifyAssertion } from "./verify.js";

const PORT = Number(process.env.PORT || 8787);
const EXPECTED = {
  teamId: process.env.VANGUARD_TEAM_ID || "",
  bundleId: process.env.VANGUARD_BUNDLE_ID || "",
  env: process.env.VANGUARD_ENV || "development",
};

// keyId(base64) -> { publicKey: KeyObject, signCount: number }
const attestedKeys = new Map();
// challenge(base64) -> issuedAt(ms). One-time use; expires after 5 minutes.
const liveChallenges = new Map();
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

/* --- helpers -------------------------------------------------------------- */

const json = (res, code, obj) => {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(body);
};

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      if (chunks.length === 0) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch (e) { reject(e); }
    });
    req.on("error", reject);
  });
}

function issueChallenge() {
  // 32 bytes of CSPRNG randomness; the client hashes this into clientDataHash.
  const challenge = crypto.randomBytes(32).toString("base64");
  liveChallenges.set(challenge, Date.now());
  return challenge;
}

function consumeChallenge(challengeB64) {
  const issued = liveChallenges.get(challengeB64);
  if (issued === undefined) return false;            // unknown / already used
  liveChallenges.delete(challengeB64);               // one-time use
  return Date.now() - issued <= CHALLENGE_TTL_MS;    // not expired
}

// Periodically drop expired challenges so the map can't grow unbounded.
setInterval(() => {
  const now = Date.now();
  for (const [c, t] of liveChallenges)
    if (now - t > CHALLENGE_TTL_MS) liveChallenges.delete(c);
}, CHALLENGE_TTL_MS).unref();

/* --- routes --------------------------------------------------------------- */

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/challenge") {
      return json(res, 200, { challenge: issueChallenge() });
    }

    if (req.method === "POST" && req.url === "/attest") {
      if (!EXPECTED.teamId || !EXPECTED.bundleId)
        return json(res, 500, {
          error: "server missing VANGUARD_TEAM_ID / VANGUARD_BUNDLE_ID",
        });
      const { keyId, challenge, attestation } = await readBody(req);
      if (!keyId || !challenge || !attestation)
        return json(res, 400, { error: "need keyId, challenge, attestation" });
      if (!consumeChallenge(challenge))
        return json(res, 400, { error: "unknown or expired challenge" });

      // The whole point: walk the Apple cert chain + nonce + identity checks.
      const result = verifyAttestation(attestation, challenge, {
        ...EXPECTED,
        keyId,
      });

      attestedKeys.set(result.keyId, {
        publicKey: result.publicKey,
        signCount: result.signCount,
      });
      return json(res, 200, {
        verified: true,
        details: `attested key ${result.keyId.slice(0, 12)}… for ${EXPECTED.teamId}.${EXPECTED.bundleId}`,
      });
    }

    if (req.method === "POST" && req.url === "/assert") {
      const { keyId, clientData, assertion } = await readBody(req);
      if (!keyId || !clientData || !assertion)
        return json(res, 400, { error: "need keyId, clientData, assertion" });
      const stored = attestedKeys.get(keyId);
      if (!stored)
        return json(res, 400, { error: "unknown keyId — attest first" });

      const { signCount, telemetryHash } = verifyAssertion(assertion, clientData, {
        ...stored,
        teamId: EXPECTED.teamId,
        bundleId: EXPECTED.bundleId,
      });

      stored.signCount = signCount; // persist the advanced counter
      return json(res, 200, {
        verified: true,
        counter: signCount,
        telemetryHash: telemetryHash ?? null,
      });
    }

    if (req.method === "GET" && req.url === "/health") {
      return json(res, 200, { ok: true, attestedKeys: attestedKeys.size });
    }

    return json(res, 404, { error: "not found" });
  } catch (err) {
    // Verification failures land here as 400s with the precise reason — handy
    // when demonstrating WHY a tampered attestation is rejected.
    return json(res, 400, { error: String(err.message || err) });
  }
});

server.listen(PORT, () => {
  console.log(`[attest-server] listening on http://127.0.0.1:${PORT}`);
  console.log(`[attest-server] expecting app: ${EXPECTED.teamId || "<unset>"}.${EXPECTED.bundleId || "<unset>"} (${EXPECTED.env})`);
  if (!EXPECTED.teamId || !EXPECTED.bundleId)
    console.log("[attest-server] WARNING: set VANGUARD_TEAM_ID and VANGUARD_BUNDLE_ID before /attest will work");
});
