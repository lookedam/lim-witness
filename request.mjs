// lim-witness v4.1 ISSUER side (runs privately on LIM, never in lookedam). Builds the PUBLIC request issue body.
// 18 Nov 2026 (ChatGPT #6969066584, Codex #6969076667): Base64 is reversible, so a witness-side refusal is too late; the
// issuer must make a leak impossible BEFORE any POST:
//  - public identifiers come ONLY from opaqueId() (random 128-bit, kind-prefixed); caller strings are never copied out;
//  - the outgoing claim is serialised from an explicit field allowlist (no spread of caller objects);
//  - assertPublicSafe() re-parses the exact outgoing Base64 body and rejects anything outside the allowlist/shape,
//    and postRequest() calls it on the bytes it is about to send, before the network call.
// The private mapping (opaque id -> real decision / lineage) stays in the LIM journal, never in the request.
import { randomBytes } from "node:crypto";
import { seal } from "./seal.mjs";

export const OPAQUE = { decision: /^d-[a-f0-9]{32}$/, lineage: /^l-[a-f0-9]{32}$/, nonce: /^n-[a-f0-9]{32}$/ };
export const opaqueId = kind => {
  if (!OPAQUE[kind]) throw new Error("OPAQUE_KIND_UNKNOWN");
  return kind[0] + "-" + randomBytes(16).toString("hex");
};
const hex64 = s => typeof s === "string" && /^[a-f0-9]{64}$/.test(s);
const seq = v => Number.isSafeInteger(v) && v >= 0;
const b64 = s => typeof s === "string" && s.length > 0 && s.length <= 4096 && /^[A-Za-z0-9+/]+={0,2}$/.test(s);
const exactKeys = (o, keys) => o && typeof o === "object" && !Array.isArray(o) &&
  Object.keys(o).sort().join(",") === [...keys].sort().join(",");
const headOk = h => exactKeys(h, ["seq", "hash"]) && seq(h.seq) && hex64(h.hash);
export const CLAIM_KEYS = ["schema", "decision_id", "lineage", "epoch", "expected_world_sha256", "journal", "registry",
  "nonce", "effect_sealed"];
const SEAL_KEYS = ["alg", "epk", "iv", "ct", "tag"];

// Shape check shared by issuer (pre-POST) and witness (on receipt). Returns "" or a refusal code.
export function publicClaimProblem(c) {
  if (!exactKeys(c, CLAIM_KEYS)) return "CLAIM_FIELDS_NOT_ALLOWLISTED";
  if (c.schema !== "lim.gatec.shadow-claim.v1") return "CLAIM_MALFORMED";
  if (!OPAQUE.decision.test(c.decision_id) || !OPAQUE.lineage.test(c.lineage) || !OPAQUE.nonce.test(c.nonce))
    return "CLAIM_ID_NOT_OPAQUE";
  if (!seq(c.epoch) || !hex64(c.expected_world_sha256) || !headOk(c.journal) || !headOk(c.registry)) return "CLAIM_MALFORMED";
  const s = c.effect_sealed;
  if (!exactKeys(s, SEAL_KEYS) || s.alg !== "X25519-HKDF-SHA256-AES256GCM" || ![s.epk, s.iv, s.ct, s.tag].every(b64))
    return "EFFECT_NOT_SEALED";
  return "";
}

// ids: { decision_id, lineage, nonce } — each MUST already be an opaqueId() value (issuer stores the private mapping).
export function buildRequest({ ids, epoch, expected_world_sha256, journal, registry, effect }, observerPubPem) {
  const claim = { schema: "lim.gatec.shadow-claim.v1", decision_id: ids.decision_id, lineage: ids.lineage, epoch,
    expected_world_sha256, journal: { seq: journal.seq, hash: journal.hash }, registry: { seq: registry.seq, hash: registry.hash },
    nonce: ids.nonce };
  const effectOnly = { kind: effect.kind, repo: effect.repo, comment_id: String(effect.comment_id) };
  claim.effect_sealed = seal(effectOnly, claim, observerPubPem);
  const body = Buffer.from(JSON.stringify(claim), "utf8").toString("base64");
  assertPublicSafe(body);
  return body;
}

export function assertPublicSafe(body) {
  let c;
  try { c = JSON.parse(Buffer.from(body, "base64").toString("utf8")); } catch { throw new Error("PUBLIC_BODY_NOT_JSON"); }
  if (Buffer.from(JSON.stringify(c), "utf8").toString("base64") !== body) throw new Error("PUBLIC_BODY_NOT_CANONICAL");
  const p = publicClaimProblem(c);
  if (p) throw new Error("PUBLIC_BODY_REFUSED_" + p);
  return true;
}

// The only network path. `send` is injected (tests pass a recorder); it is never reached unless the exact bytes pass.
export async function postRequest(body, send) {
  assertPublicSafe(body);
  return send({ title: "LIM Gate C witness request", body });
}
