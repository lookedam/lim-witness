// lim-witness v4.3 (SOURCE ONLY, NOT INSTALLED): `committer-ledger-head` request type (ChatGPT #1738 c7025818639, row 14).
// Runs ONLY in lookedam/lim-witness Actions, beside the unchanged v4.2 shadow-claim path. It is an OFF-HOST, append-only,
// forward-only acknowledgement of a LIM Committer ledger head:
//   - the request is SIGNED by an owner-pinned producer key (producers.json, installed only by the repo owner); the issue
//     author/transport is never trusted (an unauthenticated comment or issue can never advance anything);
//   - it binds the full canonical lineage id, monotonic seq, exact head hash, the PRIOR acknowledged seq+head, the producer's
//     key fingerprint + identity, a request id (replay nonce) and the producer's UTC time; the witness adds its own UTC;
//   - it refuses rewind, skipped chain, same-seq conflict, fork, replay, request-id reuse, stale/future requests, a closed or
//     unpinned lineage and an unverified or foreign producer;
//   - floors live under highwater.json `ledger_heads` (a separate namespace from `lineages`: no collision with the opaque
//     shadow-claim lineages or the closed historical selftest lineage, and the v4.2 read-side verifiers are unaffected);
//   - every request (accepted or refused) gets a numbered record on the SAME anchor_version sequence, GitHub-OIDC-bound by
//     record hash, exactly like v4.2. Only ACCEPTED advances a floor. Output is evidence only: never Gate C/first30 credit.
import { createHash, createPublicKey, verify } from "node:crypto";

export const LEDGER_SCHEMA = "lim.witness.committer-ledger-head.v1";
export const SIG_DOMAIN = "lim-witness/committer-ledger-head/v1\n";
export const REQUEST_KEYS = ["schema", "lineage", "seq", "head", "prior", "producer", "request_id", "produced_at_ms", "signature"];
export const PRODUCER_KEYS = ["key_fingerprint", "identity"];
export const MAX_SKEW_MS = 30 * 60 * 1000;          // producer clock vs witness clock (Actions queue delay included)
export const canonical = v => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canonical).join(",") + "]"
  : "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
const sha256 = b => createHash("sha256").update(b).digest("hex");
const hex64 = s => typeof s === "string" && /^[a-f0-9]{64}$/.test(s);
const seqOk = v => Number.isSafeInteger(v) && v >= 0;
const exactKeys = (o, keys) => o && typeof o === "object" && !Array.isArray(o) && Object.keys(o).sort().join(",") === [...keys].sort().join(",");
export const LINEAGE_RE = /^lim-[a-z0-9]+(?:-[a-z0-9]+)*-v[0-9]+$/;          // full canonical id, e.g. lim-meryl-ledger-v1
export const REQUEST_ID_RE = /^n-[a-f0-9]{32}$/;
export const IDENTITY_RE = /^S-1-5-(?:80(?:-[0-9]{1,10}){5}|21(?:-[0-9]{1,10}){4})$/;   // a Windows SID: service (80) or account (21); the exact value is owner-pinned

// Exact bytes the producer signs (and the witness verifies): domain || canonical(request without `signature`).
export const signingBytes = req => { const { signature, ...rest } = req; return Buffer.from(SIG_DOMAIN + canonical(rest), "utf8"); };
export const requestSha256 = req => sha256(Buffer.from(canonical(req), "utf8"));
export const spkiFingerprint = spkiB64 => sha256(Buffer.from(spkiB64, "base64"));

export function shapeProblem(r) {
  if (!exactKeys(r, REQUEST_KEYS)) return "LEDGER_FIELDS_NOT_ALLOWLISTED";
  if (r.schema !== LEDGER_SCHEMA) return "LEDGER_SCHEMA";
  if (typeof r.lineage !== "string" || r.lineage.length > 64 || !LINEAGE_RE.test(r.lineage)) return "LEDGER_LINEAGE_NOT_CANONICAL";
  if (!seqOk(r.seq) || !hex64(r.head)) return "LEDGER_HEAD_MALFORMED";
  if (r.prior !== null && !(exactKeys(r.prior, ["seq", "head"]) && seqOk(r.prior.seq) && hex64(r.prior.head))) return "LEDGER_PRIOR_MALFORMED";
  if (!exactKeys(r.producer, PRODUCER_KEYS) || !hex64(r.producer.key_fingerprint) || !IDENTITY_RE.test(r.producer.identity)) return "LEDGER_PRODUCER_MALFORMED";
  if (!REQUEST_ID_RE.test(r.request_id)) return "LEDGER_REQUEST_ID_MALFORMED";
  if (!Number.isSafeInteger(r.produced_at_ms) || r.produced_at_ms <= 0) return "LEDGER_TIME_MALFORMED";
  if (typeof r.signature !== "string" || !/^[A-Za-z0-9+/]{86}==$/.test(r.signature)) return "LEDGER_SIGNATURE_MALFORMED";   // 64-byte P1363
  return "";
}

// producers.json (owner-installed): { schema, producers: { <lineage>: { status, spki_b64, key_fingerprint, identity } } }
export function producerProblem(producers, r) {
  const p = producers && producers.producers && Object.prototype.hasOwnProperty.call(producers.producers, r.lineage) ? producers.producers[r.lineage] : null;
  if (!p) return "LEDGER_PRODUCER_UNPINNED";
  if (p.status !== "provisional" && p.status !== "active") return "LEDGER_PRODUCER_NOT_ADMITTED";
  if (!hex64(p.key_fingerprint) || typeof p.spki_b64 !== "string" || spkiFingerprint(p.spki_b64) !== p.key_fingerprint) return "LEDGER_PRODUCER_PIN_INVALID";
  if (r.producer.key_fingerprint !== p.key_fingerprint) return "LEDGER_PRODUCER_FOREIGN_KEY";
  if (r.producer.identity !== p.identity) return "LEDGER_PRODUCER_FOREIGN_IDENTITY";
  let key;
  try { key = createPublicKey({ key: Buffer.from(p.spki_b64, "base64"), format: "der", type: "spki" }); } catch { return "LEDGER_PRODUCER_PIN_INVALID"; }
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails.namedCurve !== "prime256v1") return "LEDGER_PRODUCER_PIN_INVALID";
  let ok = false;
  try { ok = verify("sha256", signingBytes(r), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(r.signature, "base64")); } catch { ok = false; }
  return ok ? "" : "LEDGER_SIGNATURE_INVALID";
}

// fl = this lineage's floor in highwater.ledger_heads (or undefined). Order of checks is part of the contract.
export function chainProblem(fl, r) {
  if (fl && fl.closed) return "LEDGER_LINEAGE_CLOSED";
  if (fl && Array.isArray(fl.request_ids) && fl.request_ids.includes(r.request_id)) return "LEDGER_REQUEST_ID_REPLAY";
  if (!fl) return r.prior === null && r.seq === 0 ? "" : "LEDGER_GENESIS_REQUIRED";            // first ack = seq 0, no prior
  if (r.prior === null) return "LEDGER_GENESIS_ALREADY_WITNESSED";
  if (r.seq < fl.seq) return "LEDGER_REWIND";
  if (r.seq === fl.seq) return r.head === fl.head ? "LEDGER_REPLAY_NOT_ADVANCED" : "LEDGER_SAME_SEQ_CONFLICT";
  if (r.prior.seq !== fl.seq) return "LEDGER_CHAIN_SKIPPED";
  if (r.prior.head !== fl.head) return "LEDGER_FORK";
  if (r.seq <= r.prior.seq) return "LEDGER_SEQ_NOT_MONOTONIC";
  return "";
}

// Pure decision. all = parsed highwater.json (mutated only on ACCEPTED); returns { status, reason, anchorBody, request }.
export function decideLedger(all, producers, body, nowMs, version, run) {
  let r = null, reason = "";
  try { r = JSON.parse(Buffer.from(body || "", "base64").toString("utf8")); } catch { reason = "LEDGER_NOT_JSON"; }
  if (!reason && Buffer.from(JSON.stringify(r), "utf8").toString("base64") !== body) reason = "LEDGER_BODY_NOT_CANONICAL";
  if (!reason) reason = shapeProblem(r);
  if (!reason) reason = producerProblem(producers, r);
  if (!reason && Math.abs(nowMs - r.produced_at_ms) > MAX_SKEW_MS) reason = "LEDGER_REQUEST_STALE_OR_FUTURE";
  const heads = (all.ledger_heads && typeof all.ledger_heads === "object") ? all.ledger_heads : {};
  const fl = r && typeof r.lineage === "string" && Object.prototype.hasOwnProperty.call(heads, r.lineage) ? heads[r.lineage] : undefined;
  if (!reason) reason = chainProblem(fl, r);
  const status = reason ? "REFUSED" : "ACCEPTED";
  const okShape = r && !shapeProblem(r);
  const anchorBody = { schema: "lim.witness.ledger-head-ack.v1", anchor_version: version, status, reason,
    lineage: okShape ? r.lineage : null, seq: okShape ? r.seq : null, head: okShape ? r.head : null, prior: okShape ? r.prior : null,
    producer: okShape ? r.producer : null, request_id: okShape ? r.request_id : null, produced_at_ms: okShape ? r.produced_at_ms : null,
    request_sha256: okShape ? requestSha256(r) : null, witnessed_at_ms: nowMs,
    floor_before: fl ? { seq: fl.seq, head: fl.head, anchor_version: fl.anchor_version } : null, run };
  if (status === "ACCEPTED") {
    all.ledger_heads = heads;
    heads[r.lineage] = { seq: r.seq, head: r.head, anchor_version: version, request_ids: [...((fl && fl.request_ids) || []), r.request_id] };
  }
  return { status, reason, anchorBody, request: r };
}

export const isLedgerBody = body => {
  try { const r = JSON.parse(Buffer.from(body || "", "base64").toString("utf8")); return !!r && r.schema === LEDGER_SCHEMA; } catch { return false; }
};
