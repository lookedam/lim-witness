// lim-witness v4.4 CANDIDATE (22 Nov 2026, ChatGPT #1738 c7071952135 gap 1; SOURCE ONLY, NOT INSTALLED ON LOOKEDAM).
// Pre-advance authentication gate for world claims on an owner-PINNED world lineage. It runs BEFORE any record number,
// observation or floor mutation; any failure => NOT_ADMITTED with NO write (highwater byte-for-byte unchanged).
// Binds: both heads (journal = Issuer journal, registry = Observer journal), decision id, nonce, task ref, nonce commitment,
// issuer + actor identities, the PRE / SEAL / DECISION signatures, and the two off-host ledger ACKs (PRE, SEAL) that this
// witness itself recorded, to the owner-pinned trust root producers.json `world_producers[<lineage>]`.
// Signatures: ECDSA P-256, IEEE-P1363, message = DOMAIN|key_id|epoch|digest (= issuer_native observer_sig_message, which the
// installed Issuer verifies with CNG).
import { createHash, createPublicKey, verify } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";

export const DOM = { CORE: "LIM-WITNESS-WORLD-CLAIM-V2", REC: "LIM-GATEC-ISSUER-RECORD-V1", ACTOR: "LIM-MERYL-ACTOR-V1" };
const canonical = v => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canonical).join(",") + "]"
  : "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
const sha256 = s => createHash("sha256").update(s, "utf8").digest("hex");
const hex = (s, n) => typeof s === "string" && new RegExp(`^[0-9a-f]{${n}}$`).test(s);
export const coreOf = c => { const { effect_sealed, effect, auth, ...rest } = c; const { core_sig, ...a } = auth; return { ...rest, auth: a }; };
export const coreDigest = c => sha256(DOM.CORE + "\n" + canonical(coreOf(c)));
const msg = (d, kid, ep, dig) => Buffer.from(`${d}|${kid}|${ep}|${dig}`, "ascii");
export function sigOk(k, domain, epoch, digest, sigHex) {
  if (!k || !hex(k.pub_x, 64) || !hex(k.pub_y, 64) || !hex(sigHex, 128) || !hex(digest, 64)) return false;
  try {
    const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: Buffer.from(k.pub_x, "hex").toString("base64url"),
      y: Buffer.from(k.pub_y, "hex").toString("base64url") }, format: "jwk" });
    return verify("sha256", msg(domain, k.key_id, epoch, digest), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(sigHex, "hex"));
  } catch { return false; }
}

// owner-installed: { schema:"lim.witness.producers.v1", producers:{...ledger...},
//   world_producers:{ <l-opaque lineage>:{ ledger_lineage, issuer:{key_id,epoch,pub_x,pub_y,identity},
//                                          actors:[{key_id,epoch,pub_x,pub_y,login}], status } } }
export function worldPin(producers, lineage) {
  const w = producers && producers.world_producers;
  return w && Object.prototype.hasOwnProperty.call(w, lineage) ? w[lineage] : null;
}

// the witness's OWN numbered ledger-head ACK record for (lineage, seq, head); returns witnessed_at_ms or null
export function ownAckMs(dir, ledgerLineage, ack) {
  let files = [];
  try { files = readdirSync(`${dir}/records`).filter(f => /^\d{8}\.json$/.test(f)); } catch { return null; }
  for (const f of files) {
    let r; try { r = JSON.parse(readFileSync(`${dir}/records/${f}`, "utf8")); } catch { continue; }
    const l = r && r.ledger_head;
    if (l && l.status === "ACCEPTED" && l.lineage === ledgerLineage && l.seq === ack.seq && l.head === ack.head
        && Number.isSafeInteger(l.witnessed_at_ms)) return l.witnessed_at_ms;
  }
  return null;
}

// -> { problem, pinned, preAckMs, sealAckMs, actor }  (problem "" = admitted)
export function worldAuthGate(c, producers, hw, dir) {
  const pin = worldPin(producers, c.lineage);
  if (!pin) return c.schema === "lim.gatec.shadow-claim.v2" ? { problem: "WORLD_LINEAGE_UNPINNED" } : { problem: "", pinned: false };
  if (pin.status !== "admitted") return { problem: "WORLD_PRODUCER_NOT_ADMITTED" };
  if (c.schema !== "lim.gatec.shadow-claim.v2") return { problem: "WORLD_CLAIM_UNSIGNED" };
  const a = c.auth, iss = pin.issuer;
  if (!iss || a.issuer_key_id !== iss.key_id || a.issuer_epoch !== iss.epoch) return { problem: "WORLD_ISSUER_NOT_PINNED" };
  const actor = (pin.actors || []).find(k => k.key_id === a.actor_key_id && k.epoch === a.actor_epoch);
  if (!actor) return { problem: "WORLD_ACTOR_NOT_PINNED" };
  if (!sigOk(iss, DOM.CORE, iss.epoch, coreDigest(c), a.core_sig)) return { problem: "WORLD_CLAIM_SIGNATURE_INVALID" };
  if (!sigOk(iss, DOM.REC, iss.epoch, a.pre_digest, a.pre_sig)) return { problem: "WORLD_PRE_SIGNATURE_INVALID" };
  if (!sigOk(iss, DOM.REC, iss.epoch, a.seal_digest, a.seal_sig)) return { problem: "WORLD_SEAL_SIGNATURE_INVALID" };
  if (!sigOk(actor, DOM.ACTOR, actor.epoch, a.decision_digest, a.decision_sig)) return { problem: "WORLD_DECISION_SIGNATURE_INVALID" };
  if (hw && hw.closed) return { problem: "LINEAGE_CLOSED" };
  if (hw && Array.isArray(hw.decisions) && hw.decisions.includes(a.decision_digest)) return { problem: "WORLD_DECISION_REPLAY" };
  if (hw && Array.isArray(hw.nonce_commits) && hw.nonce_commits.includes(a.nonce_commit)) return { problem: "WORLD_NONCE_REPLAY" };
  // temporal anchors this witness recorded itself (not issuer-reported times)
  if (!(a.pre_ack.seq < a.seal_ack.seq)) return { problem: "WORLD_ACK_ORDER" };
  const preAckMs = ownAckMs(dir, pin.ledger_lineage, a.pre_ack), sealAckMs = ownAckMs(dir, pin.ledger_lineage, a.seal_ack);
  if (preAckMs === null) return { problem: "WORLD_PRE_ACK_NOT_WITNESSED" };
  if (sealAckMs === null) return { problem: "WORLD_SEAL_ACK_NOT_WITNESSED" };
  if (!(preAckMs < sealAckMs)) return { problem: "WORLD_ACK_ORDER" };
  return { problem: "", pinned: true, preAckMs, sealAckMs, actor };
}
