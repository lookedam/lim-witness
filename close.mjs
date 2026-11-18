// lim-witness v4.2 GOVERNED LINEAGE CLOSE (18 Nov 2026, ChatGPT #6979934937 G3 option (a)).
// Runs ONLY on GitHub Actions in lookedam/lim-witness, ONLY from a workflow_dispatch that the repository OWNER triggered
// (witness.yml `close` job guard; OIDC then attests event_name=workflow_dispatch and actor=owner). It never reads a
// provider, never accepts issuer data, and takes exactly one input: the lineage to close.
//
// What it does, all from the files already in this repo (nothing caller-supplied except the lineage name):
//  1. binds the exact pre-close highwater.json bytes (SHA-256) and EVERY existing record of that lineage (number,
//     raw-file SHA-256, canonical record SHA-256, status, journal/registry heads) — old records are never changed;
//  2. recomputes the lineage's TRUE floor = the last WORLD_MATCH record, and compares it with the floor highwater.json
//     asserts; any difference is disclosed as `poisoned:true` with the record(s) that produced the asserted floor;
//  3. writes ONE new monotonically numbered signed record (status LINEAGE_CLOSED) that links the superseded and the
//     corrected floor and is a permanent tombstone;
//  4. marks the lineage closed in highwater.json, keeping the superseded floor visible next to the corrected one.
// witness.mjs then refuses every later claim on a closed lineage (LINEAGE_CLOSED); nothing can reopen it.
// The record is evidence only: it grants no Gate C pass and no first30 credit.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve as resolvePath } from "node:path";

const canonical = v => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canonical).join(",") + "]"
  : "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
const sha256 = b => createHash("sha256").update(b).digest("hex");
// v4.2 rev 2 (ChatGPT #6981129195): NOT a generic retirement capability. This close can only ever repair the ONE known
// historical self-test lineage, and only if its records are byte-for-byte the known ones and the poison is exactly the
// known one. Anything else (including the valid new lineage) is refused with zero writes. There are no workflow inputs.
export const PINNED = Object.freeze({
  lineage: "lim-witness-selftest-20261117",
  reason: "SELFTEST_LINEAGE_POISONED_FLOOR",
  records: Object.freeze([   // anchor_version, status, raw file sha256, canonical {world,anchor} sha256 (public main@b2d5ea41)
    [1, "WORLD_MATCH", "3b3ef9c7447de1f4fa558d7c6ec5b06d8f1df19304dad088820f70afab3e884e", "0adadb2bc95e21af1822bed678ec14aa0aca207671615b8466cd355c8eb6b151"],
    [2, "REFUSED", "f58d0746a9a1e5dad0bf15db64db71bd781974523a36bd17b833a09c8eeb2125", "0e585a7bdd449329f4b498a7448a2cebde4d6764a5625ff54750fca7cc7975fe"],
    [3, "FALSE_WORLD_POSTCONDITION", "3ace9d619b7d061458c89e048991f1818654114872df88c42116b0ae8a6fafb2", "31d00ab01427532a1120032f141972354c287727b4a123c0888e867135f17195"],
    [4, "REFUSED", "f3a86e8aa4264260d49659829afbd5670454492f6dcb3d4d39e1a1a7e03ec72a", "e5620bc9ed7e0608d5ef5a63c4c1678a0f12039d448d797f6215c2dddd47706a"]]),
  superseded: Object.freeze({ anchor_version: 3, seq: 2, hash: "325fbd6bd907a9b24c8a0032bb08056de00fe3a649ada91ec4582f9c7e6ffa3f" }),
  corrected: Object.freeze({ anchor_version: 1, seq: 1, hash: "fdb6e26a6c7926961ed796b1ad2650dda8bd2fa07d64956a8c1888acc99aae74" }),
});
export const CLOSE_REASONS = new Set([PINNED.reason]);
const LINEAGE_NAME = /^[A-Za-z0-9._-]{1,64}$/;
const head = h => h && { seq: h.seq, hash: h.hash };

async function oidc(audience, env) {
  const u = env.ACTIONS_ID_TOKEN_REQUEST_URL, t = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!u || !t) throw new Error("OIDC_UNAVAILABLE");
  const r = await fetch(`${u}&audience=${encodeURIComponent(audience)}`, { headers: { Authorization: `Bearer ${t}` } });
  if (!r.ok) throw new Error("OIDC_FAILED_" + r.status);
  return (await r.json()).value;
}

// Pure planning step (no writes): returns { problem } or { record, highwater }. Exported for tests.
export function planClose({ lineage, reason, hwBytes, recordFiles, env }) {
  if (env.GITHUB_EVENT_NAME !== "workflow_dispatch") return { problem: "CLOSE_NOT_DISPATCH" };
  if (!env.GITHUB_ACTOR || env.GITHUB_ACTOR !== env.GITHUB_REPOSITORY_OWNER ||
      env.GITHUB_TRIGGERING_ACTOR !== env.GITHUB_REPOSITORY_OWNER) return { problem: "CLOSE_NOT_OWNER" };
  if (typeof lineage !== "string" || !LINEAGE_NAME.test(lineage)) return { problem: "CLOSE_LINEAGE_MALFORMED" };
  if (lineage !== PINNED.lineage) return { problem: "CLOSE_LINEAGE_NOT_PINNED" };
  if (!CLOSE_REASONS.has(reason)) return { problem: "CLOSE_REASON_NOT_ALLOWED" };
  if (!hwBytes) return { problem: "CLOSE_NO_HIGHWATER" };
  let all;
  try { all = JSON.parse(hwBytes.toString("utf8")); } catch { return { problem: "CLOSE_HIGHWATER_NOT_JSON" }; }
  if (!all || !Number.isSafeInteger(all.anchor_version) || !all.lineages || typeof all.lineages !== "object")
    return { problem: "CLOSE_HIGHWATER_MALFORMED" };
  if (!Object.prototype.hasOwnProperty.call(all.lineages, lineage)) return { problem: "CLOSE_LINEAGE_UNKNOWN" };
  const asserted = all.lineages[lineage];
  if (asserted && asserted.closed) return { problem: "CLOSE_ALREADY_CLOSED" };

  // every record file must parse and be numbered 1..anchor_version with no gap: the close binds the WHOLE history
  const names = Object.keys(recordFiles).sort();
  if (names.length !== all.anchor_version) return { problem: "CLOSE_RECORD_COUNT_MISMATCH" };
  const mine = [];
  for (let i = 0; i < names.length; i++) {
    if (names[i] !== String(i + 1).padStart(8, "0") + ".json") return { problem: "CLOSE_RECORD_NUMBERING_GAP" };
    let r;
    try { r = JSON.parse(recordFiles[names[i]].toString("utf8")); } catch { return { problem: "CLOSE_RECORD_NOT_JSON" }; }
    if (!r || !r.anchor || r.anchor.anchor_version !== i + 1) return { problem: "CLOSE_RECORD_VERSION_MISMATCH" };
    if (r.anchor.lineage !== lineage) continue;
    mine.push({ anchor_version: i + 1, file_sha256: sha256(recordFiles[names[i]]),
      record_sha256: sha256(canonical({ world: r.world, anchor: r.anchor })), status: r.anchor.status,
      epoch: r.anchor.epoch, journal: head(r.anchor.journal), registry: head(r.anchor.registry) });
  }
  if (!mine.length) return { problem: "CLOSE_LINEAGE_HAS_NO_RECORDS" };
  const matches = mine.filter(m => m.status === "WORLD_MATCH");
  const last = matches[matches.length - 1] || null;
  const corrected = last && { epoch: last.epoch, journal: last.journal, registry: last.registry, anchor_version: last.anchor_version };
  const superseded = asserted && { epoch: asserted.epoch, journal: head(asserted.journal), registry: head(asserted.registry),
    anchor_version: asserted.anchor_version };
  const poisoned = canonical(superseded) !== canonical(corrected);
  const poisonSources = mine.filter(m => superseded && m.anchor_version === superseded.anchor_version)
    .map(m => ({ anchor_version: m.anchor_version, status: m.status, record_sha256: m.record_sha256 }));
  // pinned-history predicates: the lineage's records, the poison and the correction must be EXACTLY the known ones
  const got = mine.map(m => [m.anchor_version, m.status, m.file_sha256, m.record_sha256]);
  if (JSON.stringify(got) !== JSON.stringify(PINNED.records)) return { problem: "CLOSE_HISTORY_NOT_PINNED" };
  const S = PINNED.superseded, C = PINNED.corrected;
  if (!poisoned || !superseded || superseded.anchor_version !== S.anchor_version || !superseded.journal ||
      superseded.journal.seq !== S.seq || superseded.journal.hash !== S.hash) return { problem: "CLOSE_POISON_NOT_PINNED" };
  if (!corrected || corrected.anchor_version !== C.anchor_version || corrected.journal.seq !== C.seq ||
      corrected.journal.hash !== C.hash) return { problem: "CLOSE_CORRECTION_NOT_PINNED" };
  if (poisonSources.length !== 1 || poisonSources[0].status !== "FALSE_WORLD_POSTCONDITION") return { problem: "CLOSE_POISON_NOT_PINNED" };

  const version = all.anchor_version + 1;
  const close = { schema: "lim.gatec.lineage-close.v1", lineage, reason, pre_close_highwater_sha256: sha256(hwBytes),
    pre_close_anchor_version: all.anchor_version, lineage_records: mine, superseded_floor: superseded,
    corrected_floor: corrected, poisoned, poison_sources: poisonSources, tombstone: true };
  const anchor = { schema: "lim.gatec.external-highwater.v1", anchor_version: version, lineage, epoch: null, nonce: null,
    decision_id: null, status: "LINEAGE_CLOSED", reason, journal: corrected ? corrected.journal : null,
    registry: corrected ? corrected.registry : null, world_observation_sha256: null, issued_at_ms: Date.now(),
    run: { id: env.GITHUB_RUN_ID || null, attempt: env.GITHUB_RUN_ATTEMPT || null, sha: env.GITHUB_SHA || null } };
  const record = { world: null, anchor, close };
  all.anchor_version = version;
  all.lineages[lineage] = { closed: true, closed_at_anchor: version, reason, corrected_floor: corrected,
    superseded_floor: superseded, poisoned };
  return { record, highwater: all, version };
}

export async function runClose(env = process.env, dir = ".") {
  const hwPath = `${dir}/highwater.json`;
  const hwBytes = existsSync(hwPath) ? readFileSync(hwPath) : null;
  const recordFiles = {};
  if (existsSync(`${dir}/records`))
    for (const n of readdirSync(`${dir}/records`)) if (n.endsWith(".json")) recordFiles[n] = readFileSync(`${dir}/records/${n}`);
  // rev 2: no workflow inputs; the only lineage/reason this can ever act on are the pinned constants
  const plan = planClose({ lineage: PINNED.lineage, reason: PINNED.reason, hwBytes, recordFiles, env });
  if (plan.problem) { console.log(JSON.stringify({ status: "CLOSE_REFUSED", reason: plan.problem })); return { problem: plan.problem }; }
  const recordSha = sha256(canonical(plan.record));   // hash covers world/anchor/close (everything except the token)
  plan.record.github_oidc = await oidc("lim-witness:" + recordSha, env);
  writeFileSync(`${dir}/records/${String(plan.version).padStart(8, "0")}.json`, JSON.stringify(plan.record, null, 1) + "\n");
  writeFileSync(hwPath, JSON.stringify(plan.highwater, null, 1) + "\n");
  console.log(JSON.stringify({ anchor_version: plan.version, status: "LINEAGE_CLOSED", lineage: plan.record.close.lineage,
    poisoned: plan.record.close.poisoned, record_sha256: recordSha }));
  return { version: plan.version, recordSha };
}

// rev 2b: run only when THIS file is the entry point (an exact path match, not a name suffix: importing close.mjs from
// e.g. xcheck_close.mjs must never execute a close).
const self = fileURLToPath(import.meta.url);
if (process.argv[1] && resolvePath(process.argv[1]) === self) {
  runClose().then(r => { if (r.problem) process.exit(3); })
    .catch(e => { console.error("CLOSE_ERROR " + e.message); process.exit(1); });
}
