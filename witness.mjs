// LIM independent world observer + rollback witness (runs ONLY on GitHub Actions in lookedam/lim-witness).
// No LIM machine or agent holds a write path here. Each run:
//  1. takes ONE claim (decision id, lineage, epoch, journal/registry heads, nonce, effect locator) from the dispatch input;
//  2. reads the REAL provider outcome itself with its own read-only token (never issuer-supplied world data);
//  3. refuses any claim whose heads are lower than (or fork from) the high-water already recorded here = rollback detection;
//  4. writes records/<n>.json + highwater.json and gets a GitHub-signed OIDC token whose audience binds the record hash.
// Output status is evidence only. It never grants Gate C or first30 credit by itself.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";

const canonical = v => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canonical).join(",") + "]"
  : "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
const sha256 = s => createHash("sha256").update(s, "utf8").digest("hex");
const hex64 = s => typeof s === "string" && /^[a-f0-9]{64}$/.test(s);
const text = s => typeof s === "string" && s.trim().length > 0 && s.length <= 160;
const seq = v => Number.isSafeInteger(v) && v >= 0;
const head = h => h && seq(h.seq) && hex64(h.hash) && Object.keys(h).length === 2;
const API = process.env.WITNESS_API_BASE || "https://api.github.com";      // tests only override this
const ALLOWED_REPOS = new Set(["LivesInMotion/lim-platform"]);

function parseClaim(b64) {
  let c;
  try { c = JSON.parse(Buffer.from(b64 || "", "base64").toString("utf8")); } catch { return [null, "CLAIM_NOT_JSON"]; }
  if (!c || c.schema !== "lim.gatec.shadow-claim.v1" || !text(c.decision_id) || !text(c.lineage) || !seq(c.epoch) ||
      !hex64(c.expected_world_sha256) || !head(c.journal) || !head(c.registry) || !text(c.nonce) || !c.effect)
    return [null, "CLAIM_MALFORMED"];
  const e = c.effect;
  if (e.kind !== "github_comment" || !ALLOWED_REPOS.has(e.repo) || !/^\d{6,12}$/.test(String(e.comment_id)))
    return [null, "EFFECT_SOURCE_NOT_SUPPORTED"];
  return [c, ""];
}

async function observeGithubComment(e, env) {
  const r = await fetch(`${API}/repos/${e.repo}/issues/comments/${e.comment_id}`, {
    headers: { Authorization: `Bearer ${env.LIM_READ_TOKEN}`, Accept: "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "lim-witness" } });
  if (r.status === 404) return { source: "github.issue_comment", repo: e.repo, comment_id: String(e.comment_id), exists: false };
  if (!r.ok) throw new Error("PROVIDER_READ_FAILED_" + r.status);
  const j = await r.json();
  return { source: "github.issue_comment", repo: e.repo, comment_id: String(j.id), exists: true,
           issue_number: Number(String(j.issue_url).split("/").pop()), author: j.user && j.user.login,
           body_sha256: sha256(j.body || ""), created_at: j.created_at, updated_at: j.updated_at };
}

// hw = the high-water of THIS claim's lineage only (each lineage is tracked separately; the verifier pins the lineage)
function rollbackCheck(hw, c) {
  if (!hw || !hw.journal) return "";
  if (c.epoch < hw.epoch) return "EPOCH_ROLLBACK";
  if (c.journal.seq <= hw.journal.seq)          // every decision advances the journal: blocks re-runs/replays of old claims
    return c.journal.seq === hw.journal.seq && c.journal.hash === hw.journal.hash ? "REPLAY_NOT_ADVANCED" : "JOURNAL_ROLLBACK";
  for (const k of ["registry"]) {
    if (c[k].seq < hw[k].seq) return k.toUpperCase() + "_ROLLBACK";
    if (c[k].seq === hw[k].seq && c[k].hash !== hw[k].hash) return k.toUpperCase() + "_FORK";
  }
  return "";
}

async function oidc(audience, env) {
  const u = env.ACTIONS_ID_TOKEN_REQUEST_URL, t = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!u || !t) throw new Error("OIDC_UNAVAILABLE");
  const r = await fetch(`${u}&audience=${encodeURIComponent(audience)}`, { headers: { Authorization: `Bearer ${t}` } });
  if (!r.ok) throw new Error("OIDC_FAILED_" + r.status);
  return (await r.json()).value;
}

export async function run(env = process.env, dir = ".") {
  const hwPath = `${dir}/highwater.json`;
  const all = existsSync(hwPath) ? JSON.parse(readFileSync(hwPath, "utf8")) : { anchor_version: 0, lineages: {} };
  const version = all.anchor_version + 1;
  const now = () => Date.now();
  const [c, bad] = parseClaim(env.REQUEST);
  let world = null, status, reason = bad;
  const hw = c && Object.prototype.hasOwnProperty.call(all.lineages, c.lineage) ? all.lineages[c.lineage] : null;
  if (c) {
    reason = rollbackCheck(hw, c);
    if (!reason) {
      try { world = await observeGithubComment(c.effect, env); } catch (e) { reason = String(e.message).slice(0, 80); }
    }
  }
  const observed_at_ms = now();
  const worldBody = world && { schema: "lim.gatec.world-observation.v1", source_id: "github:" + c.effect.repo,
    event_id: "comment:" + world.comment_id, decision_id: c.decision_id, lineage: c.lineage, epoch: c.epoch,
    nonce: c.nonce, journal: c.journal, registry: c.registry, observed_at_ms,
    observed_world: world, observed_world_sha256: sha256(canonical(world)) };
  if (!reason) status = worldBody.observed_world_sha256 === c.expected_world_sha256 ? "WORLD_MATCH" : "FALSE_WORLD_POSTCONDITION";
  else status = "REFUSED";
  const anchorBody = { schema: "lim.gatec.external-highwater.v1", anchor_version: version,
    lineage: c ? c.lineage : null, epoch: c ? c.epoch : null, nonce: c ? c.nonce : null,
    decision_id: c ? c.decision_id : null, status, reason,
    journal: (status === "REFUSED" ? hw && hw.journal : c.journal) || null,
    registry: (status === "REFUSED" ? hw && hw.registry : c.registry) || null,
    world_observation_sha256: worldBody ? sha256(canonical(worldBody)) : null, issued_at_ms: now(),
    run: { id: env.GITHUB_RUN_ID || null, attempt: env.GITHUB_RUN_ATTEMPT || null, sha: env.GITHUB_SHA || null } };
  const record = { world: worldBody, anchor: anchorBody };
  const recordSha = sha256(canonical(record));
  record.github_oidc = await oidc("lim-witness:" + recordSha, env);   // GitHub-signed: binds repo, workflow file SHA, run, record hash
  mkdirSync(`${dir}/records`, { recursive: true });
  writeFileSync(`${dir}/records/${String(version).padStart(8, "0")}.json`, JSON.stringify(record, null, 1) + "\n");
  // the high-water only moves forward, and only on a non-refused claim
  all.anchor_version = version;
  if (status !== "REFUSED") all.lineages[c.lineage] = { epoch: c.epoch, journal: c.journal, registry: c.registry, anchor_version: version };
  writeFileSync(hwPath, JSON.stringify(all, null, 1) + "\n");
  console.log(JSON.stringify({ anchor_version: version, status, reason, record_sha256: recordSha }));
  return { version, status, reason, recordSha };
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("witness.mjs")) {
  run().catch(e => { console.error("WITNESS_ERROR " + e.message); process.exit(1); });
}
