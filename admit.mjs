// lim-witness v4.3 ADMISSION (SOURCE ONLY, NOT INSTALLED; ChatGPT #1738, Gemini 20 Nov finding 1). Runs in the `admit` job,
// which is NOT in the serialised `witness` concurrency group and has NO contents write: it decides, with no write to this
// repository, whether an issue from the team account may enter the serialised, record-writing `observe` job.
//  - a committer-ledger-head body is admitted ONLY if the pure ledger decision (ledger.mjs decideLedger on a COPY of this
//    commit's highwater + the owner-pinned producers.json) would ACCEPT it now: exact shape, pinned producer, valid P-256
//    signature, fresh (MAX_SKEW), not a replay, prior == floor. Anything else is closed as NOT_ADMITTED with NO record,
//    NO commit, NO push, and never enters (or cancels a pending run in) the serialised group;
//  - a v4.2 shadow claim is admitted only if it is shape-valid (request.mjs publicClaimProblem, no plaintext effect), no
//    GENUINE committer-ledger-head issue is in flight (rev 3), and fewer than CLAIM_CAP_PER_HOUR shape-valid claims were opened in the hour
//    before it (a deterministic rule over issue numbers: every admit job computes the same answer for the same issue);
//  - anything else (not JSON, wrong schema, junk) is NOT_ADMITTED.
// `yield` mode is the observe job's last check before it commits a CLAIM record: a claim never moves main while a ledger
// head is in flight (a moved main makes that head's run fail closed on the v4.1 checkout binding).
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { isLedgerBody, decideLedger, MAX_SKEW_MS } from "./ledger.mjs";
import { publicClaimProblem } from "./request.mjs";

export const CLAIM_CAP_PER_HOUR = 4;              // bounds the queue ahead of a head: see TRUST_BOUNDARY_PROOFS C3 (formal delay bound)
export const CLAIM_WINDOW_MS = 60 * 60 * 1000;
export const SCAN_LIMIT = 100;                      // one API page; a full page means the window may be truncated -> no claim
export const TEAM = "ekijoyce";

export function claimShapeOk(body) {
  if (typeof body !== "string" || body.length === 0 || body.length > 8192) return false;
  let c; try { c = JSON.parse(Buffer.from(body, "base64").toString("utf8")); } catch { return false; }
  if (!c || typeof c !== "object" || Array.isArray(c) || "effect" in c) return false;
  return publicClaimProblem(c) === "";
}
const issues = list => Array.isArray(list) ? list.filter(i => i && typeof i === "object" && !i.pull_request && i.user && i.user.login === TEAM
  && Number.isSafeInteger(i.number) && typeof i.created_at === "string" && Number.isFinite(Date.parse(i.created_at))) : null;
// rev 3 (round-2 W2): "in flight" = an open team issue whose body the pure ledger decision would ACCEPT now (exact shape,
// pinned producer, valid signature, fresh, prior == floor, not a replay). Ledger-shaped junk can therefore never pause claims.
export function genuineHead(body, highwater, producers, nowMs) {
  if (!isLedgerBody(body)) return false;
  let hw; try { hw = JSON.parse(JSON.stringify(highwater)); } catch { return false; }
  if (!hw || typeof hw !== "object" || !Number.isSafeInteger(hw.anchor_version)) return false;
  return decideLedger(hw, producers, body, nowMs, hw.anchor_version + 1, null).status === "ACCEPTED";
}
export function ledgerInFlight(list, selfNumber, nowMs, highwater, producers) {
  return list.filter(i => i.number !== selfNumber && i.state === "open" && Date.parse(i.created_at) >= nowMs - MAX_SKEW_MS
    && genuineHead(i.body || "", highwater, producers, nowMs)).map(i => i.number);
}

// recent: the GitHub issues list (state=all, creator=team, since = created - 1 h), or null when unavailable.
export function admitDecision({ body, number, createdMs, nowMs, highwater, producers, recent }) {
  if (isLedgerBody(body)) {
    let hw; try { hw = JSON.parse(JSON.stringify(highwater)); } catch { return { admit: false, path: "ledger", reason: "ADMIT_HIGHWATER_UNREADABLE" }; }
    if (!hw || typeof hw !== "object" || !Number.isSafeInteger(hw.anchor_version)) return { admit: false, path: "ledger", reason: "ADMIT_HIGHWATER_UNREADABLE" };
    const d = decideLedger(hw, producers, body, nowMs, hw.anchor_version + 1, null);
    return d.status === "ACCEPTED" ? { admit: true, path: "ledger", reason: "" } : { admit: false, path: "ledger", reason: d.reason };
  }
  if (!claimShapeOk(body)) return { admit: false, path: "none", reason: "ADMIT_BODY_NOT_A_REQUEST" };
  const l = issues(recent);
  if (!l || recent.length >= SCAN_LIMIT) return { admit: false, path: "claim", reason: "ADMIT_CLAIM_WINDOW_UNVERIFIABLE" };
  const busy = ledgerInFlight(l, number, nowMs, highwater, producers);
  if (busy.length) return { admit: false, path: "claim", reason: "ADMIT_LEDGER_HEAD_IN_FLIGHT" };
  const prior = l.filter(i => i.number < number && Date.parse(i.created_at) <= createdMs && Date.parse(i.created_at) > createdMs - CLAIM_WINDOW_MS && claimShapeOk(i.body || ""));
  if (prior.length >= CLAIM_CAP_PER_HOUR) return { admit: false, path: "claim", reason: "ADMIT_CLAIM_RATE_CAP" };
  return { admit: true, path: "claim", reason: "" };
}
// open: the GitHub open-issues list (state=open, creator=team), or null when unavailable. Ledger bodies never yield.
export function yieldDecision({ body, number, nowMs, open, highwater, producers }) {
  if (isLedgerBody(body)) return { yield: false, reason: "" };
  const l = issues(open);
  if (!l || open.length >= SCAN_LIMIT) return { yield: true, reason: "YIELD_OPEN_LIST_UNVERIFIABLE" };
  return ledgerInFlight(l, number, nowMs, highwater, producers).length ? { yield: true, reason: "YIELD_LEDGER_HEAD_IN_FLIGHT" } : { yield: false, reason: "" };
}

const readJson = p => { try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; } };
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [mode, listPath] = process.argv.slice(2), env = process.env, now = Date.now();
  const number = Number(env.N), body = env.REQUEST || "";
  let out;
  if (mode === "admit") out = admitDecision({ body, number, createdMs: Date.parse(env.CREATED || ""), nowMs: now,
    highwater: readJson("highwater.json"), producers: readJson("producers.json"), recent: readJson(listPath) });
  else if (mode === "yield") out = yieldDecision({ body, number, nowMs: now, open: readJson(listPath), highwater: readJson("highwater.json"), producers: readJson("producers.json") });
  else out = { admit: false, yield: true, reason: "ADMIT_USAGE" };
  process.stdout.write(JSON.stringify({ schema: "lim.witness.admission.v1", mode, issue: number, ...out }) + "\n");
}
