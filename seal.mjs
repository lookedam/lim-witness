// lim-witness v4: seal / unseal the effect locator (which private comment to observe) so the PUBLIC request issue does not
// reveal it. X25519 ECDH with a fresh ephemeral key -> HKDF-SHA256 -> AES-256-GCM. The AAD is the canonical claim WITHOUT
// the sealed field, so a sealed locator cannot be spliced into a different claim. Only the witness holds the private key
// (lookedam repo secret OBSERVER_X25519_PRIV); requesters hold the public key (observer_x25519.pub.pem in the repo).
import { createPublicKey, createPrivateKey, generateKeyPairSync, diffieHellman, hkdfSync, randomBytes,
         createCipheriv, createDecipheriv } from "node:crypto";

export const canonical = v => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canonical).join(",") + "]"
  : "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
const INFO = Buffer.from("lim-witness-effect-v1");
const aadOf = claim => { const { effect_sealed, effect, ...rest } = claim; return Buffer.from(canonical(rest), "utf8"); };
const kdf = (shared, epkDer) => Buffer.from(hkdfSync("sha256", shared, epkDer, INFO, 32));

export function seal(effect, claim, publicPem) {
  const pub = createPublicKey(publicPem);
  if (pub.asymmetricKeyType !== "x25519") throw new Error("OBSERVER_KEY_NOT_X25519");
  const eph = generateKeyPairSync("x25519");
  const epkDer = eph.publicKey.export({ type: "spki", format: "der" });
  const key = kdf(diffieHellman({ privateKey: eph.privateKey, publicKey: pub }), epkDer);
  const iv = randomBytes(12), c = createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(aadOf(claim));
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(effect), "utf8")), c.final()]);
  return { alg: "X25519-HKDF-SHA256-AES256GCM", epk: epkDer.toString("base64"), iv: iv.toString("base64"),
           ct: ct.toString("base64"), tag: c.getAuthTag().toString("base64") };
}

export function unseal(claim, privatePem) {
  const s = claim.effect_sealed;
  if (!s || s.alg !== "X25519-HKDF-SHA256-AES256GCM") throw new Error("EFFECT_NOT_SEALED");
  const priv = createPrivateKey(privatePem);
  const epkDer = Buffer.from(s.epk, "base64");
  const epk = createPublicKey({ key: epkDer, format: "der", type: "spki" });
  if (epk.asymmetricKeyType !== "x25519") throw new Error("EFFECT_SEAL_BAD_KEY");
  const key = kdf(diffieHellman({ privateKey: priv, publicKey: epk }), epkDer);
  const d = createDecipheriv("aes-256-gcm", key, Buffer.from(s.iv, "base64"));
  d.setAAD(aadOf(claim)); d.setAuthTag(Buffer.from(s.tag, "base64"));
  return JSON.parse(Buffer.concat([d.update(Buffer.from(s.ct, "base64")), d.final()]).toString("utf8"));
}
