import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalize, digestJson, type JsonValue } from "@prt/jcs-digest";
import {
  CORE_MEMBERS,
  verifyChain,
  verifyEventSignature,
  type CanonicalEvent,
  type EventCore,
} from "@prt/event-v1";
import { CORE_EVENT_TYPES, foldHistory } from "@prt/fold-core";

const CORE_TYPE_SET = new Set(CORE_EVENT_TYPES);
import {
  EXPORT_FORMAT,
  RECEIPT_MEMBERS,
  type BundleVerificationCheck,
  type BundleVerificationReport,
  type ExportManifest,
  type KeyBundleEntry,
} from "./bundle.js";

/**
 * §57/§58: independent offline verification of a process-export/v1 bundle.
 *
 * Trust model (RT-EXPORT-001): the verifier trusts nothing but the bundle
 * bytes. No live runtime, no deployment account, no network.
 */
export function verifyBundle(dir: string): BundleVerificationReport {
  const checks: BundleVerificationCheck[] = [];
  const check = (name: string, ok: boolean, detail?: string) => {
    checks.push(detail === undefined ? { name, ok } : { name, ok, detail });
    return ok;
  };

  // --- manifest -----------------------------------------------------------
  let manifestRaw: string;
  try {
    manifestRaw = fs.readFileSync(path.join(dir, "manifest.json"), "utf8");
  } catch {
    check("manifest exists", false, "manifest.json not found");
    return { status: "INVALID", checks };
  }

  let manifest: ExportManifest & { digest?: string };
  try {
    manifest = JSON.parse(manifestRaw) as ExportManifest & { digest?: string };
  } catch {
    check("manifest parses", false, "manifest.json is not JSON");
    return { status: "INVALID", checks };
  }

  check("manifest format identifier", manifest.format === EXPORT_FORMAT, `format=${String(manifest.format)}`);

  // Manifest canonical form: the file must be the JCS of its object.
  check(
    "manifest is canonical JCS",
    canonicalize(manifest as unknown as JsonValue) === manifestRaw,
  );

  // Manifest self-digest: recompute over manifest without digest member.
  const { digest: claimedDigest, ...manifestCore } = manifest;
  const recomputed = digestJson(manifestCore as unknown as JsonValue).digest;
  check("manifest digest recomputation", claimedDigest === recomputed);

  // --- path confinement (§56.3: exactly one canonical reading) ----------
  // Every path reference coming from the manifest MUST resolve inside the
  // bundle root. No absolute paths, no "..", no escapes.
  const root = path.resolve(dir);
  const confined = (ref: string): boolean => {
    if (path.isAbsolute(ref)) return false;
    if (ref.split("/").some((seg) => seg === ".." || seg === "")) return false;
    const resolved = path.resolve(root, ref);
    return resolved.startsWith(root + path.sep);
  };
  const allRefs = [...(manifest.receipt_refs ?? []), ...(manifest.kind_reference !== null ? [manifest.kind_reference] : [])];
  check(
    "manifest path references confined to bundle root",
    allRefs.every((r) => confined(r)),
  );

  // --- closed bundle inventory -------------------------------------------
  // The bundle contains EXACTLY: manifest.json, events.jsonl, the referenced
  // receipts, keys/keys.json, referenced kind bytes, and inventory-listed
  // artifacts/evidence. Extra files or symlinks break the single canonical
  // reading and are rejected.
  const allowed = new Set<string>([
    "manifest.json",
    "events.jsonl",
    "keys/keys.json",
    ...allRefs,
    ...((manifest.artifact_inventory ?? []) as Array<{ path?: string }>).map((a) => a.path).filter((p): p is string => typeof p === "string"),
    ...((manifest.evidence_inventory ?? []) as Array<{ path?: string }>).map((e) => e.path).filter((p): p is string => typeof p === "string"),
  ]);
  const found: string[] = [];
  let symlinkFound = false;
  const walk = (rel: string): void => {
    const abs = path.join(root, rel);
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(abs, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const childRel = rel === "" ? e.name : `${rel}/${e.name}`;
      if (e.isSymbolicLink()) {
        symlinkFound = true;
      } else if (e.isDirectory()) {
        walk(childRel);
      } else if (e.isFile()) {
        found.push(childRel);
      }
    }
  };
  walk("");
  check("bundle contains no symlinks", !symlinkFound);
  const extras = found.filter((f) => !allowed.has(f));
  check("closed bundle inventory (no unexpected files)", extras.length === 0, extras.join(", ") || undefined);

  // --- events -------------------------------------------------------------
  let envelopes: CanonicalEvent[] = [];
  try {
    const lines = fs.readFileSync(path.join(dir, "events.jsonl"), "utf8").trim().split("\n");
    envelopes = lines.map((l) => JSON.parse(l) as CanonicalEvent);
  } catch {
    check("events.jsonl parses", false);
    return { status: "INVALID", checks };
  }

  try {
    verifyChain(envelopes);
    check("canonical chain (genesis, links, sequences, digests, epochs)", true);
  } catch (e) {
    check("canonical chain (genesis, links, sequences, digests, epochs)", false, (e as Error).message);
  }

  check(
    "event digests match manifest inventory",
    JSON.stringify(envelopes.map((e) => e.digest)) === JSON.stringify(manifest.event_digests),
  );

  const finalHead = envelopes[envelopes.length - 1]?.digest;
  check("manifest head matches final event", finalHead === manifest.head);
  check("manifest event_count matches", envelopes.length === manifest.event_count);

  // --- replay (§12, §58) ---------------------------------------------------
  try {
    const cores = envelopes.map(
      (env) =>
        Object.fromEntries(CORE_MEMBERS.map((m: string) => [m, (env as unknown as Record<string, unknown>)[m]])) as unknown as EventCore,
    );
    const projection = foldHistory(cores);
    check("replay folds from pinned history", true);
    check("manifest epoch matches replay", projection.epoch === manifest.epoch);
  } catch (e) {
    check("replay folds from pinned history", false, (e as Error).message);
  }

  // --- signatures, fully offline (RT-EXPORT-001) ----------------------------
  let keys: KeyBundleEntry[] = [];
  try {
    keys = JSON.parse(fs.readFileSync(path.join(dir, "keys", "keys.json"), "utf8")) as KeyBundleEntry[];
    check("keys/ inventory parses", true);
  } catch {
    check("keys/ inventory parses", false);
  }

  const signedEvents = envelopes.filter((e) => e.signature !== undefined);
  if (signedEvents.length > 0) {
    const manifestKeyIds = new Set(manifest.key_inventory.map((k) => k.key_id));
    const everyKeyResolvable = signedEvents.every((e) => {
      const kid = e.signature?.key_id;
      return kid !== undefined && manifestKeyIds.has(kid) && keys.some((k) => k.key_id === kid);
    });
    check("every key_id resolvable from bundle (RT-EXPORT-001)", everyKeyResolvable);

    // Full key material binding: the digest of each bundled key MUST match
    // the digest bound in the (self-digesting) manifest.
    const keyDigestsMatch = manifest.key_inventory.every((inv) => {
      const entry = keys.find((k) => k.key_id === inv.key_id && k.valid_from_seq === inv.valid_from_seq);
      if (entry === undefined) return false;
      const derDigest = "sha256:" + createHash("sha256").update(Buffer.from(entry.public_key, "base64url")).digest("hex");
      return derDigest === inv.key_digest;
    });
    check("bundled key material matches manifest digests", keyDigestsMatch);

    // Trust anchor (§7.7): bundle keys cannot bootstrap their own
    // authenticity. The anchored key set is constructed from canonical
    // history alone — the genesis anchor plus every authority_key_introduced
    // event. Any signing key outside that set is indistinguishable from a
    // substitution attack.
    const genesisPayload = envelopes[0]?.payload as Record<string, unknown> | undefined;
    const anchor = typeof genesisPayload?.authority_key_digest === "string" ? (genesisPayload.authority_key_digest as string) : undefined;
    if (anchor === undefined) {
      check("history carries a genesis key anchor (RT-KEY-001)", false, "signed history without authority_key_digest in genesis");
    } else {
      const anchored = new Set<string>([anchor]);
      for (const e of envelopes) {
        if (e.type === "authority_key_introduced") {
          const kd = (e.payload as Record<string, unknown>).key_digest;
          if (typeof kd === "string") anchored.add(kd);
        }
      }
      const digestOf = (der: Uint8Array) => "sha256:" + createHash("sha256").update(Buffer.from(der)).digest("hex");
      const usedKeyDigests = new Set(
        signedEvents.map((e) => {
          const kid = e.signature?.key_id;
          const entry = keys
            .filter((k) => k.key_id === kid && k.valid_from_seq <= e.sequence)
            .sort((a, b) => a.valid_from_seq - b.valid_from_seq)
            .at(-1);
          return entry === undefined ? "unresolvable" : digestOf(Buffer.from(entry.public_key, "base64url"));
        }),
      );
      const unanchored = [...usedKeyDigests].filter((d) => !anchored.has(d));
      check(
        "all signing keys anchored in canonical history (§7.7, RT-KEY-002)",
        unanchored.length === 0,
        unanchored.length > 0 ? "unanchored key material in bundle" : undefined,
      );
    }

    // Historical resolution: the key valid at the event's sequence (§7.5).
    const allSignaturesValid = signedEvents.every((e) => {
      const resolver = (keyId: string): Uint8Array | undefined => {
        const candidates = keys
          .filter((k) => k.key_id === keyId && k.valid_from_seq <= e.sequence)
          .sort((a, b) => a.valid_from_seq - b.valid_from_seq);
        const latest = candidates[candidates.length - 1];
        if (latest === undefined) return undefined;
        return Buffer.from(latest.public_key, "base64url");
      };
      return verifyEventSignature(e, resolver);
    });
    check("all signatures verify offline (RT-SIG-001)", allSignaturesValid);
  } else {
    check("history unsigned (permitted where Kind does not require)", true);
  }

  // --- receipts (§57: structurally valid) ----------------------------------
  let receiptsOk = true;
  let receiptsDetail: string | undefined;
  const eventDigests = new Set(envelopes.map((e) => e.digest));
  for (const ref of manifest.receipt_refs) {
    try {
      const r = JSON.parse(fs.readFileSync(path.join(dir, ref), "utf8")) as Record<string, unknown>;
      const hasMembers = RECEIPT_MEMBERS.every((m) => Object.prototype.hasOwnProperty.call(r, m));
      if (!hasMembers) {
        receiptsOk = false;
        receiptsDetail = `${ref}: missing members`;
        break;
      }
      if (!eventDigests.has(r.event_digest as string)) {
        receiptsOk = false;
        receiptsDetail = `${ref}: event_digest not in chain`;
        break;
      }
    } catch {
      receiptsOk = false;
      receiptsDetail = `${ref}: unreadable`;
      break;
    }
  }
  check("receipts structurally valid and bound to chain", receiptsOk, receiptsDetail);

  // --- kind material ---------------------------------------------------------
  if (manifest.kind_reference !== null) {
    const kindPath = path.join(root, manifest.kind_reference);
    if (!confined(manifest.kind_reference) || !fs.existsSync(kindPath)) {
      check("pinned Kind material present and confined", false, manifest.kind_reference);
    } else {
      // §56: bytes, not existence. The embedded Kind MUST hash to kind_digest.
      const kindBytes = fs.readFileSync(kindPath);
      const kindDigest = "sha256:" + createHash("sha256").update(kindBytes).digest("hex");
      check("embedded Kind bytes match kind_digest", kindDigest === manifest.kind_digest);
    }
  }

  // Known verifier limits (documented, not hidden): Kind law is not
  // interpreted here, so Kind-defined fold semantics remain opaque (§7.4)
  // and signature obligations of the Kind cannot be evaluated offline yet.
  const hasKindDefinedTypes = envelopes.some((e) => {
    const t = e.type;
    return !CORE_TYPE_SET.has(t);
  });
  if (hasKindDefinedTypes) {
    check("note: Kind-defined event types folded opaquely (Kind law not interpreted)", true);
  }

  const status = checks.every((c) => c.ok) ? "VALID" : "INVALID";
  return { status, checks };
}
