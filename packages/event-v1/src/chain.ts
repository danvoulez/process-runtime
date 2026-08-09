import { verifyEventEnvelope } from "./envelope.js";
import type { CanonicalEvent } from "./types.js";

function fail(section: string, msg: string): never {
  throw new Error(`${section}: ${msg}`);
}

/**
 * §12 structural chain verification (verification-only, no mutation):
 *  - genesis: sequence 0, previous null
 *  - contiguous sequences
 *  - previous links (event[n].previous == event[n-1].digest)
 *  - digest recomputation for every event (RT-EVENT-002)
 *  - epoch monotonicity (§10, §10.1)
 */
export function verifyChain(events: unknown[]): CanonicalEvent[] {
  if (!Array.isArray(events) || events.length === 0) fail("§12", "chain must be a non-empty array");

  const verified = events.map((e) => verifyEventEnvelope(e));

  const genesis = verified[0] as CanonicalEvent;
  if (genesis.sequence !== 0) fail("§12", "genesis sequence must be 0");
  if (genesis.previous !== null) fail("§12", "genesis previous must be null");

  let lastEpoch = genesis.epoch;
  for (let i = 1; i < verified.length; i++) {
    const prev = verified[i - 1] as CanonicalEvent;
    const cur = verified[i] as CanonicalEvent;
    if (cur.sequence !== i) fail("§12", `sequence gap at position ${i}: expected ${i}, got ${cur.sequence}`);
    if (cur.previous !== prev.digest) fail("§12", `broken previous link at sequence ${i}`);
    if (cur.epoch < lastEpoch) fail("§10", `epoch decreased at sequence ${i}`);
    lastEpoch = cur.epoch;
  }
  return verified;
}

/** §8: the chain's current head is the digest of its latest event. */
export function chainHead(events: CanonicalEvent[]): string {
  const last = events[events.length - 1];
  if (last === undefined) fail("§8", "empty chain has no head");
  return last.digest;
}
