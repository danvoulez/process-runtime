/**
 * RFC 8785 (JSON Canonicalization Scheme) serialization.
 *
 * Determinism rules implemented here:
 *  - object members sorted lexicographically by UTF-16 code units
 *    (ECMAScript default string comparison, as the RFC requires);
 *  - numbers serialized with ECMA-262 Number::toString semantics
 *    (JSON.stringify already implements exactly this);
 *  - -0 serialized as 0; non-finite numbers rejected (not JSON data);
 *  - strings minimally escaped per JSON (JSON.stringify semantics);
 *  - no whitespace anywhere.
 */

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export function canonicalize(value: JsonValue): string {
  return serialize(value);
}

function serialize(value: JsonValue): string {
  if (value === null) return "null";

  const t = typeof value;

  if (t === "boolean") return value ? "true" : "false";

  if (t === "number") {
    const n = value as number;
    if (!Number.isFinite(n)) {
      throw new Error("JCS: non-finite numbers are not in the JSON data model");
    }
    // JSON.stringify(-0) === "0", matching RFC 8785.
    return JSON.stringify(n);
  }

  if (t === "string") return JSON.stringify(value as string);

  if (Array.isArray(value)) {
    return "[" + value.map((item) => serialize(item)).join(",") + "]";
  }

  if (t === "object") {
    const obj = value as Record<string, JsonValue>;
    // Array.prototype.sort compares UTF-16 code units by default,
    // which is the ordering RFC 8785 section 3.2.3 requires.
    const keys = Object.keys(obj).sort();
    const entries = keys.map((k) => JSON.stringify(k) + ":" + serialize(obj[k] as JsonValue));
    return "{" + entries.join(",") + "}";
  }

  throw new Error(`JCS: unsupported value type: ${t}`);
}
