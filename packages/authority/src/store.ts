import Database from "better-sqlite3";

export type Store = Database.Database;

/**
 * §46/§47: minimal physical model. Canonical events are the only
 * authoritative history; projection, receipts, and leases are durable
 * but derived/operational records (§47.1).
 */
export function openStore(path: string): Store {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(`
    CREATE TABLE IF NOT EXISTS processes (
      process_id    TEXT PRIMARY KEY,
      kind_digest   TEXT NOT NULL,
      created_at    TEXT NOT NULL,
      epoch         INTEGER NOT NULL,
      current_head  TEXT NOT NULL,
      sequence      INTEGER NOT NULL,
      projection    TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS canonical_events (
      process_id  TEXT NOT NULL REFERENCES processes(process_id),
      sequence    INTEGER NOT NULL,
      digest      TEXT NOT NULL,
      event       TEXT NOT NULL,
      PRIMARY KEY (process_id, sequence)
    );

    CREATE TABLE IF NOT EXISTS receipts (
      process_id      TEXT NOT NULL REFERENCES processes(process_id),
      command_id      TEXT NOT NULL,
      request_digest  TEXT NOT NULL,
      receipt         TEXT NOT NULL,
      PRIMARY KEY (process_id, command_id)
    );

    -- §30/§60: one valid Invocation owner per Process, enforced by the
    -- store itself (UNIQUE process_id) — not by application-level checks
    -- that can race across connections.
    CREATE TABLE IF NOT EXISTS leases (
      lease_id      TEXT PRIMARY KEY,
      process_id    TEXT NOT NULL UNIQUE REFERENCES processes(process_id),
      worker_id     TEXT NOT NULL,
      epoch         INTEGER NOT NULL,
      head_at_issue TEXT NOT NULL,
      issued_at     TEXT NOT NULL,
      expires_at    TEXT NOT NULL
    );
  `);
  return db;
}
