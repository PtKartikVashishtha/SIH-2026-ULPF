import Database from "better-sqlite3";
import type { DbRepositoryInterface, IngestEnvelope } from "./types.js";

export class SqliteRawEventsRepository implements DbRepositoryInterface {
  private db: Database.Database;
  private insertStmt: Database.Statement;
  private isClosed = false;

  constructor(dbPathOrDb: string | Database.Database) {
    if (typeof dbPathOrDb === "string") {
      this.db = new Database(dbPathOrDb);
      this.db.pragma("journal_mode = WAL");
      this.db.pragma("foreign_keys = ON");
    } else {
      this.db = dbPathOrDb;
    }
    this.ensureSchema();
    this.insertStmt = this.db.prepare(`
      INSERT INTO raw_events (
        lineage_id, sha256_hash, ingestion_timestamp, source_ip, source_port,
        transport_protocol, char_encoding, raw_size_bytes, storage_pointer,
        chunk_id, merkle_leaf_index, created_at
      ) VALUES (
        @lineage_id, @sha256_hash, @ingestion_timestamp, @source_ip, @source_port,
        @transport_protocol, @char_encoding, @raw_size_bytes, @storage_pointer,
        @chunk_id, @merkle_leaf_index, @created_at
      )
    `);
  }

  private ensureSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS raw_events (
        lineage_id TEXT PRIMARY KEY,
        sha256_hash TEXT NOT NULL,
        ingestion_timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        source_port INTEGER NOT NULL,
        transport_protocol TEXT NOT NULL CHECK (transport_protocol IN ('UDP','TCP','TLS','HTTP')),
        char_encoding TEXT NOT NULL,
        raw_size_bytes INTEGER NOT NULL,
        storage_pointer TEXT NOT NULL,
        chunk_id TEXT,
        merkle_leaf_index INTEGER,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_re_sha256 ON raw_events(sha256_hash);
      CREATE INDEX IF NOT EXISTS idx_re_chunk ON raw_events(chunk_id);
    `);
  }

  insertRawEvents(events: IngestEnvelope[]): void {
    if (this.isClosed) {
      throw new Error("Database repository is closed");
    }
    const insertMany = this.db.transaction((items: IngestEnvelope[]) => {
      const now = new Date().toISOString();
      for (const item of items) {
        this.insertStmt.run({
          lineage_id: item.lineage_id,
          sha256_hash: item.sha256_hash,
          ingestion_timestamp: item.ingestion_timestamp,
          source_ip: item.source_ip,
          source_port: item.source_port,
          transport_protocol: item.transport_protocol,
          char_encoding: item.char_encoding,
          raw_size_bytes: item.raw_size_bytes,
          storage_pointer: item.storage_pointer || "",
          chunk_id: item.chunk_id ?? null,
          merkle_leaf_index: item.merkle_leaf_index ?? null,
          created_at: now,
        });
      }
    });
    insertMany(events);
  }

  getRawEvent(lineageId: string): unknown | null {
    if (this.isClosed) throw new Error("Database repository is closed");
    return this.db.prepare("SELECT * FROM raw_events WHERE lineage_id = ?").get(lineageId) || null;
  }

  countRawEvents(): number {
    if (this.isClosed) throw new Error("Database repository is closed");
    const row = this.db.prepare("SELECT count(*) as count FROM raw_events").get() as { count: number };
    return row.count;
  }

  isHealthy(): boolean {
    if (this.isClosed) return false;
    try {
      this.db.prepare("SELECT 1").get();
      return true;
    } catch {
      return false;
    }
  }

  close(): void {
    if (!this.isClosed) {
      this.isClosed = true;
      this.db.close();
    }
  }
}
