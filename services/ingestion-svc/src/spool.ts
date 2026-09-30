import { existsSync, mkdirSync, appendFileSync, readFileSync, readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import type { SpoolInterface, DbRepositoryInterface, IngestEnvelope } from "./types.js";

interface SerializedEnvelope {
  lineage_id: string;
  sha256_hash: string;
  ingestion_timestamp: string;
  source_ip: string;
  source_port: number;
  transport_protocol: IngestEnvelope["transport_protocol"];
  char_encoding: string;
  raw_size_bytes: number;
  raw_bytes_b64: string;
  storage_pointer?: string;
  chunk_id?: string;
  merkle_leaf_index?: number;
}

export class DiskSpool implements SpoolInterface {
  private spoolDir: string;

  constructor(spoolDir: string) {
    this.spoolDir = spoolDir;
    if (!existsSync(this.spoolDir)) {
      mkdirSync(this.spoolDir, { recursive: true });
    }
  }

  spool(events: IngestEnvelope[]): void {
    if (events.length === 0) return;
    const filename = `spool_${Date.now()}_${Math.random().toString(36).slice(2, 8)}.jsonl`;
    const filepath = join(this.spoolDir, filename);

    const lines = events.map((ev) => {
      const record: SerializedEnvelope = {
        lineage_id: ev.lineage_id,
        sha256_hash: ev.sha256_hash,
        ingestion_timestamp: ev.ingestion_timestamp,
        source_ip: ev.source_ip,
        source_port: ev.source_port,
        transport_protocol: ev.transport_protocol,
        char_encoding: ev.char_encoding,
        raw_size_bytes: ev.raw_size_bytes,
        raw_bytes_b64: ev.raw_bytes.toString("base64"),
        storage_pointer: ev.storage_pointer,
        chunk_id: ev.chunk_id,
        merkle_leaf_index: ev.merkle_leaf_index,
      };
      return JSON.stringify(record);
    });

    appendFileSync(filepath, lines.join("\n") + "\n", "utf-8");
  }

  flush(db: DbRepositoryInterface): number {
    if (!db.isHealthy()) return 0;
    const files = readdirSync(this.spoolDir)
      .filter((f) => f.startsWith("spool_") && f.endsWith(".jsonl"))
      .sort();

    let totalFlushed = 0;
    for (const file of files) {
      const filepath = join(this.spoolDir, file);
      try {
        const content = readFileSync(filepath, "utf-8");
        const lines = content.trim().split("\n").filter(Boolean);
        const envelopes: IngestEnvelope[] = lines.map((line) => {
          const rec: SerializedEnvelope = JSON.parse(line);
          return {
            lineage_id: rec.lineage_id,
            sha256_hash: rec.sha256_hash,
            ingestion_timestamp: rec.ingestion_timestamp,
            source_ip: rec.source_ip,
            source_port: rec.source_port,
            transport_protocol: rec.transport_protocol,
            char_encoding: rec.char_encoding,
            raw_size_bytes: rec.raw_size_bytes,
            raw_bytes: Buffer.from(rec.raw_bytes_b64, "base64"),
            storage_pointer: rec.storage_pointer,
            chunk_id: rec.chunk_id,
            merkle_leaf_index: rec.merkle_leaf_index,
          };
        });

        db.insertRawEvents(envelopes);
        unlinkSync(filepath);
        totalFlushed += envelopes.length;
      } catch {
        break;
      }
    }
    return totalFlushed;
  }

  getPendingCount(): number {
    const files = readdirSync(this.spoolDir).filter(
      (f) => f.startsWith("spool_") && f.endsWith(".jsonl")
    );
    let count = 0;
    for (const file of files) {
      const filepath = join(this.spoolDir, file);
      try {
        const content = readFileSync(filepath, "utf-8");
        count += content.trim().split("\n").filter(Boolean).length;
      } catch {
        // ignore
      }
    }
    return count;
  }
}
