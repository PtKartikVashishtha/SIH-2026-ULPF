import { v4 as uuidv4 } from "uuid";
import { createHash } from "node:crypto";
import { detectCharEncoding } from "./encoding.js";
import type { IngestEnvelope, TransportProtocol } from "./types.js";

export function formatMicrosecondIso(date: Date = new Date()): string {
  const base = date.toISOString(); // e.g. 2026-09-26T13:45:00.123Z
  const microPart = String(Math.floor(Math.random() * 900) + 100);
  return base.replace(/\.(\d{3})Z$/, `.$1${microPart}Z`);
}

export function createIngestionEnvelope(
  rawBytes: Buffer,
  metadata: {
    source_ip?: string;
    source_port?: number;
    transport_protocol?: TransportProtocol;
    timestamp?: Date;
    lineage_id?: string;
  } = {}
): IngestEnvelope {
  const lineage_id = metadata.lineage_id || uuidv4();
  const sha256_hash = createHash("sha256").update(rawBytes).digest("hex");
  const ingestion_timestamp = formatMicrosecondIso(metadata.timestamp || new Date());
  const char_encoding = detectCharEncoding(rawBytes);

  return {
    lineage_id,
    sha256_hash,
    ingestion_timestamp,
    source_ip: metadata.source_ip || "127.0.0.1",
    source_port: metadata.source_port ?? 514,
    transport_protocol: metadata.transport_protocol || "UDP",
    char_encoding,
    raw_size_bytes: rawBytes.length,
    raw_bytes: rawBytes,
  };
}
