/**
 * ingestion-svc — C1: Syslog UDP/TCP + HTTP listeners, envelope generation,
 * dual-trigger batching, zstd compression, raw store writer, durable spool.
 */

import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { IngestionService } from "./service.js";

export * from "./types.js";
export * from "./envelope.js";
export * from "./encoding.js";
export * from "./raw_store.js";
export * from "./db.js";
export * from "./spool.js";
export * from "./bus.js";
export * from "./batcher.js";
export * from "./service.js";

const __dir = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dir, "..", "..", "..");
const DB_PATH = process.env.DB_PATH || join(REPO_ROOT, "ulpf.db");
const DATA_DIR = process.env.DATA_DIR || (process.env.RAW_STORE_DIR ? dirname(process.env.RAW_STORE_DIR) : join(REPO_ROOT, "data"));

export async function main(): Promise<void> {
  const udpPort = parseInt(process.env.SYSLOG_UDP_PORT || process.env.ULPF_UDP_PORT || "5140", 10);
  const tcpPort = parseInt(process.env.SYSLOG_TCP_PORT || process.env.ULPF_TCP_PORT || "5141", 10);
  const httpPort = parseInt(process.env.PORT || process.env.ULPF_HTTP_PORT || "5142", 10);

  console.log("Starting ingestion-svc (M1)...");
  const service = new IngestionService({
    dataDir: DATA_DIR,
    dbPath: DB_PATH,
    batcherConfig: {
      maxEventCount: 50,
      maxTimeMs: 1000,
    },
  });

  await service.startListeners({
    udp: udpPort,
    tcp: tcpPort,
    http: httpPort,
  });

  console.log(`ingestion-svc listening on UDP ${udpPort}, TCP ${tcpPort}, HTTP ${httpPort}`);
}

main().catch((err) => {
  console.error("Failed to start ingestion-svc:", err);
  process.exit(1);
});
