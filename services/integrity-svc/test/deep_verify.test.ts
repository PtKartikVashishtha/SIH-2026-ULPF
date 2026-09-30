import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import Database from "better-sqlite3";
import { FileLedger } from "../src/ledger.js";
import { SqliteIntegrityRepository } from "../src/db.js";
import { AnchorService } from "../src/anchor.js";
import { DeepVerifier } from "../src/deep_verify.js";
import { TamperDrill } from "../src/tamper_drill.js";
import { loadPrivateKey, loadPublicKey } from "../src/crypto.js";
import type { MerkleLeaf } from "../src/types.js";
// @ts-expect-error zstd-codec lacks ts types
import { ZstdCodec } from "zstd-codec";

const TEST_DIR = join(process.cwd(), "test-tmp-deep-verify");
const RAW_STORE_DIR = join(TEST_DIR, "raw_store");
const LEDGER_FILE = join(TEST_DIR, "ledger.jsonl");
const DB_FILE = join(TEST_DIR, "test_deep.db");
const REPO_ROOT = join(process.cwd(), "..", "..");
const PRIV_KEY = join(REPO_ROOT, "keys", "dev_signing.key");
const PUB_KEY = join(REPO_ROOT, "keys", "dev_signing.pub");

let zstdInstance: any = null;
async function compressZstd(buf: Buffer): Promise<Uint8Array> {
  if (!zstdInstance) {
    zstdInstance = await new Promise((resolve) => ZstdCodec.run((z: any) => resolve(new z.Simple())));
  }
  return zstdInstance.compress(buf);
}

describe("M2 Acceptance Criterion: Deep Verification & Tamper Drill Isolation", () => {
  let db: SqliteIntegrityRepository;
  let ledger: FileLedger;
  let anchorSvc: AnchorService;
  let verifier: DeepVerifier;

  beforeEach(async () => {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
    await fs.mkdir(RAW_STORE_DIR, { recursive: true });

    const rawDb = new Database(DB_FILE);
    rawDb.exec(`
      CREATE TABLE IF NOT EXISTS merkle_chunks (
        chunk_id TEXT PRIMARY KEY, event_count INTEGER NOT NULL,
        merkle_root_hash TEXT NOT NULL, batch_opened_at TEXT NOT NULL,
        batch_closed_at TEXT NOT NULL, chain_tx_hash TEXT,
        anchor_status TEXT NOT NULL DEFAULT 'pending', anchored_at TEXT
      );
      CREATE TABLE IF NOT EXISTS raw_events (
        lineage_id TEXT PRIMARY KEY, sha256_hash TEXT NOT NULL,
        ingestion_timestamp TEXT NOT NULL, source_ip TEXT NOT NULL,
        source_port INTEGER NOT NULL, transport_protocol TEXT NOT NULL,
        char_encoding TEXT NOT NULL, raw_size_bytes INTEGER NOT NULL,
        storage_pointer TEXT NOT NULL, chunk_id TEXT, merkle_leaf_index INTEGER, created_at TEXT NOT NULL
      );
    `);

    db = new SqliteIntegrityRepository(rawDb);
    ledger = new FileLedger({
      filePath: LEDGER_FILE,
      privateKey: loadPrivateKey(PRIV_KEY),
      publicKey: loadPublicKey(PUB_KEY),
    });

    anchorSvc = new AnchorService({ ledger, db });
    verifier = new DeepVerifier({ rawStoreDir: RAW_STORE_DIR, ledger, db });
  });

  afterEach(async () => {
    db.close();
    await fs.rm(TEST_DIR, { recursive: true, force: true });
  });

  async function createChunkOnDisk(chunkId: string, payloads: string[]): Promise<MerkleLeaf[]> {
    const leaves: MerkleLeaf[] = [];
    const buffers: Buffer[] = [];
    const entries: Record<string, any> = {};

    let currentOffset = 0;
    for (let i = 0; i < payloads.length; i++) {
      const p = payloads[i]!;
      const buf = Buffer.from(p, "utf-8");
      buffers.push(buf);

      const crypto = await import("node:crypto");
      const hash = crypto.createHash("sha256").update(buf).digest("hex");
      const lineageId = `leaf-uuid-${chunkId}-${i}`;

      entries[`offset_${i}`] = {
        offset: currentOffset,
        length: buf.length,
        sha256_hash: hash,
        lineage_id: lineageId,
      };

      leaves.push({
        lineage_id: lineageId,
        sha256_hash: hash,
        ingestion_timestamp: new Date().toISOString(),
      });

      currentOffset += buf.length;
    }

    const uncompressed = Buffer.concat(buffers);
    const compressed = await compressZstd(uncompressed);

    await fs.writeFile(join(RAW_STORE_DIR, `${chunkId}.zst`), Buffer.from(compressed));
    await fs.writeFile(
      join(RAW_STORE_DIR, `${chunkId}.idx.json`),
      JSON.stringify({ chunk_id: chunkId, event_count: payloads.length, entries }, null, 2),
      "utf-8"
    );

    return leaves;
  }

  it("passes deep verification on clean chunks", async () => {
    const chunkId = "chunk_clean_01";
    const leaves = await createChunkOnDisk(chunkId, [
      "2026-09-26T12:00:00Z fw1 Deny tcp",
      "2026-09-26T12:00:01Z fw1 Allow udp",
      "2026-09-26T12:00:02Z fw1 Deny icmp",
    ]);

    anchorSvc.anchorChunk({ chunk_id: chunkId, leaves });

    const result = await verifier.verifyChunkDeep(chunkId);
    expect(result.verified).toBe(true);
    expect(result.merkle_root_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(result.event_count).toBe(3);
    expect(result.ledger_sequence).toBe(0);
  });

  it("tamper drill: fails deep verify, isolates altered leaf, and untouched chunk still verifies (negative control)", async () => {
    // 1. Create Chunk A (will be tampered)
    const chunkA = "chunk_drill_A";
    const leavesA = await createChunkOnDisk(chunkA, [
      "Chunk A Log 0 — legitimate log line",
      "Chunk A Log 1 — target for tamper drill",
      "Chunk A Log 2 — legitimate log line",
    ]);
    anchorSvc.anchorChunk({ chunk_id: chunkA, leaves: leavesA });

    // 2. Create Chunk B (negative control — remains untouched)
    const chunkB = "chunk_drill_B";
    const leavesB = await createChunkOnDisk(chunkB, [
      "Chunk B Log 0 — untouched clean event",
      "Chunk B Log 1 — untouched clean event",
    ]);
    anchorSvc.anchorChunk({ chunk_id: chunkB, leaves: leavesB });

    // Verify both are initially clean
    expect((await verifier.verifyChunkDeep(chunkA)).verified).toBe(true);
    expect((await verifier.verifyChunkDeep(chunkB)).verified).toBe(true);

    // 3. Execute Tamper Drill: Alter 1 byte in Chunk A's raw store file
    const drillResult = await TamperDrill.tamperRawChunkByte({
      rawStoreDir: RAW_STORE_DIR,
      chunkId: chunkA,
      targetOffsetKey: "offset_1",
    });

    expect(drillResult.altered_leaf).toBe(`leaf-uuid-${chunkA}-1`);

    // 4. Verify Chunk A fails and accurately isolates the altered leaf
    const checkA = await verifier.verifyChunkDeep(chunkA);
    expect(checkA.verified).toBe(false);
    expect(checkA.altered_leaf).toBe(drillResult.altered_leaf);
    expect(checkA.error).toContain("Content seal mismatch");

    // 5. Negative control: Chunk B MUST still verify successfully
    const checkB = await verifier.verifyChunkDeep(chunkB);
    expect(checkB.verified).toBe(true);
  });
});
