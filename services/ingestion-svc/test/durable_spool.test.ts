import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import Database from "better-sqlite3";
import { FileSystemRawStore } from "../src/raw_store.js";
import { SqliteRawEventsRepository } from "../src/db.js";
import { DiskSpool } from "../src/spool.js";
import { LocalEventBus } from "../src/bus.js";
import { DualTriggerBatcher } from "../src/batcher.js";
import { createIngestionEnvelope } from "../src/envelope.js";

const TEST_DIR = join(process.cwd(), "test-tmp-spool");
const DB_FILE = join(TEST_DIR, "test_outage.db");

describe("M1 Acceptance Criterion: Killing and restarting DB mid-run loses nothing", () => {
  beforeEach(async () => {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
    await fs.mkdir(TEST_DIR, { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
  });

  it("diverts to disk spool during DB outage and drains to DB on recovery", async () => {
    const rawStore = new FileSystemRawStore(join(TEST_DIR, "raw_store"));
    const spool = new DiskSpool(join(TEST_DIR, "spool"));
    const bus = new LocalEventBus();

    // 1. Initial healthy state: DB is active
    let db = new SqliteRawEventsRepository(DB_FILE);
    const batcher = new DualTriggerBatcher({
      config: { maxEventCount: 2, maxTimeMs: 5000 },
      rawStore,
      db,
      spool,
      bus,
    });

    const env1 = createIngestionEnvelope(Buffer.from("before-kill-1"));
    const env2 = createIngestionEnvelope(Buffer.from("before-kill-2"));
    await batcher.add(env1);
    await batcher.add(env2); // Triggers batch close -> writes to DB

    expect(db.countRawEvents()).toBe(2);
    expect(spool.getPendingCount()).toBe(0);

    // 2. Kill the database mid-run
    db.close();

    // 3. Ingest more events during DB outage
    const outageEnv1 = createIngestionEnvelope(Buffer.from("during-outage-1"));
    const outageEnv2 = createIngestionEnvelope(Buffer.from("during-outage-2"));
    const outageEnv3 = createIngestionEnvelope(Buffer.from("during-outage-3"));
    const outageEnv4 = createIngestionEnvelope(Buffer.from("during-outage-4"));

    await batcher.add(outageEnv1);
    await batcher.add(outageEnv2); // Batch closes -> DB write fails -> spooled!
    await batcher.add(outageEnv3);
    await batcher.add(outageEnv4); // Batch closes -> spooled!

    // Verify events were durably captured on disk
    expect(spool.getPendingCount()).toBe(4);

    // 4. Restart the database
    db = new SqliteRawEventsRepository(DB_FILE);
    expect(db.countRawEvents()).toBe(2); // Still only the 2 from before outage

    // 5. Drain the durable spool to restored DB
    const flushedCount = spool.flush(db);
    expect(flushedCount).toBe(4);
    expect(spool.getPendingCount()).toBe(0);

    // 6. Verify zero data loss: all 6 events are now stored in DB
    expect(db.countRawEvents()).toBe(6);

    const allIngested = [env1, env2, outageEnv1, outageEnv2, outageEnv3, outageEnv4];
    for (const env of allIngested) {
      const row = db.getRawEvent(env.lineage_id) as any;
      expect(row).toBeDefined();
      expect(row.lineage_id).toBe(env.lineage_id);
      expect(row.sha256_hash).toBe(env.sha256_hash);
      expect(row.storage_pointer).toMatch(/^raw_store:\/\/chunk_\d{8}_\d{2}\/offset_\d+$/);

      // Verify raw store byte fidelity for all events (even those spooled during outage)
      const retrievedBytes = await rawStore.readRawBytes(row.storage_pointer);
      expect(Buffer.compare(env.raw_bytes, retrievedBytes)).toBe(0);
    }

    db.close();
  });
});
