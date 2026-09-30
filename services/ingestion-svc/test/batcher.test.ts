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
import type { RawIngestV1, MerkleLeafV1 } from "@ulpf/contracts";

const TEST_DIR = join(process.cwd(), "test-tmp-batcher");

describe("M1 Acceptance Criterion: Dual-Trigger Batching", () => {
  let rawStore: FileSystemRawStore;
  let db: SqliteRawEventsRepository;
  let spool: DiskSpool;
  let bus: LocalEventBus;

  beforeEach(async () => {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
    await fs.mkdir(TEST_DIR, { recursive: true });

    rawStore = new FileSystemRawStore(join(TEST_DIR, "raw_store"));
    db = new SqliteRawEventsRepository(new Database(":memory:"));
    spool = new DiskSpool(join(TEST_DIR, "spool"));
    bus = new LocalEventBus();
  });

  afterEach(async () => {
    db.close();
    await fs.rm(TEST_DIR, { recursive: true, force: true });
  });

  it("closes batch immediately upon reaching count threshold (COUNT_TRIGGER)", async () => {
    const batcher = new DualTriggerBatcher({
      config: { maxEventCount: 3, maxTimeMs: 10000 },
      rawStore,
      db,
      spool,
      bus,
    });

    // Add 2 events — batch should still be open
    await batcher.add(createIngestionEnvelope(Buffer.from("event-1")));
    await batcher.add(createIngestionEnvelope(Buffer.from("event-2")));
    expect(batcher.getPendingCount()).toBe(2);
    expect(db.countRawEvents()).toBe(0);

    // Add 3rd event — count threshold reached (3), triggers immediate close
    await batcher.add(createIngestionEnvelope(Buffer.from("event-3")));
    expect(batcher.getPendingCount()).toBe(0);
    expect(db.countRawEvents()).toBe(3);

    // Verify bus messages published
    const rawIngestMsgs = bus.getHistory("ulpf.raw.ingest.v1") as RawIngestV1[];
    const merkleLeafMsgs = bus.getHistory("ulpf.merkle.leaf.v1") as MerkleLeafV1[];

    expect(rawIngestMsgs).toHaveLength(3);
    expect(merkleLeafMsgs).toHaveLength(3);

    // Verify storage pointers
    expect(rawIngestMsgs[0]!.storage_pointer).toMatch(/^raw_store:\/\/chunk_\d{8}_\d{2}\/offset_0$/);
    expect(rawIngestMsgs[1]!.storage_pointer).toMatch(/^raw_store:\/\/chunk_\d{8}_\d{2}\/offset_1$/);
    expect(rawIngestMsgs[2]!.storage_pointer).toMatch(/^raw_store:\/\/chunk_\d{8}_\d{2}\/offset_2$/);
  });

  it("closes batch when time window expires (TIME_TRIGGER)", async () => {
    const batcher = new DualTriggerBatcher({
      config: { maxEventCount: 100, maxTimeMs: 150 },
      rawStore,
      db,
      spool,
      bus,
    });

    // Add 2 events (far below 100 count)
    await batcher.add(createIngestionEnvelope(Buffer.from("time-event-1")));
    await batcher.add(createIngestionEnvelope(Buffer.from("time-event-2")));
    expect(batcher.getPendingCount()).toBe(2);
    expect(db.countRawEvents()).toBe(0);

    // Wait for the 150ms timer trigger
    await new Promise((resolve) => setTimeout(resolve, 250));

    expect(batcher.getPendingCount()).toBe(0);
    expect(db.countRawEvents()).toBe(2);

    const merkleLeafMsgs = bus.getHistory("ulpf.merkle.leaf.v1") as MerkleLeafV1[];
    expect(merkleLeafMsgs).toHaveLength(2);
  });
});
