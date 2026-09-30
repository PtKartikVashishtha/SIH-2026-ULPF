import type {
  BatcherConfig,
  IngestEnvelope,
  RawStoreInterface,
  DbRepositoryInterface,
  SpoolInterface,
  BusInterface,
} from "./types.js";
import type { RawIngestV1, MerkleLeafV1 } from "@ulpf/contracts";

export class DualTriggerBatcher {
  private config: BatcherConfig;
  private rawStore: RawStoreInterface;
  private db: DbRepositoryInterface;
  private spool: SpoolInterface;
  private bus: BusInterface;

  private pendingEvents: IngestEnvelope[] = [];
  private timer: NodeJS.Timeout | null = null;
  private chunkSequence = 1;

  constructor(options: {
    config: BatcherConfig;
    rawStore: RawStoreInterface;
    db: DbRepositoryInterface;
    spool: SpoolInterface;
    bus: BusInterface;
  }) {
    this.config = options.config;
    this.rawStore = options.rawStore;
    this.db = options.db;
    this.spool = options.spool;
    this.bus = options.bus;
  }

  async add(event: IngestEnvelope): Promise<void> {
    this.pendingEvents.push(event);

    // If first event in batch, arm time trigger
    if (this.pendingEvents.length === 1 && !this.timer) {
      this.timer = setTimeout(() => {
        this.closeBatch("TIME_TRIGGER").catch(console.error);
      }, this.config.maxTimeMs);
    }

    // Check count trigger
    if (this.pendingEvents.length >= this.config.maxEventCount) {
      await this.closeBatch("COUNT_TRIGGER");
    }
  }

  async flush(): Promise<void> {
    if (this.pendingEvents.length > 0) {
      await this.closeBatch("MANUAL_FLUSH");
    }
  }

  async closeBatch(triggerReason: string = "UNKNOWN"): Promise<{ chunk_id: string; count: number } | null> {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    if (this.pendingEvents.length === 0) return null;

    // Grab current batch
    const batch = [...this.pendingEvents];
    this.pendingEvents = [];

    // Format chunk ID: chunk_<yyyyMMdd>_<sequence>
    const now = new Date();
    const dateStr = now.toISOString().slice(0, 10).replace(/-/g, "");
    const seqStr = String(this.chunkSequence++).padStart(2, "0");
    const chunkId = `chunk_${dateStr}_${seqStr}`;

    // 1. Write chunk to raw store
    const { storage_pointers } = await this.rawStore.writeChunk(chunkId, batch);

    // 2. Assign storage pointers and indexes to events
    for (let i = 0; i < batch.length; i++) {
      const item = batch[i];
      if (item && storage_pointers[i] !== undefined) {
        item.storage_pointer = storage_pointers[i];
        item.chunk_id = chunkId;
        item.merkle_leaf_index = i;
      }
    }

    // 3. Write to DB or Durable Spool if DB fails
    try {
      this.db.insertRawEvents(batch);
      // If DB is healthy, attempt to drain any previous spooled items
      this.spool.flush(this.db);
    } catch {
      // DB write failed — divert to durable spool
      this.spool.spool(batch);
    }

    // 4. Publish to Bus
    const maxInline = this.config.maxInlineBytes ?? 65536;
    for (const ev of batch) {
      const rawIngestMsg: RawIngestV1 = {
        lineage_id: ev.lineage_id,
        raw_bytes_b64: ev.raw_size_bytes <= maxInline ? ev.raw_bytes.toString("base64") : null,
        storage_pointer: ev.storage_pointer!,
        sha256_hash: ev.sha256_hash,
        ingestion_timestamp: ev.ingestion_timestamp,
        source_ip: ev.source_ip,
        source_port: ev.source_port,
        transport_protocol: ev.transport_protocol,
        char_encoding: ev.char_encoding,
      };

      const merkleLeafMsg: MerkleLeafV1 = {
        lineage_id: ev.lineage_id,
        sha256_hash: ev.sha256_hash,
        ingestion_timestamp: ev.ingestion_timestamp,
      };

      await this.bus.publish("ulpf.raw.ingest.v1", rawIngestMsg);
      await this.bus.publish("ulpf.merkle.leaf.v1", merkleLeafMsg);
    }

    return { chunk_id: chunkId, count: batch.length };
  }

  getPendingCount(): number {
    return this.pendingEvents.length;
  }
}
