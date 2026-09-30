import type { RawIngestV1, MerkleLeafV1 } from "@ulpf/contracts";

export type TransportProtocol = "UDP" | "TCP" | "TLS" | "HTTP";

export interface IngestEnvelope {
  lineage_id: string;
  sha256_hash: string;
  ingestion_timestamp: string;
  source_ip: string;
  source_port: number;
  transport_protocol: TransportProtocol;
  char_encoding: string;
  raw_size_bytes: number;
  raw_bytes: Buffer;
  storage_pointer?: string;
  chunk_id?: string;
  merkle_leaf_index?: number;
}

export interface ChunkIndexEntry {
  offset: number;
  length: number;
  sha256_hash: string;
  lineage_id: string;
}

export interface ChunkIndex {
  chunk_id: string;
  event_count: number;
  entries: Record<string, ChunkIndexEntry>;
}

export interface RawStoreInterface {
  writeChunk(chunkId: string, events: IngestEnvelope[]): Promise<{ chunk_id: string; storage_pointers: string[] }>;
  readRawBytes(storagePointer: string): Promise<Buffer>;
}

export interface BusInterface {
  publish(topic: string, message: unknown): Promise<void>;
  subscribe(topic: string, consumerGroup: string, handler: (msg: unknown) => Promise<void> | void): void;
  getHistory(topic: string): unknown[];
}

export interface DbRepositoryInterface {
  insertRawEvents(events: IngestEnvelope[]): void;
  getRawEvent(lineageId: string): unknown | null;
  countRawEvents(): number;
  close(): void;
  isHealthy(): boolean;
}

export interface SpoolInterface {
  spool(events: IngestEnvelope[]): void;
  flush(db: DbRepositoryInterface): number;
  getPendingCount(): number;
}

export interface BatcherConfig {
  maxEventCount: number;
  maxTimeMs: number;
  maxInlineBytes?: number;
}
