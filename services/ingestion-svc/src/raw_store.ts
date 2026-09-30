import { promises as fs } from "node:fs";
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
// @ts-expect-error zstd-codec lacks ts types
import { ZstdCodec } from "zstd-codec";
import type { RawStoreInterface, IngestEnvelope, ChunkIndex } from "./types.js";

let zstdSimplePromise: Promise<any> | null = null;

export function getZstdSimple(): Promise<any> {
  if (!zstdSimplePromise) {
    zstdSimplePromise = new Promise((resolve) => {
      ZstdCodec.run((zstd: any) => {
        resolve(new zstd.Simple());
      });
    });
  }
  return zstdSimplePromise;
}

export class FileSystemRawStore implements RawStoreInterface {
  private baseDir: string;

  constructor(baseDir: string) {
    this.baseDir = baseDir;
    if (!existsSync(this.baseDir)) {
      mkdirSync(this.baseDir, { recursive: true });
    }
  }

  async writeChunk(chunkId: string, events: IngestEnvelope[]): Promise<{ chunk_id: string; storage_pointers: string[] }> {
    const simple = await getZstdSimple();
    const buffers: Buffer[] = [];
    const entries: Record<string, { offset: number; length: number; sha256_hash: string; lineage_id: string }> = {};
    const storage_pointers: string[] = [];

    let currentOffset = 0;
    for (let i = 0; i < events.length; i++) {
      const ev = events[i];
      if (!ev) continue;
      const buf = ev.raw_bytes;
      buffers.push(buf);

      const offsetKey = `offset_${i}`;
      entries[offsetKey] = {
        offset: currentOffset,
        length: buf.length,
        sha256_hash: ev.sha256_hash,
        lineage_id: ev.lineage_id,
      };
      const pointer = `raw_store://${chunkId}/${offsetKey}`;
      storage_pointers.push(pointer);
      currentOffset += buf.length;
    }

    const uncompressedData = Buffer.concat(buffers);
    const compressedData = simple.compress(uncompressedData);

    const chunkFilePath = join(this.baseDir, `${chunkId}.zst`);
    const indexFilePath = join(this.baseDir, `${chunkId}.idx.json`);

    const indexContent: ChunkIndex = {
      chunk_id: chunkId,
      event_count: events.length,
      entries,
    };

    await fs.writeFile(chunkFilePath, Buffer.from(compressedData));
    await fs.writeFile(indexFilePath, JSON.stringify(indexContent, null, 2), "utf-8");

    return { chunk_id: chunkId, storage_pointers };
  }

  async readRawBytes(storagePointer: string): Promise<Buffer> {
    const match = storagePointer.match(/^raw_store:\/\/([^/]+)\/(offset_\d+)$/);
    if (!match || !match[1] || !match[2]) {
      throw new Error(`Invalid storage pointer format: ${storagePointer}`);
    }
    const chunkId = match[1];
    const offsetKey = match[2];

    const chunkFilePath = join(this.baseDir, `${chunkId}.zst`);
    const indexFilePath = join(this.baseDir, `${chunkId}.idx.json`);

    const [compressedBuf, indexJson] = await Promise.all([
      fs.readFile(chunkFilePath),
      fs.readFile(indexFilePath, "utf-8"),
    ]);

    const index: ChunkIndex = JSON.parse(indexJson);
    const entry = index.entries[offsetKey];
    if (!entry) {
      throw new Error(`Offset ${offsetKey} not found in index for chunk ${chunkId}`);
    }

    const simple = await getZstdSimple();
    const decompressed = simple.decompress(new Uint8Array(compressedBuf));
    const fullBuffer = Buffer.from(decompressed);

    const rawBytes = fullBuffer.subarray(entry.offset, entry.offset + entry.length);

    // Byte fidelity check: content seal must match
    const computedHash = createHash("sha256").update(rawBytes).digest("hex");
    if (computedHash !== entry.sha256_hash) {
      throw new Error(`Data corruption detected: expected ${entry.sha256_hash} but got ${computedHash}`);
    }

    return rawBytes;
  }
}
