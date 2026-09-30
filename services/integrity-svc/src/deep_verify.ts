import { promises as fs } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
// @ts-expect-error zstd-codec lacks ts types
import { ZstdCodec } from "zstd-codec";
import { MerkleTree } from "./merkle.js";
import { FileLedger } from "./ledger.js";
import { SqliteIntegrityRepository } from "./db.js";
import type { DeepVerificationResult, MerkleLeaf } from "./types.js";

let zstdSimplePromise: Promise<any> | null = null;
function getZstd(): Promise<any> {
  if (!zstdSimplePromise) {
    zstdSimplePromise = new Promise((resolve) => {
      ZstdCodec.run((zstd: any) => resolve(new zstd.Simple()));
    });
  }
  return zstdSimplePromise;
}

export class DeepVerifier {
  private rawStoreDir: string;
  private ledger: FileLedger;
  private db: SqliteIntegrityRepository;

  constructor(options: {
    rawStoreDir: string;
    ledger: FileLedger;
    db: SqliteIntegrityRepository;
  }) {
    this.rawStoreDir = options.rawStoreDir;
    this.ledger = options.ledger;
    this.db = options.db;
  }

  async verifyChunkDeep(chunkId: string): Promise<DeepVerificationResult> {
    // 1. Verify ledger integrity first
    const chainCheck = this.ledger.verifyChain();
    if (!chainCheck.valid) {
      return {
        verified: false,
        chunk_id: chunkId,
        merkle_root_hash: "",
        event_count: 0,
        error: `Ledger chain invalid: ${chainCheck.error}`,
      };
    }

    const ledgerEntries = this.ledger.getEntries();
    const ledgerEntry = ledgerEntries.find((e) => e.chunk_id === chunkId);
    if (!ledgerEntry) {
      return {
        verified: false,
        chunk_id: chunkId,
        merkle_root_hash: "",
        event_count: 0,
        error: `Chunk ${chunkId} not found in signed ledger`,
      };
    }

    // 2. Read raw store chunk compressed file and index
    const chunkPath = join(this.rawStoreDir, `${chunkId}.zst`);
    const indexPath = join(this.rawStoreDir, `${chunkId}.idx.json`);

    try {
      await fs.access(chunkPath);
      await fs.access(indexPath);
    } catch {
      return {
        verified: false,
        chunk_id: chunkId,
        merkle_root_hash: ledgerEntry.merkle_root_hash,
        event_count: ledgerEntry.event_count,
        error: `Raw store files missing for chunk ${chunkId}`,
      };
    }

    const [compressedBuf, indexStr] = await Promise.all([
      fs.readFile(chunkPath),
      fs.readFile(indexPath, "utf-8"),
    ]);

    const index = JSON.parse(indexStr);
    const zstd = await getZstd();
    let decompressed: Uint8Array;
    try {
      decompressed = zstd.decompress(new Uint8Array(compressedBuf));
    } catch (err: any) {
      return {
        verified: false,
        chunk_id: chunkId,
        merkle_root_hash: ledgerEntry.merkle_root_hash,
        event_count: ledgerEntry.event_count,
        error: `Zstandard chunk decompression failed: ${err.message}`,
      };
    }

    const fullBuffer = Buffer.from(decompressed);

    // 3. Deep re-hash: recompute SHA-256 of every single slice from raw disk bytes
    const recomputedLeaves: MerkleLeaf[] = [];

    const entriesArray: Array<[string, any]> = Object.entries(index.entries);
    for (const [offsetKey, entry] of entriesArray) {
      const slice = fullBuffer.subarray(entry.offset, entry.offset + entry.length);
      const computedHash = createHash("sha256").update(slice).digest("hex");

      // Bit-for-bit check
      if (computedHash !== entry.sha256_hash) {
        // Tamper detected! Isolate altered leaf
        return {
          verified: false,
          chunk_id: chunkId,
          merkle_root_hash: ledgerEntry.merkle_root_hash,
          event_count: ledgerEntry.event_count,
          altered_leaf: entry.lineage_id,
          error: `Deep verification failed: Content seal mismatch on leaf ${entry.lineage_id} (${offsetKey}). Expected ${entry.sha256_hash}, recomputed ${computedHash}`,
        };
      }

      recomputedLeaves.push({
        lineage_id: entry.lineage_id,
        sha256_hash: computedHash,
        ingestion_timestamp: "",
      });
    }

    // 4. Reconstruct Merkle tree from independently re-hashed raw bytes
    const tree = new MerkleTree(recomputedLeaves);

    if (tree.root !== ledgerEntry.merkle_root_hash) {
      return {
        verified: false,
        chunk_id: chunkId,
        merkle_root_hash: tree.root,
        event_count: recomputedLeaves.length,
        error: `Recomputed Merkle root ${tree.root} does not match ledger root ${ledgerEntry.merkle_root_hash}`,
      };
    }

    return {
      verified: true,
      chunk_id: chunkId,
      merkle_root_hash: tree.root,
      event_count: recomputedLeaves.length,
      ledger_sequence: ledgerEntry.sequence,
      ledger_entry_hash: ledgerEntry.entry_hash,
    };
  }
}
