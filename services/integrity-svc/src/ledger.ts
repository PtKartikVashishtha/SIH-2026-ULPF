import { readFileSync, appendFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { KeyObject } from "node:crypto";
import { sha256, signData, verifySignature } from "./crypto.js";
import type { LedgerEntry } from "./types.js";

export class FileLedger {
  private filePath: string;
  private privateKey: KeyObject;
  private publicKey: KeyObject;
  private signerKeyId: string;

  constructor(options: {
    filePath: string;
    privateKey: KeyObject;
    publicKey: KeyObject;
    signerKeyId?: string;
  }) {
    this.filePath = options.filePath;
    this.privateKey = options.privateKey;
    this.publicKey = options.publicKey;
    this.signerKeyId = options.signerKeyId ?? "dev_signing";

    const dir = dirname(this.filePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }

  getEntries(): LedgerEntry[] {
    if (!existsSync(this.filePath)) return [];
    const content = readFileSync(this.filePath, "utf-8").trim();
    if (!content) return [];
    return content.split("\n").filter(Boolean).map((line) => JSON.parse(line));
  }

  appendEntry(params: {
    chunk_id: string;
    merkle_root_hash: string;
    event_count: number;
    timestamp?: string;
  }): LedgerEntry {
    const entries = this.getEntries();
    const sequence = entries.length;
    const lastEntry = entries[entries.length - 1];
    const prev_hash = lastEntry ? lastEntry.entry_hash : "0".repeat(64);
    const timestamp = params.timestamp ?? new Date().toISOString();

    // Canonical representation for hash calculation
    const payloadToHash = JSON.stringify({
      chunk_id: params.chunk_id,
      event_count: params.event_count,
      merkle_root_hash: params.merkle_root_hash,
      prev_hash,
      sequence,
      signer_key_id: this.signerKeyId,
      timestamp,
    });

    const entry_hash = sha256(payloadToHash);
    const signature = signData(entry_hash, this.privateKey);

    const entry: LedgerEntry = {
      sequence,
      prev_hash,
      chunk_id: params.chunk_id,
      event_count: params.event_count,
      merkle_root_hash: params.merkle_root_hash,
      timestamp,
      signer_key_id: this.signerKeyId,
      entry_hash,
      signature,
    };

    appendFileSync(this.filePath, JSON.stringify(entry) + "\n", "utf-8");
    return entry;
  }

  verifyChain(): { valid: boolean; error?: string; brokenIndex?: number } {
    const entries = this.getEntries();
    if (entries.length === 0) return { valid: true };

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      if (!entry) continue;

      // 1. Sequence must be contiguous
      if (entry.sequence !== i) {
        return {
          valid: false,
          brokenIndex: i,
          error: `Invalid sequence at index ${i}: expected ${i}, got ${entry.sequence}`,
        };
      }

      // 2. Genesis prev_hash or chain hash match
      const expectedPrevHash = i === 0 ? "0".repeat(64) : entries[i - 1]!.entry_hash;
      if (entry.prev_hash !== expectedPrevHash) {
        return {
          valid: false,
          brokenIndex: i,
          error: `Broken chain hash at index ${i}: expected prev_hash ${expectedPrevHash}, got ${entry.prev_hash}`,
        };
      }

      // 3. Recompute entry hash
      const payloadToHash = JSON.stringify({
        chunk_id: entry.chunk_id,
        event_count: entry.event_count,
        merkle_root_hash: entry.merkle_root_hash,
        prev_hash: entry.prev_hash,
        sequence: entry.sequence,
        signer_key_id: entry.signer_key_id,
        timestamp: entry.timestamp,
      });
      const expectedEntryHash = sha256(payloadToHash);
      if (entry.entry_hash !== expectedEntryHash) {
        return {
          valid: false,
          brokenIndex: i,
          error: `Entry hash mismatch at index ${i}: recomputed ${expectedEntryHash}, recorded ${entry.entry_hash}`,
        };
      }

      // 4. Verify Ed25519 signature
      const sigValid = verifySignature(entry.entry_hash, entry.signature, this.publicKey);
      if (!sigValid) {
        return {
          valid: false,
          brokenIndex: i,
          error: `Invalid cryptographic signature at index ${i}`,
        };
      }
    }

    return { valid: true };
  }
}
