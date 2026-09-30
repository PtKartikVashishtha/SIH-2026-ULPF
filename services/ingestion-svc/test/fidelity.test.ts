import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { FileSystemRawStore } from "../src/raw_store.js";
import { createIngestionEnvelope } from "../src/envelope.js";
import type { IngestEnvelope } from "../src/types.js";

const TEST_DIR = join(process.cwd(), "test-tmp-fidelity");

describe("M1 Acceptance Criterion: Byte-for-Byte Fidelity", () => {
  let store: FileSystemRawStore;

  beforeEach(async () => {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
    store = new FileSystemRawStore(TEST_DIR);
  });

  afterEach(async () => {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
  });

  it("preserves exact bytes across write, zstd compression, and retrieval for diverse payloads", async () => {
    const testCases: Buffer[] = [
      Buffer.from("Simple ASCII log: Jun 14 15:16:01 host sshd[123]: Accepted publickey"),
      Buffer.from("<134>1 2026-09-26T12:00:00.123456Z fw-01 %ASA-4-106023: Deny tcp src outside:192.0.2.1/54321"),
      Buffer.from("UTF-8 text with symbols: 🚀 Firewall Event: Prüfprotokoll № 42 § 9.1 🔥"),
      Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd, 0x80, 0x7f, 0x00]), // Binary bytes
      Buffer.alloc(16 * 1024, "A"), // 16KB repeated pattern
      Buffer.from(""), // Empty payload
    ];

    const envelopes: IngestEnvelope[] = testCases.map((buf) => createIngestionEnvelope(buf));

    const { storage_pointers } = await store.writeChunk("chunk_20260926_01", envelopes);
    expect(storage_pointers).toHaveLength(testCases.length);

    for (let i = 0; i < testCases.length; i++) {
      const original = testCases[i]!;
      const pointer = storage_pointers[i]!;
      const retrieved = await store.readRawBytes(pointer);

      // 1. Exact buffer equality (byte-for-byte fidelity)
      expect(Buffer.compare(original, retrieved)).toBe(0);

      // 2. Hash verification
      const expectedHash = createHash("sha256").update(original).digest("hex");
      const actualHash = createHash("sha256").update(retrieved).digest("hex");
      expect(actualHash).toBe(expectedHash);
    }
  });
});
