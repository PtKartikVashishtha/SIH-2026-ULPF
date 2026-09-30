import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { createIngestionEnvelope } from "../src/envelope.js";

describe("M1 Acceptance Criterion: Lineage ID Uniqueness & Content Seal", () => {
  it("N identical payloads produce N distinct lineage_ids with matching sha256 hashes", () => {
    const N = 100;
    const identicalPayload = Buffer.from("<134>1 2026-09-26T12:00:00Z fw-01 %ASA-4-106023: Deny tcp src 10.1.1.1 dst 8.8.8.8");
    const expectedSha256 = createHash("sha256").update(identicalPayload).digest("hex");

    const envelopes = Array.from({ length: N }, () => createIngestionEnvelope(identicalPayload));

    // 1. All lineage_ids must be unique
    const lineageIds = new Set(envelopes.map((e) => e.lineage_id));
    expect(lineageIds.size).toBe(N);

    // 2. Every lineage_id must be a valid UUIDv4
    const uuidv4Regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    for (const env of envelopes) {
      expect(env.lineage_id).toMatch(uuidv4Regex);
    }

    // 3. Independently recomputed SHA-256 matches for every single envelope
    for (const env of envelopes) {
      expect(env.sha256_hash).toBe(expectedSha256);
      const independentlyComputed = createHash("sha256").update(env.raw_bytes).digest("hex");
      expect(independentlyComputed).toBe(env.sha256_hash);
    }
  });
});
