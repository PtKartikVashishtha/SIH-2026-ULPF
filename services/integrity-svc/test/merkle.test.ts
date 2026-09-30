import { describe, it, expect } from "vitest";
import { MerkleTree, hashLeaf, hashInternal } from "../src/merkle.js";
import type { MerkleLeaf } from "../src/types.js";

describe("M2 Acceptance Criterion: Deterministic Root & Sibling-Hash Proofs", () => {
  const leaves: MerkleLeaf[] = [
    { lineage_id: "00000000-0000-4000-a000-000000000001", sha256_hash: "11".repeat(32), ingestion_timestamp: "2026-09-26T12:00:00Z" },
    { lineage_id: "00000000-0000-4000-a000-000000000002", sha256_hash: "22".repeat(32), ingestion_timestamp: "2026-09-26T12:00:01Z" },
    { lineage_id: "00000000-0000-4000-a000-000000000003", sha256_hash: "33".repeat(32), ingestion_timestamp: "2026-09-26T12:00:02Z" },
    { lineage_id: "00000000-0000-4000-a000-000000000004", sha256_hash: "44".repeat(32), ingestion_timestamp: "2026-09-26T12:00:03Z" },
    { lineage_id: "00000000-0000-4000-a000-000000000005", sha256_hash: "55".repeat(32), ingestion_timestamp: "2026-09-26T12:00:04Z" },
  ];

  it("produces deterministic root regardless of leaf-arrival order", () => {
    // Permutation 1: forward order
    const tree1 = new MerkleTree(leaves);

    // Permutation 2: reverse order
    const tree2 = new MerkleTree([...leaves].reverse());

    // Permutation 3: shuffled order
    const tree3 = new MerkleTree([leaves[3]!, leaves[0]!, leaves[4]!, leaves[1]!, leaves[2]!]);

    expect(tree1.root).toMatch(/^[0-9a-f]{64}$/);
    expect(tree2.root).toBe(tree1.root);
    expect(tree3.root).toBe(tree1.root);
  });

  it("handles spec padding rule correctly when leaf count is odd", () => {
    // 3 leaves -> level 1 has 3 hashes, pair 0+1 and pair 2+2 (duplicated)
    const oddLeaves = leaves.slice(0, 3);
    const tree = new MerkleTree(oddLeaves);

    const h0 = hashLeaf(oddLeaves[0]!.sha256_hash);
    const h1 = hashLeaf(oddLeaves[1]!.sha256_hash);
    const h2 = hashLeaf(oddLeaves[2]!.sha256_hash);

    const parent01 = hashInternal(h0, h1);
    const parent22 = hashInternal(h2, h2); // duplicated last node
    const expectedRoot = hashInternal(parent01, parent22);

    expect(tree.root).toBe(expectedRoot);
  });

  it("generates and verifies single-lineage sibling-hash proofs for all leaves", () => {
    const tree = new MerkleTree(leaves);

    for (const leaf of leaves) {
      const proof = tree.getProof(leaf.lineage_id);
      expect(proof).not.toBeNull();
      expect(proof!.root_hash).toBe(tree.root);

      // Verification of valid proof
      const isValid = MerkleTree.verifyProof(proof!);
      expect(isValid).toBe(true);

      // Negative control: tamper with leaf_hash -> proof fails
      const tamperedProof = { ...proof!, leaf_hash: "0".repeat(64) };
      expect(MerkleTree.verifyProof(tamperedProof)).toBe(false);
    }
  });
});
