import { sha256 } from "./crypto.js";
import type { MerkleLeaf, MerkleProof, SiblingProof } from "./types.js";

const DOMAIN_LEAF = Buffer.from([0x00]);
const DOMAIN_INTERNAL = Buffer.from([0x01]);

export function hashLeaf(contentSha256: string): string {
  const buf = Buffer.concat([DOMAIN_LEAF, Buffer.from(contentSha256, "hex")]);
  return sha256(buf);
}

export function hashInternal(leftHex: string, rightHex: string): string {
  const buf = Buffer.concat([
    DOMAIN_INTERNAL,
    Buffer.from(leftHex, "hex"),
    Buffer.from(rightHex, "hex"),
  ]);
  return sha256(buf);
}

export class MerkleTree {
  public leaves: MerkleLeaf[];
  public levels: string[][] = [];
  public root: string;

  constructor(leaves: MerkleLeaf[]) {
    // Spec Requirement: Deterministic leaf ordering by lineage_id
    // This ensures deterministic root regardless of leaf-arrival order
    this.leaves = [...leaves].sort((a, b) => a.lineage_id.localeCompare(b.lineage_id));

    if (this.leaves.length === 0) {
      this.root = "0".repeat(64);
      this.levels = [[]];
      return;
    }

    // 1. Compute leaf hashes with domain separation (0x00)
    let currentLevel = this.leaves.map((l) => hashLeaf(l.sha256_hash));
    this.levels.push([...currentLevel]);

    // 2. Build tree upwards with spec padding rule
    while (currentLevel.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        if (!left) continue;

        // Spec Padding Rule: If odd number of nodes at this level, duplicate the last node
        const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
        if (!right) continue;

        nextLevel.push(hashInternal(left, right));
      }
      this.levels.push(nextLevel);
      currentLevel = nextLevel;
    }

    const topLevel = this.levels[this.levels.length - 1];
    this.root = topLevel && topLevel[0] ? topLevel[0] : "0".repeat(64);
  }

  getProof(lineageId: string): MerkleProof | null {
    const leafIndex = this.leaves.findIndex((l) => l.lineage_id === lineageId);
    if (leafIndex === -1) return null;

    const targetLeaf = this.leaves[leafIndex];
    if (!targetLeaf) return null;

    const siblings: SiblingProof[] = [];
    let idx = leafIndex;

    for (let levelIdx = 0; levelIdx < this.levels.length - 1; levelIdx++) {
      const level = this.levels[levelIdx];
      if (!level) break;

      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;

      let siblingHash: string;
      if (siblingIdx < level.length) {
        siblingHash = level[siblingIdx] ?? level[idx]!;
      } else {
        // Spec padding rule: duplicated self
        siblingHash = level[idx]!;
      }

      siblings.push({
        position: isRight ? "left" : "right",
        hash: siblingHash,
      });

      idx = Math.floor(idx / 2);
    }

    return {
      lineage_id: targetLeaf.lineage_id,
      leaf_hash: hashLeaf(targetLeaf.sha256_hash),
      leaf_index: leafIndex,
      root_hash: this.root,
      siblings,
    };
  }

  static verifyProof(proof: MerkleProof): boolean {
    let currentHash = proof.leaf_hash;

    for (const sibling of proof.siblings) {
      if (sibling.position === "left") {
        currentHash = hashInternal(sibling.hash, currentHash);
      } else {
        currentHash = hashInternal(currentHash, sibling.hash);
      }
    }

    return currentHash === proof.root_hash;
  }
}
