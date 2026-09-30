export interface MerkleLeaf {
  lineage_id: string;
  sha256_hash: string;
  ingestion_timestamp: string;
}

export interface SiblingProof {
  position: "left" | "right";
  hash: string;
}

export interface MerkleProof {
  lineage_id: string;
  leaf_hash: string;
  leaf_index: number;
  root_hash: string;
  siblings: SiblingProof[];
}

export interface LedgerEntry {
  sequence: number;
  prev_hash: string;
  chunk_id: string;
  event_count: number;
  merkle_root_hash: string;
  timestamp: string;
  signer_key_id: string;
  entry_hash: string;
  signature: string;
}

export interface DeepVerificationResult {
  verified: boolean;
  chunk_id: string;
  merkle_root_hash: string;
  event_count: number;
  ledger_sequence?: number;
  ledger_entry_hash?: string;
  altered_leaf?: string;
  error?: string;
}
