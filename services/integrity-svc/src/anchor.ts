import { MerkleTree } from "./merkle.js";
import { FileLedger } from "./ledger.js";
import { SqliteIntegrityRepository } from "./db.js";
import type { MerkleLeaf } from "./types.js";

export class AnchorService {
  private ledger: FileLedger;
  private db: SqliteIntegrityRepository;

  constructor(options: {
    ledger: FileLedger;
    db: SqliteIntegrityRepository;
  }) {
    this.ledger = options.ledger;
    this.db = options.db;
  }

  anchorChunk(params: {
    chunk_id: string;
    leaves: MerkleLeaf[];
    opened_at?: string;
    closed_at?: string;
  }): {
    chunk_id: string;
    merkle_root_hash: string;
    chain_tx_hash: string;
    event_count: number;
    tree: MerkleTree;
  } {
    const tree = new MerkleTree(params.leaves);
    const now = new Date().toISOString();
    const openedAt = params.opened_at ?? now;
    const closedAt = params.closed_at ?? now;

    // 1. Commit to hash-chained signed ledger
    const ledgerEntry = this.ledger.appendEntry({
      chunk_id: params.chunk_id,
      merkle_root_hash: tree.root,
      event_count: tree.leaves.length,
      timestamp: closedAt,
    });

    // 2. Persist in merkle_chunks table
    this.db.saveChunkAnchor({
      chunk_id: params.chunk_id,
      event_count: tree.leaves.length,
      merkle_root_hash: tree.root,
      batch_opened_at: openedAt,
      batch_closed_at: closedAt,
      chain_tx_hash: ledgerEntry.entry_hash,
      anchored_at: now,
    });

    // 3. Backfill raw_events with deterministic leaf indices
    this.db.backfillRawEventIndices(params.chunk_id, tree.leaves);

    return {
      chunk_id: params.chunk_id,
      merkle_root_hash: tree.root,
      chain_tx_hash: ledgerEntry.entry_hash,
      event_count: tree.leaves.length,
      tree,
    };
  }
}
