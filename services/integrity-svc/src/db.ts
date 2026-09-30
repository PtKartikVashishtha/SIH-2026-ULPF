import Database from "better-sqlite3";
import type { MerkleLeaf } from "./types.js";

export class SqliteIntegrityRepository {
  private db: Database.Database;

  constructor(dbPathOrDb: string | Database.Database) {
    if (typeof dbPathOrDb === "string") {
      this.db = new Database(dbPathOrDb);
      this.db.pragma("journal_mode = WAL");
      this.db.pragma("foreign_keys = ON");
    } else {
      this.db = dbPathOrDb;
    }
  }

  saveChunkAnchor(params: {
    chunk_id: string;
    event_count: number;
    merkle_root_hash: string;
    batch_opened_at: string;
    batch_closed_at: string;
    chain_tx_hash: string;
    anchored_at: string;
  }): void {
    const stmt = this.db.prepare(`
      INSERT INTO merkle_chunks (
        chunk_id, event_count, merkle_root_hash, batch_opened_at, batch_closed_at,
        chain_tx_hash, anchor_status, anchored_at
      ) VALUES (
        @chunk_id, @event_count, @merkle_root_hash, @batch_opened_at, @batch_closed_at,
        @chain_tx_hash, 'anchored', @anchored_at
      )
      ON CONFLICT(chunk_id) DO UPDATE SET
        merkle_root_hash = @merkle_root_hash,
        anchor_status = 'anchored',
        chain_tx_hash = @chain_tx_hash,
        anchored_at = @anchored_at
    `);

    stmt.run(params);
  }

  backfillRawEventIndices(chunkId: string, orderedLeaves: MerkleLeaf[]): void {
    const updateStmt = this.db.prepare(`
      UPDATE raw_events
      SET chunk_id = @chunk_id, merkle_leaf_index = @merkle_leaf_index
      WHERE lineage_id = @lineage_id
    `);

    const tx = this.db.transaction((leaves: MerkleLeaf[]) => {
      for (let i = 0; i < leaves.length; i++) {
        const leaf = leaves[i];
        if (!leaf) continue;
        updateStmt.run({
          chunk_id: chunkId,
          merkle_leaf_index: i,
          lineage_id: leaf.lineage_id,
        });
      }
    });

    tx(orderedLeaves);
  }

  getChunk(chunkId: string): unknown | null {
    return this.db.prepare("SELECT * FROM merkle_chunks WHERE chunk_id = ?").get(chunkId) || null;
  }

  getRawEventsForChunk(chunkId: string): Array<{ lineage_id: string; sha256_hash: string; storage_pointer: string; merkle_leaf_index: number }> {
    return this.db.prepare(`
      SELECT lineage_id, sha256_hash, storage_pointer, merkle_leaf_index
      FROM raw_events
      WHERE chunk_id = ?
      ORDER BY merkle_leaf_index ASC
    `).all(chunkId) as any[];
  }

  close(): void {
    this.db.close();
  }
}
