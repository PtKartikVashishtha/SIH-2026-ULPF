import { promises as fs } from "node:fs";
import { join } from "node:path";
import Database from "better-sqlite3";
// @ts-expect-error zstd-codec lacks ts types
import { ZstdCodec } from "zstd-codec";

let zstdSimplePromise: Promise<any> | null = null;
function getZstd(): Promise<any> {
  if (!zstdSimplePromise) {
    zstdSimplePromise = new Promise((resolve) => {
      ZstdCodec.run((zstd: any) => resolve(new zstd.Simple()));
    });
  }
  return zstdSimplePromise;
}

export class TamperDrill {
  /**
   * Tamper with a raw chunk by flipping 1 byte in the decompressed data of an entry, then recompressing.
   */
  static async tamperRawChunkByte(options: {
    rawStoreDir: string;
    chunkId: string;
    targetOffsetKey?: string;
  }): Promise<{ altered_leaf: string; byte_offset: number }> {
    const chunkPath = join(options.rawStoreDir, `${options.chunkId}.zst`);
    const indexPath = join(options.rawStoreDir, `${options.chunkId}.idx.json`);

    const [compressedBuf, indexStr] = await Promise.all([
      fs.readFile(chunkPath),
      fs.readFile(indexPath, "utf-8"),
    ]);

    const index = JSON.parse(indexStr);
    const targetKey = options.targetOffsetKey ?? Object.keys(index.entries)[0]!;
    const entry = index.entries[targetKey];
    if (!entry) throw new Error(`Offset key ${targetKey} not found in chunk index`);

    const zstd = await getZstd();
    const decompressed = Buffer.from(zstd.decompress(new Uint8Array(compressedBuf)));

    // Flip 1 byte in target leaf slice
    const flipPos = entry.offset;
    decompressed[flipPos] = (decompressed[flipPos]! ^ 0xff);

    // Recompress tampered buffer
    const recompressed = zstd.compress(decompressed);
    await fs.writeFile(chunkPath, Buffer.from(recompressed));

    return {
      altered_leaf: entry.lineage_id,
      byte_offset: flipPos,
    };
  }

  /**
   * Tamper with a ledger line by modifying 1 character in the JSON file.
   */
  static async tamperLedgerLine(ledgerPath: string, lineIndex: number = 0): Promise<void> {
    const content = await fs.readFile(ledgerPath, "utf-8");
    const lines = content.trim().split("\n");
    if (!lines[lineIndex]) throw new Error(`Ledger line ${lineIndex} does not exist`);

    const parsed = JSON.parse(lines[lineIndex]);
    parsed.event_count = (parsed.event_count ?? 1) + 999; // corrupt count
    lines[lineIndex] = JSON.stringify(parsed);

    await fs.writeFile(ledgerPath, lines.join("\n") + "\n", "utf-8");
  }

  /**
   * Tamper with database merkle_root_hash directly.
   */
  static tamperDbChunk(dbPathOrDb: string | Database.Database, chunkId: string): void {
    const db = typeof dbPathOrDb === "string" ? new Database(dbPathOrDb) : dbPathOrDb;
    db.prepare("UPDATE merkle_chunks SET merkle_root_hash = ? WHERE chunk_id = ?").run(
      "f".repeat(64),
      chunkId
    );
  }
}
