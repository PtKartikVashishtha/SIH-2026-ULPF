import { promises as fs } from "node:fs";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);

let zstdCodecModule: any = null;
try {
  zstdCodecModule = require("../../ingestion-svc/node_modules/zstd-codec");
} catch {
  try {
    zstdCodecModule = require("../../../node_modules/.pnpm/zstd-codec@0.1.5/node_modules/zstd-codec");
  } catch {
    // fallback
  }
}
const ZstdCodec = zstdCodecModule?.ZstdCodec;

let zstdSimplePromise: Promise<any> | null = null;

function getZstdSimple(): Promise<any> {
  if (!zstdSimplePromise) {
    zstdSimplePromise = new Promise((res, rej) => {
      if (!ZstdCodec) return rej(new Error("ZstdCodec not found"));
      ZstdCodec.run((z: any) => {
        res(new z.Simple());
      });
    });
  }
  return zstdSimplePromise;
}

// In-memory cache for decompressed chunks to make repeated reads instantaneous
const chunkCache = new Map<string, Buffer>();
const MAX_CACHED_CHUNKS = 50;

export async function readRawLogByPointer(storagePointer: string | null | undefined): Promise<string | null> {
  if (!storagePointer) return null;

  // 1. First try remote pipeline daemon (which has native C zstandard decompression)
  try {
    const pipelineUrl = process.env.PIPELINE_HTTP_URL || "http://pipeline-svc:8000";
    const remoteRes = await fetch(`${pipelineUrl}/raw?pointer=${encodeURIComponent(storagePointer)}`);
    if (remoteRes.ok) {
      const text = await remoteRes.text();
      if (text) return text;
    }
  } catch {
    // fallback to local decompression
  }

  const match = storagePointer.match(/^raw_store:\/\/([^/]+)\/(offset_\d+)$/);
  if (!match || !match[1] || !match[2]) {
    return null;
  }

  const chunkId = match[1];
  const offsetKey = match[2];

  // Try relative to workspace or process.cwd()
  const candidateDirs = [
    resolve(process.cwd(), "data", "raw_store"),
    resolve(process.cwd(), "..", "..", "data", "raw_store"),
    resolve(process.cwd(), "..", "data", "raw_store"),
  ];

  let rawDir = candidateDirs[0]!;
  for (const d of candidateDirs) {
    if (existsSync(join(d, `${chunkId}.zst`))) {
      rawDir = d;
      break;
    }
  }

  const chunkFilePath = join(rawDir, `${chunkId}.zst`);
  const indexFilePath = join(rawDir, `${chunkId}.idx.json`);

  if (!existsSync(chunkFilePath) || !existsSync(indexFilePath)) {
    return null;
  }

  try {
    let fullBuffer = chunkCache.get(chunkId);
    if (!fullBuffer) {
      const [compressedBuf, indexJson] = await Promise.all([
        fs.readFile(chunkFilePath),
        fs.readFile(indexFilePath, "utf-8"),
      ]);

      const zstd = await getZstdSimple();
      const decompressed = zstd.decompress(new Uint8Array(compressedBuf));
      fullBuffer = Buffer.from(decompressed);

      if (chunkCache.size >= MAX_CACHED_CHUNKS) {
        const firstKey = chunkCache.keys().next().value;
        if (firstKey) chunkCache.delete(firstKey);
      }
      chunkCache.set(chunkId, fullBuffer);
    }

    const index = JSON.parse(await fs.readFile(indexFilePath, "utf-8"));
    const entry = index?.entries?.[offsetKey];
    if (!entry) return null;

    const rawBytes = fullBuffer.subarray(entry.offset, entry.offset + entry.length);

    // Verify hash integrity
    const hash = createHash("sha256").update(rawBytes).digest("hex");
    if (entry.sha256_hash && hash !== entry.sha256_hash) {
      console.warn(`[raw_reader] SHA-256 mismatch for ${storagePointer}: expected ${entry.sha256_hash} but got ${hash}`);
    }

    return rawBytes.toString("utf-8");
  } catch (err) {
    // Try remote pipeline daemon which has native libzstd decompression
    try {
      const pipelineUrl = process.env.PIPELINE_HTTP_URL || "http://localhost:8000";
      const remoteRes = await fetch(`${pipelineUrl}/raw?pointer=${encodeURIComponent(storagePointer)}`);
      if (remoteRes.ok) {
        const text = await remoteRes.text();
        if (text) return text;
      }
    } catch {
      // ignore remote error
    }

    console.error(`[raw_reader] Error reading ${storagePointer}:`, err);
    return null;
  }
}
