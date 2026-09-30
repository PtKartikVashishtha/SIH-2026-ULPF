import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { FileLedger } from "../src/ledger.js";
import { loadPrivateKey, loadPublicKey } from "../src/crypto.js";
import { TamperDrill } from "../src/tamper_drill.js";

const TEST_DIR = join(process.cwd(), "test-tmp-ledger");
const LEDGER_FILE = join(TEST_DIR, "test_ledger.jsonl");
const REPO_ROOT = join(process.cwd(), "..", "..");
const PRIV_KEY = join(REPO_ROOT, "keys", "dev_signing.key");
const PUB_KEY = join(REPO_ROOT, "keys", "dev_signing.pub");

describe("M2 Acceptance Criterion: Hash-Chained Signed Ledger & Edit Detection", () => {
  let ledger: FileLedger;

  beforeEach(async () => {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
    await fs.mkdir(TEST_DIR, { recursive: true });

    ledger = new FileLedger({
      filePath: LEDGER_FILE,
      privateKey: loadPrivateKey(PRIV_KEY),
      publicKey: loadPublicKey(PUB_KEY),
      signerKeyId: "dev_signing",
    });
  });

  afterEach(async () => {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
  });

  it("appends valid hash-chained entries with cryptographic Ed25519 signatures", () => {
    const entry0 = ledger.appendEntry({
      chunk_id: "chunk_20260926_01",
      merkle_root_hash: "aa".repeat(32),
      event_count: 50,
    });
    expect(entry0.sequence).toBe(0);
    expect(entry0.prev_hash).toBe("0".repeat(64));
    expect(entry0.signature).toBeDefined();

    const entry1 = ledger.appendEntry({
      chunk_id: "chunk_20260926_02",
      merkle_root_hash: "bb".repeat(32),
      event_count: 75,
    });
    expect(entry1.sequence).toBe(1);
    expect(entry1.prev_hash).toBe(entry0.entry_hash);

    const check = ledger.verifyChain();
    expect(check.valid).toBe(true);
  });

  it("detects an edited ledger line during chain verification", async () => {
    // Append 3 entries
    ledger.appendEntry({ chunk_id: "chunk_1", merkle_root_hash: "11".repeat(32), event_count: 10 });
    ledger.appendEntry({ chunk_id: "chunk_2", merkle_root_hash: "22".repeat(32), event_count: 20 });
    ledger.appendEntry({ chunk_id: "chunk_3", merkle_root_hash: "33".repeat(32), event_count: 30 });

    // Untouched chain verifies clean
    expect(ledger.verifyChain().valid).toBe(true);

    // Tamper with middle line (index 1)
    await TamperDrill.tamperLedgerLine(LEDGER_FILE, 1);

    // Chain verification must detect the modification
    const tamperedCheck = ledger.verifyChain();
    expect(tamperedCheck.valid).toBe(false);
    expect(tamperedCheck.brokenIndex).toBe(1);
    expect(tamperedCheck.error).toBeDefined();
  });
});
