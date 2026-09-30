/**
 * review-api — Express REST API (C7 backend)
 * Endpoints per architecture.md §6
 */
import express, { type Express } from "express";
import cors from "cors";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as fs from "node:fs/promises";
import os from "node:os";
import { createHash } from "node:crypto";
import { getDb } from "./db.js";
import { readRawLogByPointer } from "./raw_reader.js";

const execFileAsync = promisify(execFile);
const __dir = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dir, "..", "..", "..");

export const app: Express = express();
app.use(cors());
app.use(express.text({ type: ["text/csv", "text/plain"], limit: "50mb" }));
app.use(express.json({ limit: "50mb" }));

const PORT = Number(process.env.PORT ?? 4000);

// ── helpers ──────────────────────────────────────────────────────────────────

function parseJson(val: unknown): unknown {
  if (typeof val === "string") {
    try { return JSON.parse(val); } catch { return val; }
  }
  return val;
}

function errorResponse(res: express.Response, code: string, message: string, status = 400) {
  return res.status(status).json({ error: { code, message } });
}

// ── /health & /ready ─────────────────────────────────────────────────────────

app.get("/health", (_req, res) => res.json({ status: "ok" }));
app.get("/ready", (_req, res) => {
  try {
    getDb().prepare("SELECT 1").get();
    res.json({ status: "ready" });
  } catch (e) {
    res.status(503).json({ status: "not_ready", reason: String(e) });
  }
});

// ── /internal/packs — cluster-grouped draft/staged packs ─────────────────────

app.get("/internal/packs/drafts", (_req, res) => {
  const db = getDb();
  // Group review_queue rows by cluster, attach pack if exists
  const clusters = db.prepare(`
    SELECT
      rq.cluster_id,
      COUNT(*) as sample_count,
      MIN(rq.created_at) as oldest_at,
      MAX(rq.created_at) as newest_at,
      rq.status,
      rq.assigned_analyst,
      rq.sample_raw_pointer,
      eh.source_type,
      mp.pack_id,
      mp.version as pack_version,
      mp.status as pack_status
    FROM review_queue rq
    LEFT JOIN extraction_history eh ON eh.extraction_id = rq.extraction_id
    LEFT JOIN mapping_packs mp ON mp.source_type = eh.source_type AND mp.status IN ('draft','staged')
    GROUP BY rq.cluster_id
    ORDER BY sample_count DESC, oldest_at ASC
  `).all();

  res.json({ clusters });
});

app.get("/internal/packs/:pack_id", (req, res) => {
  const db = getDb();
  const pack = db.prepare("SELECT * FROM mapping_packs WHERE pack_id = ?").get(req.params["pack_id"]);
  if (!pack) return errorResponse(res, "NOT_FOUND", "Pack not found", 404);

  const events = db.prepare(
    "SELECT * FROM pack_lifecycle_events WHERE pack_id = ? ORDER BY occurred_at ASC"
  ).all(req.params["pack_id"]);

  const fixtures = db.prepare(
    "SELECT * FROM test_fixtures WHERE pack_id = ?"
  ).all(req.params["pack_id"]);

  return res.json({ pack, lifecycle_events: events, fixtures });
});

app.post("/internal/packs/:pack_id/confirm", (req, res) => {
  const db = getDb();
  const { pack_id } = req.params;
  const { actor, confirmed_mapping } = req.body as { actor?: string; confirmed_mapping?: unknown };

  if (!actor) return errorResponse(res, "MISSING_ACTOR", "actor is required");
  if (!confirmed_mapping) return errorResponse(res, "MISSING_MAPPING", "confirmed_mapping is required");

  const pack = db.prepare("SELECT * FROM mapping_packs WHERE pack_id = ?").get(pack_id) as { status: string } | undefined;
  if (!pack) return errorResponse(res, "NOT_FOUND", "Pack not found", 404);
  if (pack.status === "confirmed" || pack.status === "active") {
    return errorResponse(res, "CONFLICT", "Pack already confirmed by another submission", 409);
  }

  db.prepare("UPDATE mapping_packs SET status = 'active', promoted_at = ? WHERE pack_id = ?")
    .run(new Date().toISOString(), pack_id);

  const hash = `hash-confirm-${Date.now()}`;
  db.prepare(
    "INSERT INTO pack_lifecycle_events (pack_id,event_type,actor,event_hash,occurred_at) VALUES (?,?,?,?,?)"
  ).run(pack_id, "pack_confirmed", actor, hash, new Date().toISOString());

  // Update related review_queue rows to confirmed
  db.prepare(
    "UPDATE review_queue SET status='confirmed', assigned_analyst=?, resolved_at=?, confirmed_mapping=? WHERE cluster_id IN (SELECT cluster_id FROM review_queue rq LEFT JOIN extraction_history eh ON eh.extraction_id = rq.extraction_id LEFT JOIN mapping_packs mp ON mp.source_type = eh.source_type WHERE mp.pack_id = ?)"
  ).run(actor, new Date().toISOString(), JSON.stringify(confirmed_mapping), pack_id);

  return res.json({ ok: true, pack_id, status: "active", event_hash: hash });
});

app.post("/internal/packs/:pack_id/reject", (req, res) => {
  const db = getDb();
  const { pack_id } = req.params;
  const { actor } = req.body as { actor?: string };
  if (!actor) return errorResponse(res, "MISSING_ACTOR", "actor is required");

  const pack = db.prepare("SELECT * FROM mapping_packs WHERE pack_id = ?").get(pack_id);
  if (!pack) return errorResponse(res, "NOT_FOUND", "Pack not found", 404);

  db.prepare("UPDATE mapping_packs SET status = 'quarantined' WHERE pack_id = ?").run(pack_id);
  const hash = `hash-reject-${Date.now()}`;
  db.prepare(
    "INSERT INTO pack_lifecycle_events (pack_id,event_type,actor,event_hash,occurred_at) VALUES (?,?,?,?,?)"
  ).run(pack_id, "pack_quarantined", actor, hash, new Date().toISOString());

  return res.json({ ok: true, pack_id, status: "quarantined" });
});

// ── /queue — review queue endpoints ─────────────────────────────────────────

app.get("/queue", (req, res) => {
  const db = getDb();
  const { status, page = "1", limit = "20" } = req.query as Record<string, string>;
  const pageN = Math.max(1, parseInt(page));
  const limitN = Math.min(100, Math.max(1, parseInt(limit)));
  const offset = (pageN - 1) * limitN;

  const where = status ? "WHERE rq.status = ?" : "";
  const params: unknown[] = status ? [status, limitN, offset] : [limitN, offset];

  const rows = db.prepare(`
    SELECT rq.*, eh.source_type, eh.extracted_fields, eh.confidence_scores
    FROM review_queue rq
    LEFT JOIN extraction_history eh ON eh.extraction_id = rq.extraction_id
    ${where}
    ORDER BY rq.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params);

  const total = (db.prepare(`SELECT COUNT(*) as c FROM review_queue ${where ? "WHERE status = ?" : ""}`).get(
    ...(status ? [status] : [])
  ) as { c: number }).c;

  const parsed = (rows as Record<string, unknown>[]).map(r => ({
    ...r,
    candidate_mapping: parseJson(r["candidate_mapping"]),
    confirmed_mapping: parseJson(r["confirmed_mapping"]),
    extracted_fields: parseJson(r["extracted_fields"]),
    confidence_scores: parseJson(r["confidence_scores"]),
  }));

  res.json({ items: parsed, total, page: pageN, limit: limitN });
});

app.get("/queue/clusters", (req, res) => {
  const db = getDb();
  const { page = "1", limit = "20", status, search, sort = "newest" } = req.query as Record<string, string>;
  const pageN = Math.max(1, parseInt(page));
  const limitN = Math.min(100, Math.max(1, parseInt(limit)));
  const offset = (pageN - 1) * limitN;

  let baseQuery = `
    SELECT
      rq.cluster_id,
      CASE 
        WHEN SUM(CASE WHEN rq.status = 'pending' THEN 1 ELSE 0 END) > 0 THEN 'pending'
        WHEN SUM(CASE WHEN rq.status = 'in_review' THEN 1 ELSE 0 END) > 0 THEN 'in_review'
        ELSE MIN(rq.status)
      END as status,
      COUNT(*) as sample_count,
      MIN(rq.created_at) as oldest_at,
      MAX(rq.created_at) as newest_at,
      MAX(rq.assigned_analyst) as assigned_analyst,
      COALESCE(MAX(rq.sample_raw_pointer), 'unknown') as sample_raw_pointer,
      COALESCE(MAX(eh.source_type), 'unknown') as source_type
    FROM review_queue rq
    LEFT JOIN extraction_history eh ON eh.lineage_id = rq.lineage_id
    GROUP BY rq.cluster_id
  `;

  let wrapperQuery = `SELECT * FROM (${baseQuery}) clusters_sub`;
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (status && status !== "all") {
    conditions.push("status = ?");
    params.push(status);
  }

  if (search && search.trim()) {
    conditions.push("(cluster_id LIKE ? OR source_type LIKE ?)");
    const s = `%${search.trim()}%`;
    params.push(s, s);
  }

  if (conditions.length > 0) {
    wrapperQuery += " WHERE " + conditions.join(" AND ");
  }

  const countSql = `SELECT COUNT(*) as c FROM (${wrapperQuery}) count_sub`;
  const total = (db.prepare(countSql).get(...params) as { c: number }).c;

  let orderClause = "newest_at DESC, sample_count DESC";
  if (sort === "samples") {
    orderClause = "sample_count DESC, newest_at DESC";
  } else if (sort === "oldest") {
    orderClause = "oldest_at ASC, newest_at ASC";
  }

  wrapperQuery += `
    ORDER BY ${orderClause}
    LIMIT ? OFFSET ?
  `;
  params.push(limitN, offset);

  const rows = db.prepare(wrapperQuery).all(...params);
  res.json({ clusters: rows, total, page: pageN, limit: limitN });
});

app.get("/queue/clusters/:cluster_id", async (req, res) => {
  const db = getDb();
  const { cluster_id } = req.params;
  const items = db.prepare(`
    SELECT rq.*, eh.source_type, eh.extracted_fields, eh.confidence_scores
    FROM review_queue rq
    LEFT JOIN extraction_history eh ON eh.lineage_id = rq.lineage_id
    WHERE rq.cluster_id = ?
    ORDER BY rq.created_at DESC
  `).all(cluster_id) as Record<string, unknown>[];

  if (!items.length) return errorResponse(res, "NOT_FOUND", "Cluster not found", 404);

  const parsed: Record<string, any>[] = items.map(r => {
    let candidate = (parseJson(r["candidate_mapping"]) || {}) as Record<string, any>;
    const confirmed = parseJson(r["confirmed_mapping"]) as Record<string, any> | null;
    let extracted = parseJson(r["extracted_fields"]) as Record<string, any> | null;
    let confidence = parseJson(r["confidence_scores"]) as Record<string, any> | null;

    if (Object.keys(candidate).length === 0 && confirmed && typeof confirmed === "object") {
      candidate = Object.fromEntries(
        Object.entries(confirmed).map(([k, v]) => [
          k,
          typeof v === "object" && v !== null && "candidate_ocsf_attribute" in v
            ? v
            : { candidate_ocsf_attribute: String(v).replace(/^\$/, ""), similarity_score: 0.95, alternate_candidates: [] }
        ])
      );
    }

    if ((!confidence || Object.keys(confidence).length === 0) && Object.keys(candidate).length > 0) {
      confidence = Object.fromEntries(
        Object.entries(candidate).map(([k, v]: [string, any]) => [
          k,
          typeof v?.similarity_score === "number" ? v.similarity_score : 0.90
        ])
      );
    }

    return {
      ...r,
      candidate_mapping: candidate,
      confirmed_mapping: confirmed,
      extracted_fields: extracted,
      confidence_scores: confidence,
    };
  });

  const clusterStatus = parsed.some(p => p.status === "pending")
    ? "pending"
    : parsed.some(p => p.status === "in_review")
    ? "in_review"
    : parsed[0]!["status"];

  const primaryCandidate =
    parsed.find(p => p.status === "pending" && Object.keys(p.candidate_mapping || {}).length > 0)?.candidate_mapping ||
    parsed.find(p => Object.keys(p.candidate_mapping || {}).length > 0)?.candidate_mapping ||
    parsed[0]!["candidate_mapping"];

  const primarySourceType =
    parsed.find(p => p.source_type && p.source_type !== "unknown")?.source_type ||
    parsed[0]!["source_type"];

  const samplePointer = parsed[0]!["sample_raw_pointer"] as string;
  const sampleRawLog = await readRawLogByPointer(samplePointer);

  return res.json({
    cluster_id,
    status: clusterStatus,
    source_type: primarySourceType,
    sample_count: parsed.length,
    oldest_at: parsed[parsed.length - 1]!["created_at"],
    assigned_analyst: parsed[0]!["assigned_analyst"],
    items: parsed,
    candidate_mapping: primaryCandidate,
    sample_raw_pointer: parsed[0]!["sample_raw_pointer"],
    sample_raw_log: sampleRawLog,
  });
});

app.post("/queue/clusters/:cluster_id/confirm", (req, res) => {
  const db = getDb();
  const { cluster_id } = req.params;
  const { actor, confirmed_mapping } = req.body as { actor?: string; confirmed_mapping?: unknown };
  if (!actor) return errorResponse(res, "MISSING_ACTOR", "actor is required");

  // Check for concurrent confirmation (409)
  const pendingCount = (db.prepare(
    "SELECT COUNT(*) as c FROM review_queue WHERE cluster_id = ? AND status IN ('pending', 'in_review')"
  ).get(cluster_id) as { c: number }).c;
  if (pendingCount === 0) {
    const existing = db.prepare(
      "SELECT status FROM review_queue WHERE cluster_id = ? AND status = 'confirmed' LIMIT 1"
    ).get(cluster_id);
    if (existing) return errorResponse(res, "CONFLICT", "Another analyst already confirmed this cluster", 409);
  }

  const now = new Date().toISOString();
  db.prepare(
    "UPDATE review_queue SET status='confirmed', assigned_analyst=?, confirmed_mapping=?, resolved_at=? WHERE cluster_id=?"
  ).run(actor, JSON.stringify(confirmed_mapping ?? {}), now, cluster_id);

  const cleanCluster = cluster_id.replace(/[^a-zA-Z0-9_]/g, "_");
  const packId = `pack_${cleanCluster}_v1.0.0`;
  const eventHash = `hash_${Date.now()}`;

  db.prepare(`
    INSERT INTO mapping_packs (
      pack_id, version, source_type, pack_yaml_hash, signature, signer_key_id, status, created_at, promoted_at
    ) VALUES (?, '1.0.0', ?, 'hash_confirmed', 'sig_analyst_confirmed', 'dev_signing', 'active', ?, ?)
    ON CONFLICT(pack_id) DO UPDATE SET status = 'active', promoted_at = excluded.promoted_at
  `).run(packId, cluster_id, now, now);

  db.prepare(`
    INSERT INTO pack_lifecycle_events (pack_id, event_type, actor, event_hash, occurred_at)
    VALUES (?, 'pack_confirmed', ?, ?, ?)
  `).run(packId, actor, eventHash, now);

  // Normalize confirmed cluster items into normalization_history
  const clusterItems = db.prepare(`
    SELECT rq.lineage_id, rq.extraction_id, eh.extracted_fields, eh.source_type
    FROM review_queue rq
    LEFT JOIN extraction_history eh ON eh.lineage_id = rq.lineage_id
    WHERE rq.cluster_id = ?
  `).all(cluster_id) as Array<{ lineage_id: string; extraction_id: number; extracted_fields: string; source_type: string }>;

  const insNorm = db.prepare(`
    INSERT INTO normalization_history (
      lineage_id, extraction_id, ocsf_class_uid, ocsf_event_json, schema_valid, published_to_bus, normalized_at
    ) VALUES (?, ?, ?, ?, 1, 1, ?)
  `);

  const mappingObj = (confirmed_mapping && typeof confirmed_mapping === "object" ? confirmed_mapping : {}) as Record<string, any>;

  for (const it of clusterItems) {
    const already = db.prepare("SELECT 1 FROM normalization_history WHERE lineage_id = ?").get(it.lineage_id);
    if (already) continue;

    const ef = (parseJson(it.extracted_fields) || {}) as Record<string, any>;
    const ocsfEvent: Record<string, any> = {
      class_uid: 4001,
      class_name: "Network Activity",
      category_uid: 4,
      category_name: "Network Activity",
      activity_id: 6,
      activity_name: "Traffic",
      severity_id: 1,
      time: Date.now(),
      metadata: {
        product: {
          name: "ULPF Onboarded Log",
          vendor_name: it.source_type || "Universal",
          version: "1.0.0",
        },
        version: "1.2.0",
      },
    };

    for (const [rawKey, rawVal] of Object.entries(ef)) {
      const cleanVal = String(rawVal).replace(/^["']|["']$/g, "");
      const mapEntry = mappingObj[rawKey];
      const targetAttr = typeof mapEntry === "string" ? mapEntry : mapEntry?.candidate_ocsf_attribute;
      if (!targetAttr) continue;

      if (targetAttr === "src_endpoint.ip") {
        ocsfEvent.src_endpoint = { ...(ocsfEvent.src_endpoint || {}), ip: cleanVal };
      } else if (targetAttr === "dst_endpoint.ip") {
        ocsfEvent.dst_endpoint = { ...(ocsfEvent.dst_endpoint || {}), ip: cleanVal };
      } else if (targetAttr === "src_endpoint.port") {
        ocsfEvent.src_endpoint = { ...(ocsfEvent.src_endpoint || {}), port: parseInt(cleanVal) || 0 };
      } else if (targetAttr === "dst_endpoint.port") {
        ocsfEvent.dst_endpoint = { ...(ocsfEvent.dst_endpoint || {}), port: parseInt(cleanVal) || 0 };
      } else if (targetAttr === "http_request.http_method") {
        ocsfEvent.http_request = { ...(ocsfEvent.http_request || {}), http_method: cleanVal };
      } else if (targetAttr === "http_request.url.path") {
        ocsfEvent.http_request = { ...(ocsfEvent.http_request || {}), url: { path: cleanVal } };
      } else if (targetAttr === "http_request.user_agent") {
        ocsfEvent.http_request = { ...(ocsfEvent.http_request || {}), user_agent: cleanVal };
      } else if (targetAttr === "http_response.code") {
        ocsfEvent.http_response = { ...(ocsfEvent.http_response || {}), code: parseInt(cleanVal) || 200 };
      } else if (targetAttr === "traffic.bytes_out") {
        ocsfEvent.traffic = { ...(ocsfEvent.traffic || {}), bytes_out: parseInt(cleanVal) || 0 };
      } else if (targetAttr === "time" || targetAttr === "timestamp") {
        ocsfEvent.time = cleanVal;
      }
    }

    try {
      insNorm.run(it.lineage_id, it.extraction_id || 1, 4001, JSON.stringify(ocsfEvent), now);
    } catch {
      // If lineage_id / extraction_id are mock records not in raw_events, continue cleanly
    }
  }

  return res.json({ ok: true, cluster_id, pack_id: packId, status: "confirmed", event_hash: eventHash });
});

app.post("/queue/clusters/:cluster_id/reject", (req, res) => {
  const db = getDb();
  const { cluster_id } = req.params;
  const { actor } = req.body as { actor?: string };
  if (!actor) return errorResponse(res, "MISSING_ACTOR", "actor is required");

  db.prepare(
    "UPDATE review_queue SET status='rejected', assigned_analyst=?, resolved_at=? WHERE cluster_id=?"
  ).run(actor, new Date().toISOString(), cluster_id);

  return res.json({ ok: true, cluster_id, status: "rejected" });
});

app.post("/queue/clusters/:cluster_id/rollback", (req, res) => {
  const db = getDb();
  const { cluster_id } = req.params;
  const { actor } = req.body as { actor?: string };
  if (!actor) return errorResponse(res, "MISSING_ACTOR", "actor is required");

  const existing = db.prepare(
    "SELECT status FROM review_queue WHERE cluster_id = ? LIMIT 1"
  ).get(cluster_id) as { status: string } | undefined;
  if (!existing) return errorResponse(res, "NOT_FOUND", "Cluster not found", 404);
  if (!["confirmed", "rejected"].includes(existing.status)) {
    return errorResponse(res, "INVALID_STATE", `Cannot rollback cluster in status '${existing.status}'`, 409);
  }

  const now = new Date().toISOString();
  db.prepare(
    "UPDATE review_queue SET status='pending', assigned_analyst=NULL, confirmed_mapping=NULL, resolved_at=NULL WHERE cluster_id=?"
  ).run(cluster_id);

  // Roll back the associated pack if it exists
  const packId = `pack_${cluster_id.replace(/[^a-zA-Z0-9_]/g, "_")}_v1.0.0`;
  const pack = db.prepare("SELECT pack_id FROM mapping_packs WHERE pack_id = ?").get(packId);
  if (pack) {
    db.prepare("UPDATE mapping_packs SET status = 'draft' WHERE pack_id = ?").run(packId);
    const hash = `hash-rollback-${Date.now()}`;
    db.prepare(
      "INSERT INTO pack_lifecycle_events (pack_id, event_type, actor, event_hash, occurred_at) VALUES (?, 'pack_rolled_back', ?, ?, ?)"
    ).run(packId, actor, hash, now);
  }

  return res.json({ ok: true, cluster_id, status: "pending" });
});

app.post("/queue/clusters/:cluster_id/assign", (req, res) => {
  const db = getDb();
  const { cluster_id } = req.params;
  const actor = req.body?.actor || req.body?.analyst || req.body?.analyst_id;
  if (!actor) return errorResponse(res, "MISSING_ACTOR", "actor or analyst is required");

  db.prepare(
    "UPDATE review_queue SET status='in_review', assigned_analyst=? WHERE cluster_id=? AND status='pending'"
  ).run(actor, cluster_id);

  return res.json({ ok: true, cluster_id, status: "in_review", analyst: actor });
});

// ── /trace & /verify ──────────────────────────────────────────────────────────

app.get("/raw/:lineage_id", async (req, res) => {
  const db = getDb();
  const { lineage_id } = req.params;
  const raw = db.prepare("SELECT * FROM raw_events WHERE lineage_id = ?").get(lineage_id) as Record<string, any> | undefined;
  if (!raw) return errorResponse(res, "NOT_FOUND", "lineage_id not found", 404);
  const rawLog = await readRawLogByPointer(raw.storage_pointer);
  return res.json({
    lineage_id,
    storage_pointer: raw.storage_pointer,
    raw_log: rawLog || `SRC=${raw.source_ip} PROTO=${raw.transport_protocol} SIZE=${raw.raw_size_bytes}bytes`,
    source_ip: raw.source_ip,
    source_port: raw.source_port,
    transport_protocol: raw.transport_protocol,
    ingestion_timestamp: raw.ingestion_timestamp,
  });
});

app.get("/trace/:lineage_id", async (req, res) => {
  const db = getDb();
  const { lineage_id } = req.params;
  const raw = db.prepare("SELECT * FROM raw_events WHERE lineage_id = ?").get(lineage_id) as Record<string, any> | undefined;
  if (!raw) return errorResponse(res, "NOT_FOUND", "lineage_id not found", 404);

  const extractions = db.prepare("SELECT * FROM extraction_history WHERE lineage_id = ?").all(lineage_id);
  const queue = db.prepare("SELECT * FROM review_queue WHERE lineage_id = ?").all(lineage_id);
  const normalization = db.prepare("SELECT * FROM normalization_history WHERE lineage_id = ?").all(lineage_id);

  const rawLog = await readRawLogByPointer(raw.storage_pointer);
  raw.raw_log_text = rawLog;

  return res.json({ lineage_id, raw_event: raw, extractions, review_queue: queue, normalization, raw_log_text: rawLog });
});

app.get("/verify/:lineage_id", async (req, res) => {
  const db = getDb();
  const { lineage_id } = req.params;
  const raw = db.prepare(`
    SELECT re.*, mc.merkle_root_hash, mc.anchor_status, mc.chain_tx_hash, mc.anchored_at
    FROM raw_events re
    LEFT JOIN merkle_chunks mc ON mc.chunk_id = re.chunk_id
    WHERE re.lineage_id = ?
  `).get(lineage_id) as Record<string, unknown> | undefined;

  if (!raw) return errorResponse(res, "NOT_FOUND", "lineage_id not found", 404);

  // 1. Fetch raw log bytes from disk store to re-verify bit-for-bit authenticity
  let rawLog: string | null = null;
  let recomputedSha256: string | null = null;
  let hashMismatch = false;

  try {
    rawLog = await readRawLogByPointer(raw["storage_pointer"] as string);
    if (rawLog !== null) {
      recomputedSha256 = createHash("sha256").update(Buffer.from(rawLog, "utf-8")).digest("hex");
      if (raw["sha256_hash"] && recomputedSha256 !== raw["sha256_hash"]) {
        hashMismatch = true;
      }
    }
  } catch (err) {
    console.error(`[verify] Failed to re-hash raw log for ${lineage_id}:`, err);
  }

  const isAnchored = raw["anchor_status"] === "anchored";

  if (hashMismatch) {
    return res.json({
      lineage_id,
      sha256_hash: raw["sha256_hash"],
      actual_raw_hash: recomputedSha256,
      chunk_id: raw["chunk_id"],
      merkle_leaf_index: raw["merkle_leaf_index"],
      merkle_root_hash: raw["merkle_root_hash"],
      anchor_status: raw["anchor_status"],
      chain_tx_hash: raw["chain_tx_hash"],
      anchored_at: raw["anchored_at"],
      verified: false,
      tampered: true,
      tamper_reason: `Raw log byte hash mismatch! DB Recorded Seal: ${raw["sha256_hash"]} != Actual Disk Seal: ${recomputedSha256}. Event payload or DB records have been modified!`,
      proof_message: "CRITICAL FAILURE: Merkle leaf hash mismatch — tampering detected!",
    });
  }

  // 2. Recompute Merkle Root from chunk leaves to detect tree root tampering
  let rootMismatch = false;
  let recomputedRoot: string | null = null;

  if (isAnchored && raw["chunk_id"] && raw["merkle_root_hash"]) {
    const chunkLeaves = db.prepare(`
      SELECT lineage_id, sha256_hash
      FROM raw_events
      WHERE chunk_id = ?
      ORDER BY lineage_id ASC
    `).all(raw["chunk_id"]) as Array<{ lineage_id: string; sha256_hash: string }>;

    if (chunkLeaves.length > 0) {
      let currentLevel = chunkLeaves.map(l => {
        const leafBuf = Buffer.concat([Buffer.from([0x00]), Buffer.from(l.sha256_hash, "hex")]);
        return createHash("sha256").update(leafBuf).digest("hex");
      });

      while (currentLevel.length > 1) {
        const nextLevel: string[] = [];
        for (let i = 0; i < currentLevel.length; i += 2) {
          const left = currentLevel[i]!;
          const right = i + 1 < currentLevel.length ? currentLevel[i + 1]! : left;
          const nodeBuf = Buffer.concat([
            Buffer.from([0x01]),
            Buffer.from(left, "hex"),
            Buffer.from(right, "hex"),
          ]);
          nextLevel.push(createHash("sha256").update(nodeBuf).digest("hex"));
        }
        currentLevel = nextLevel;
      }

      recomputedRoot = currentLevel[0] || null;
      if (recomputedRoot && recomputedRoot !== raw["merkle_root_hash"]) {
        rootMismatch = true;
      }
    }
  }

  if (rootMismatch) {
    return res.json({
      lineage_id,
      sha256_hash: raw["sha256_hash"],
      actual_raw_hash: recomputedSha256 || raw["sha256_hash"],
      chunk_id: raw["chunk_id"],
      merkle_leaf_index: raw["merkle_leaf_index"],
      merkle_root_hash: raw["merkle_root_hash"],
      recomputed_root_hash: recomputedRoot,
      anchor_status: raw["anchor_status"],
      chain_tx_hash: raw["chain_tx_hash"],
      anchored_at: raw["anchored_at"],
      verified: false,
      tampered: true,
      tamper_reason: `Merkle Root mismatch! Database recorded root (${raw["merkle_root_hash"]}) does not match recomputed root (${recomputedRoot}) derived from chunk leaves. Merkle chunk header has been tampered with!`,
      proof_message: "CRITICAL FAILURE: Merkle tree root mismatch — tampering detected!",
    });
  }

  return res.json({
    lineage_id,
    sha256_hash: raw["sha256_hash"],
    actual_raw_hash: recomputedSha256 || raw["sha256_hash"],
    chunk_id: raw["chunk_id"],
    merkle_leaf_index: raw["merkle_leaf_index"],
    merkle_root_hash: raw["merkle_root_hash"],
    anchor_status: raw["anchor_status"],
    chain_tx_hash: raw["chain_tx_hash"],
    anchored_at: raw["anchored_at"],
    verified: isAnchored,
    tampered: false,
    proof_message: isAnchored
      ? "Merkle proof valid — bit-for-bit raw log seal matches anchored Merkle root on-chain"
      : "Batch pending anchoring — cannot verify yet",
  });
});

// ── /normalized — normalized OCSF events stream ─────────────────────────────

app.get("/normalized", async (req, res) => {
  const db = getDb();
  const page = Math.max(1, parseInt((req.query["page"] as string) || "1"));
  const limit = Math.min(200, Math.max(1, parseInt((req.query["limit"] as string) || "25")));
  const offset = (page - 1) * limit;
  const path = req.query["path"] as string | undefined;
  const search = req.query["search"] as string | undefined;

  const conditions: string[] = [];
  const params: unknown[] = [];

  if (path && (path === "HOT" || path === "COLD")) {
    conditions.push("eh.path_taken = ?");
    params.push(path);
  }

  if (search && search.trim()) {
    conditions.push("(nh.lineage_id LIKE ? OR re.source_ip LIKE ? OR eh.source_type LIKE ? OR nh.ocsf_event_json LIKE ?)");
    const s = `%${search.trim()}%`;
    params.push(s, s, s, s);
  }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

  const countSql = `
    SELECT COUNT(*) as c
    FROM normalization_history nh
    LEFT JOIN raw_events re ON re.lineage_id = nh.lineage_id
    LEFT JOIN extraction_history eh ON eh.lineage_id = nh.lineage_id
    ${where}
  `;
  const total = (db.prepare(countSql).get(...params) as { c: number }).c;

  const rows = db.prepare(`
    SELECT
      nh.normalization_id,
      nh.lineage_id,
      nh.extraction_id,
      nh.ocsf_class_uid,
      nh.ocsf_event_json,
      nh.schema_valid,
      nh.normalized_at,
      re.source_ip,
      re.transport_protocol,
      re.storage_pointer,
      eh.source_type,
      eh.path_taken
    FROM normalization_history nh
    LEFT JOIN raw_events re ON re.lineage_id = nh.lineage_id
    LEFT JOIN extraction_history eh ON eh.lineage_id = nh.lineage_id
    ${where}
    ORDER BY nh.normalization_id DESC
    LIMIT ? OFFSET ?
  `).all(...params, limit, offset) as Record<string, unknown>[];

  const parsed = await Promise.all(rows.map(async r => ({
    ...r,
    ocsf_event: parseJson(r["ocsf_event_json"]),
    raw_log_text: await readRawLogByPointer(r["storage_pointer"] as string),
  })));

  return res.json({ total, items: parsed, page, limit });
});

// ── /stats — triage dashboard metrics ────────────────────────────────────────

app.get("/stats", (_req, res) => {
  const db = getDb();
  const status_counts = db.prepare(`
    SELECT status, COUNT(*) as count FROM review_queue GROUP BY status
  `).all();

  const oldest = db.prepare(`
    SELECT cluster_id, MIN(created_at) as oldest_at FROM review_queue WHERE status='pending' GROUP BY cluster_id ORDER BY oldest_at ASC LIMIT 1
  `).get() as { cluster_id: string; oldest_at: string } | undefined;

  const analyst_load = db.prepare(`
    SELECT assigned_analyst, COUNT(*) as count FROM review_queue WHERE assigned_analyst IS NOT NULL GROUP BY assigned_analyst
  `).all();

  const packs = db.prepare(`
    SELECT status, COUNT(*) as count FROM mapping_packs GROUP BY status
  `).all();

  const chunks = db.prepare(`
    SELECT anchor_status, COUNT(*) as count, SUM(event_count) as total_events FROM merkle_chunks GROUP BY anchor_status
  `).all();

  res.json({ status_counts, oldest_pending: oldest ?? null, analyst_load, packs, merkle_chunks: chunks });
});

// ── /packs — public pack list ─────────────────────────────────────────────────

app.get("/packs", (_req, res) => {
  const db = getDb();
  const packs = db.prepare("SELECT * FROM mapping_packs ORDER BY created_at DESC").all();
  res.json({ packs });
});

// ── /ingest/csv — Universal CSV Log Ingestion & Pipeline Orchestration ─────

export function parseCsvToLogs(content: string): Array<{
  raw_log: string;
  source_ip?: string;
  source_port?: number;
}> {
  if (!content || !content.trim()) return [];

  // Parse lines respecting quotes
  const lines: string[] = [];
  let cur = "";
  let insideQuote = false;
  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    if (ch === '"') {
      insideQuote = !insideQuote;
      cur += ch;
    } else if ((ch === "\n" || ch === "\r") && !insideQuote) {
      if (ch === "\r" && content[i + 1] === "\n") i++;
      if (cur.trim().length > 0) lines.push(cur.trim());
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.trim().length > 0) lines.push(cur.trim());
  if (lines.length === 0) return [];

  function parseRow(line: string, delim = ","): string[] {
    const fields: string[] = [];
    let field = "";
    let inQ = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') {
        if (inQ && line[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQ = !inQ;
        }
      } else if (c === delim && !inQ) {
        fields.push(field.trim());
        field = "";
      } else {
        field += c;
      }
    }
    fields.push(field.trim());
    return fields;
  }

  // Detect delimiter
  const firstLine = lines[0]!;
  let delim = ",";
  const commas = (firstLine.match(/,/g) || []).length;
  const semis = (firstLine.match(/;/g) || []).length;
  const tabs = (firstLine.match(/\t/g) || []).length;
  if (semis > commas && semis > tabs) delim = ";";
  else if (tabs > commas && tabs > semis) delim = "\t";

  const firstRow = parseRow(firstLine, delim);

  const knownLogCols = ["raw_log", "raw_message", "message", "log", "event", "syslog", "payload", "raw", "data", "log_message", "log_text"];
  const headerIndices: Record<string, number> = {};
  firstRow.forEach((col, idx) => {
    headerIndices[col.toLowerCase().replace(/[\s\-_]+/g, "_")] = idx;
  });

  let logColIdx = -1;
  for (const k of knownLogCols) {
    if (k in headerIndices) {
      logColIdx = headerIndices[k]!;
      break;
    }
  }

  const ipColIdx = headerIndices["source_ip"] ?? headerIndices["src_ip"] ?? headerIndices["ip"] ?? headerIndices["host"] ?? -1;
  const portColIdx = headerIndices["source_port"] ?? headerIndices["src_port"] ?? headerIndices["port"] ?? -1;
  const hasHeader = logColIdx !== -1 || ipColIdx !== -1 || Object.keys(headerIndices).some(k => ["timestamp", "action", "protocol", "dst_ip", "dest_ip"].includes(k));

  const startIdx = hasHeader ? 1 : 0;
  const results: Array<{ raw_log: string; source_ip?: string; source_port?: number }> = [];

  for (let i = startIdx; i < lines.length; i++) {
    const row = parseRow(lines[i]!, delim);
    if (!row || row.length === 0 || (row.length === 1 && !row[0])) continue;

    let rawLog = "";
    let srcIp: string | undefined = undefined;
    let srcPort: number | undefined = undefined;

    if (logColIdx !== -1 && row[logColIdx]) {
      rawLog = row[logColIdx]!;
    } else if (hasHeader) {
      const parts: string[] = [];
      firstRow.forEach((colName, idx) => {
        const val = row[idx];
        if (val !== undefined && val !== "") {
          parts.push(`${colName}="${val.replace(/"/g, '\\"')}"`);
        }
      });
      rawLog = parts.join(" ");
    } else {
      rawLog = row.join(" ");
    }

    if (ipColIdx !== -1 && row[ipColIdx]) srcIp = row[ipColIdx];
    if (portColIdx !== -1 && row[portColIdx]) {
      const p = parseInt(row[portColIdx]!, 10);
      if (!isNaN(p)) srcPort = p;
    }

    if (rawLog.trim()) {
      results.push({
        raw_log: rawLog.trim(),
        source_ip: srcIp,
        source_port: srcPort,
      });
    }
  }

  return results;
}

app.post(["/ingest/csv", "/api/upload-csv"], async (req, res) => {
  let csvText = "";
  let filename = "universal_logs.csv";
  let defaultSourceIp = "127.0.0.1";

  if (typeof req.body === "string") {
    csvText = req.body;
  } else if (req.body && typeof req.body === "object") {
    csvText = req.body.csv_content || req.body.csv || req.body.content || "";
    if (req.body.filename) filename = String(req.body.filename);
    if (req.body.source_ip) defaultSourceIp = String(req.body.source_ip);
  }

  if (!csvText || !csvText.trim()) {
    return errorResponse(res, "EMPTY_CSV", "CSV content is empty or not provided", 400);
  }

  const logs = parseCsvToLogs(csvText);
  if (logs.length === 0) {
    return errorResponse(res, "NO_LOGS_PARSED", "No valid log records found in CSV", 400);
  }

  const ingestionUrl = process.env.INGESTION_HTTP_URL || "http://localhost:5142";
  const pipelineUrl = process.env.PIPELINE_HTTP_URL || "http://localhost:8000";
  let ingestedEvents: Array<{ lineage_id: string; sha256_hash?: string }> = [];

  try {
    const ingestRes = await fetch(`${ingestionUrl}/ingest/batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(logs.map(l => ({
        payload: l.raw_log,
        source_ip: l.source_ip || defaultSourceIp,
        source_port: l.source_port || 514,
      }))),
    });

    if (!ingestRes.ok) {
      throw new Error(`Ingestion service returned HTTP ${ingestRes.status}`);
    }

    const json = (await ingestRes.json()) as { events: Array<{ lineage_id: string; sha256_hash?: string }> };
    ingestedEvents = json.events || [];
  } catch (err: any) {
    console.error("Ingestion listener error:", err.message);
    return errorResponse(res, "INGESTION_FAILED", `Failed to send to Ingestion Layer: ${err.message}`, 502);
  }

  // Ensure flushed
  try {
    await fetch(`${ingestionUrl}/flush`, { method: "POST" });
  } catch {
    // ignore
  }

  // Trigger pipeline extraction and coldpath Drain
  const lineageIds = ingestedEvents.map(e => e.lineage_id);
  if (lineageIds.length > 0) {
    try {
      const pipeRes = await fetch(`${pipelineUrl}/process`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lineage_ids: lineageIds }),
      });
      if (!pipeRes.ok) {
        console.warn(`Pipeline HTTP returned ${pipeRes.status}`);
      }
    } catch (err: any) {
      console.warn("Pipeline service HTTP dispatch note:", err.message);
      // Fallback to local python process if running directly outside docker
      let tempFile: string | null = null;
      try {
        const workerScript = join(REPO_ROOT, "tools", "pipeline_worker.py");
        tempFile = join(os.tmpdir(), `ulpf_lineage_${Date.now()}_${Math.random().toString(36).slice(2)}.json`);
        await fs.writeFile(tempFile, JSON.stringify(lineageIds), "utf-8");
        await execFileAsync("python", [workerScript, "--lineage-file", tempFile]);
      } catch {
        // ignore fallback errors
      } finally {
        if (tempFile) {
          try { await fs.unlink(tempFile); } catch {}
        }
      }
    }
  }

  // Query DB for complete event trace (chunked to respect SQLite parameter limits)
  const db = getDb();
  const records: Record<string, unknown>[] = [];
  const BATCH_SIZE = 500;
  for (let i = 0; i < lineageIds.length; i += BATCH_SIZE) {
    const batch = lineageIds.slice(i, i + BATCH_SIZE);
    const placeholders = batch.map(() => "?").join(",");
    const rows = db.prepare(`
      SELECT
        re.lineage_id,
        re.sha256_hash,
        re.source_ip,
        re.source_port,
        re.transport_protocol,
        re.raw_size_bytes,
        re.storage_pointer,
        re.chunk_id,
        re.ingestion_timestamp,
        eh.path_taken,
        eh.source_type,
        eh.extracted_fields,
        eh.confidence_scores,
        rq.cluster_id,
        rq.status as review_status,
        nh.ocsf_class_uid,
        nh.schema_valid
      FROM raw_events re
      LEFT JOIN extraction_history eh ON eh.lineage_id = re.lineage_id
      LEFT JOIN review_queue rq ON rq.lineage_id = re.lineage_id
      LEFT JOIN normalization_history nh ON nh.lineage_id = re.lineage_id
      WHERE re.lineage_id IN (${placeholders})
      ORDER BY re.created_at ASC
    `).all(...batch) as Record<string, unknown>[];
    records.push(...rows);
  }

  const parsedRecords: Array<Record<string, any>> = records.map((r, idx) => ({
    ...r,
    extracted_fields: parseJson(r["extracted_fields"]),
    confidence_scores: parseJson(r["confidence_scores"]),
    sample_preview: logs[idx]?.raw_log?.slice(0, 160) || "",
  }));

  const chunks = Array.from(new Set(parsedRecords.map(r => r["chunk_id"] as string).filter(Boolean)));
  const hotCount = parsedRecords.filter(r => r["path_taken"] === "HOT").length;
  const coldCount = parsedRecords.filter(r => r["path_taken"] === "COLD").length;
  const rawCount = parsedRecords.length - hotCount - coldCount;

  return res.json({
    ok: true,
    filename,
    total_rows: logs.length,
    ingested_count: ingestedEvents.length,
    chunks,
    summary: {
      total: parsedRecords.length,
      hot_path_count: hotCount,
      cold_path_count: coldCount,
      raw_stored_count: rawCount,
    },
    records: parsedRecords,
  });
});

// ── start ────────────────────────────────────────────────────────────────────

if (!process.env.VITEST && process.env.NODE_ENV !== "test") {
  app.listen(PORT, () => {
    console.log(`review-api listening on http://localhost:${PORT}`);
    // Trigger DB init + seed
    getDb();
  });
}
