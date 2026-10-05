import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { Server } from "node:http";
import { app } from "../src/index.js";
import { getDb } from "../src/db.js";

describe("review-api M8 Endpoints & Workflow", () => {
  let server: Server;
  let baseUrl: string;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address();
        if (typeof addr === "object" && addr) {
          baseUrl = `http://localhost:${addr.port}`;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("GET /health and GET /ready return 200", async () => {
    const h = await fetch(`${baseUrl}/health`).then((r) => r.json());
    expect(h.status).toBe("ok");
    const rd = await fetch(`${baseUrl}/ready`).then((r) => r.json());
    expect(rd.status).toBe("ready");
  });

  it("GET /stats returns valid queue and pack metrics", async () => {
    const s = await fetch(`${baseUrl}/stats`).then((r) => r.json());
    expect(Array.isArray(s.status_counts)).toBe(true);
    expect(Array.isArray(s.packs)).toBe(true);
    expect(Array.isArray(s.merkle_chunks)).toBe(true);
  });

  it("GET /queue/clusters lists clusters", async () => {
    const res = await fetch(`${baseUrl}/queue/clusters`).then((r) => r.json());
    expect(Array.isArray(res.clusters)).toBe(true);
  });

  it("POST /queue/clusters/:id/confirm activates pack and enforces 409 conflict", async () => {
    const clusterId = `test_cluster_${Date.now()}`;
    const db = getDb();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO review_queue (lineage_id, extraction_id, candidate_mapping, cluster_id, status, created_at)
      VALUES (?, 0, '{}', ?, 'pending', ?)
    `).run(`lid_${Date.now()}`, clusterId, now);

    // 1. Analyst 1 confirms
    const r1 = await fetch(`${baseUrl}/queue/clusters/${clusterId}/confirm`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actor: "analyst:alice", confirmed_mapping: { src_ip: "$src" } }),
    });
    expect(r1.status).toBe(200);
    const d1 = await r1.json();
    expect(d1.status).toBe("confirmed");
    expect(d1.pack_id).toBeDefined();

    // Verify mapping_packs record created with active status
    const packRow = db.prepare("SELECT status FROM mapping_packs WHERE pack_id = ?").get(d1.pack_id) as { status: string };
    expect(packRow.status).toBe("active");

    // Verify pack_lifecycle_events record
    const eventRow = db.prepare("SELECT event_type, actor FROM pack_lifecycle_events WHERE pack_id = ?").get(d1.pack_id) as { event_type: string; actor: string };
    expect(eventRow.event_type).toBe("pack_confirmed");
    expect(eventRow.actor).toBe("analyst:alice");

    // 2. Analyst 2 confirms concurrently -> 409 Conflict
    const r2 = await fetch(`${baseUrl}/queue/clusters/${clusterId}/confirm`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actor: "analyst:bob", confirmed_mapping: { src_ip: "$src" } }),
    });
    expect(r2.status).toBe(409);
  });

  it("POST /queue/clusters/:id/reject rejects cluster", async () => {
    const clusterId = `test_cluster_rej_${Date.now()}`;
    const db = getDb();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO review_queue (lineage_id, extraction_id, candidate_mapping, cluster_id, status, created_at)
      VALUES (?, 0, '{}', ?, 'pending', ?)
    `).run(`lid_${Date.now()}`, clusterId, now);

    const r = await fetch(`${baseUrl}/queue/clusters/${clusterId}/reject`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actor: "analyst:alice" }),
    });
    expect(r.status).toBe(200);
    const res = await r.json();
    expect(res.status).toBe("rejected");
  });

  it("GET /packs lists mapping packs", async () => {
    const res = await fetch(`${baseUrl}/packs`).then((r) => r.json());
    expect(Array.isArray(res.packs)).toBe(true);
    expect(res.packs.length).toBeGreaterThan(0);
  });

  it("GET /metrics returns Prometheus text and JSON observability metrics", async () => {
    const textRes = await fetch(`${baseUrl}/metrics`);
    expect(textRes.status).toBe(200);
    const text = await textRes.text();
    expect(text).toContain("ulpf_events_ingested_total");
    expect(text).toContain("ulpf_normalized_events_total");

    const jsonRes = await fetch(`${baseUrl}/metrics`, {
      headers: { Accept: "application/json" },
    });
    expect(jsonRes.status).toBe(200);
    const json = await jsonRes.json();
    expect(typeof json.events_ingested_total).toBe("number");
    expect(typeof json.memory_rss_bytes).toBe("number");
  });

  it("POST /queue/clusters/:id/confirm re-normalizes with stripped quotes and enriched OCSF fields", async () => {
    const clusterId = `cluster_norm_test_${Date.now()}`;
    const lineageId = `lid_norm_${Date.now()}`;
    const db = getDb();
    const now = new Date().toISOString();

    // Insert extraction_history with quoted values
    const extFields = JSON.stringify({
      "Src IP": '"172.17.17.130"',
      "Dst IP": '"20.101.57.9"',
      "Src port": '"123"',
      "Dst port": '"123"',
      protocol: '"UDP"',
      "Log subtype": '"Allowed"',
    });

    db.prepare(`
      INSERT INTO raw_events (lineage_id, sha256_hash, ingestion_timestamp, source_ip, source_port, transport_protocol, char_encoding, raw_size_bytes, storage_pointer, chunk_id, merkle_leaf_index, created_at)
      VALUES (?, 'hash_norm_test', ?, '172.17.17.130', 123, 'UDP', 'ASCII', 200, 'raw_store://chunk_1/offset_0', 'chunk_1', 0, ?)
    `).run(lineageId, now, now);

    db.prepare(`
      INSERT INTO extraction_history (lineage_id, path_taken, source_type, parser_version, extracted_fields, confidence_scores, processed_at)
      VALUES (?, 'COLD', 'cold_path_unmapped', '0.1.0-cold', ?, '{}', ?)
    `).run(lineageId, extFields, now);

    const extRow = db.prepare("SELECT extraction_id FROM extraction_history WHERE lineage_id = ?").get(lineageId) as { extraction_id: number };

    // Insert review queue item
    db.prepare(`
      INSERT INTO review_queue (lineage_id, extraction_id, candidate_mapping, cluster_id, status, created_at)
      VALUES (?, ?, '{}', ?, 'pending', ?)
    `).run(lineageId, extRow.extraction_id, clusterId, now);

    // Seed prior unmapped stub in normalization_history
    db.prepare(`
      INSERT INTO normalization_history (lineage_id, extraction_id, ocsf_class_uid, ocsf_event_json, schema_valid, published_to_bus, normalized_at)
      VALUES (?, ?, 4001, '{"class_uid":4001,"activity_name":"Traffic"}', 1, 1, ?)
    `).run(lineageId, extRow.extraction_id, now);

    // Analyst promotes cluster with overrides
    const res = await fetch(`${baseUrl}/queue/clusters/${clusterId}/confirm`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actor: "analyst:kartik",
        overrides: {
          "Src IP": "src_endpoint.ip",
          "Dst IP": "dst_endpoint.ip",
          "Src port": "src_endpoint.port",
          "Dst port": "dst_endpoint.port",
          protocol: "connection_info.protocol_name",
          "Log subtype": "action",
        },
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("confirmed");

    // Verify normalization_history has been replaced with enriched OCSF event
    const normRow = db.prepare("SELECT ocsf_event_json FROM normalization_history WHERE lineage_id = ?").get(lineageId) as { ocsf_event_json: string };
    expect(normRow).toBeDefined();
    const event = JSON.parse(normRow.ocsf_event_json);

    // Verify fields are present, clean, and without quotes
    expect(event.src_endpoint?.ip).toBe("172.17.17.130");
    expect(event.dst_endpoint?.ip).toBe("20.101.57.9");
    expect(event.src_endpoint?.port).toBe(123);
    expect(event.dst_endpoint?.port).toBe(123);
    expect(event.connection_info?.protocol_name).toBe("UDP");
    expect(event.connection_info?.protocol_num).toBe(17);
    expect(event.activity_name).toBe("Open");
    expect(event.activity_id).toBe(1);
  });
});


