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
});
