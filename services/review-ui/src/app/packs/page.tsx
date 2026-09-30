"use client";

import React, { useState, useEffect } from "react";
import { API, StatusTag, TimeAgo } from "../../components/Common";
import { IconPacks, IconSearch } from "../../components/Icons";

export default function PacksPage() {
  const [packs, setPacks] = useState<any[]>([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API}/packs`)
      .then(r => r.json())
      .then(d => {
        setPacks(d.packs || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const filtered = packs.filter(p => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return p.pack_id?.toLowerCase().includes(q) || p.source_type?.toLowerCase().includes(q);
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="panel-card" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", background: "var(--bg-subtle)", borderBottom: "1px solid var(--border-subtle)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <IconPacks style={{ width: 18, height: 18, color: "var(--accent-blue)" }} />
            <strong style={{ fontSize: 13, color: "var(--text-primary)" }}>Active Mapping &amp; Ingestion Parser Packs</strong>
            <span className="text-mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>RCU JIT Engine Bytecode Registry</span>
          </div>
          <span className="status-tag status-tag-confirmed">{packs.length} Active Packs</span>
        </div>

        <div style={{ padding: "8px 16px", background: "#ffffff", borderBottom: "1px solid var(--border-subtle)", display: "flex", alignItems: "center", gap: 8 }}>
          <IconSearch style={{ width: 14, height: 14, color: "var(--text-muted)" }} />
          <input
            placeholder="Search parser packs by name or source..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ width: 280, border: "none", outline: "none", fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--text-primary)" }}
          />
        </div>

        {loading ? (
          <div style={{ padding: 40, textAlign: "center", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
            Loading parser packs from SQLite ledger...
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="stitch-table">
              <thead>
                <tr>
                  <th>Pack ID</th>
                  <th>Source</th>
                  <th>Version</th>
                  <th>Status</th>
                  <th>Promoted Date</th>
                  <th style={{ textAlign: "right" }}>Digest / Signature</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(p => (
                  <tr key={p.pack_id}>
                    <td style={{ fontWeight: 700, color: "var(--text-primary)" }}>{p.pack_id}</td>
                    <td><span className="status-tag status-tag-neutral">{p.source_type}</span></td>
                    <td><span className="text-mono" style={{ fontSize: 11 }}>v{p.version}</span></td>
                    <td><StatusTag status={p.status} /></td>
                    <td style={{ color: "var(--text-muted)", fontSize: 11 }}>
                      {p.promoted_at ? <TimeAgo iso={p.promoted_at} /> : "Pending"}
                    </td>
                    <td style={{ textAlign: "right", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                      {p.pack_yaml_hash ? `0x${p.pack_yaml_hash.slice(0, 10)}...` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
