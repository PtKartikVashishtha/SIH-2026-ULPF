"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { API, TimeAgo, Pagination } from "../../components/Common";
import { IconTerminal, IconRefresh, IconSearch } from "../../components/Icons";

export default function NormalizedPage() {
  const [items, setItems] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(25);
  const [total, setTotal] = useState(0);
  const [pathFilter, setPathFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");

  const fetchItems = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams();
    params.set("page", String(page));
    params.set("limit", String(limit));
    if (pathFilter !== "all") params.set("path", pathFilter);
    if (searchQuery.trim()) params.set("search", searchQuery.trim());

    fetch(`${API}/normalized?${params.toString()}`)
      .then(r => r.json())
      .then(d => {
        setItems(d.items || d.events || []);
        setTotal(d.total || 0);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [page, limit, pathFilter, searchQuery]);

  useEffect(() => {
    fetchItems();
  }, [fetchItems]);

  const handlePathFilterChange = (p: string) => {
    setPathFilter(p);
    setPage(1);
  };

  const handleSearchChange = (val: string) => {
    setSearchQuery(val);
    setPage(1);
  };

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="panel-card" style={{ padding: 0, overflow: "hidden" }}>
        {/* Header Toolbar */}
        <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", background: "var(--bg-subtle)", borderBottom: "1px solid var(--border-subtle)", gap: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <IconTerminal style={{ width: 18, height: 18, color: "var(--accent-blue)" }} />
            <div>
              <strong style={{ fontSize: 13, color: "var(--text-primary)" }}>Canonical OCSF 4001 Security Event Stream</strong>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                Streaming live normalized security telemetry ({total.toLocaleString()} total events in ledger)
              </div>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <button className="btn-secondary" style={{ fontSize: 11, padding: "3px 8px" }} onClick={fetchItems}>
              <IconRefresh className="nav-icon" style={{ width: 12, height: 12 }} />
              <span>Refresh</span>
            </button>
            {/* Path Filter Tabs */}
            <div style={{ display: "flex", background: "var(--border-subtle)", padding: 2, borderRadius: 6 }}>
              {["all", "HOT", "COLD"].map(p => (
                <button
                  key={p}
                  className={`filter-tab ${pathFilter === p ? "active" : ""}`}
                  onClick={() => handlePathFilterChange(p)}
                >
                  {p === "all" ? "ALL PATHS" : `${p} PATH`}
                </button>
              ))}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--accent-emerald)" }} />
              <span className="text-mono" style={{ color: "var(--accent-emerald)", fontWeight: 700, fontSize: 10 }}>LIVE</span>
            </div>
          </div>
        </div>

        {/* Search Bar within table */}
        <div style={{ padding: "8px 16px", background: "#ffffff", borderBottom: "1px solid var(--border-subtle)", display: "flex", alignItems: "center", gap: 8 }}>
          <IconSearch style={{ width: 14, height: 14, color: "var(--text-muted)" }} />
          <input
            placeholder="Search by Lineage ID, Source IP, Device, or OCSF payload..."
            value={searchQuery}
            onChange={e => handleSearchChange(e.target.value)}
            style={{ width: 360, border: "none", outline: "none", fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--text-primary)" }}
          />
          {searchQuery && (
            <button onClick={() => handleSearchChange("")} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)", fontSize: 12 }}>
              ✕
            </button>
          )}
        </div>

        {loading ? (
          <div style={{ padding: 40, textAlign: "center", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
            Loading stream events...
          </div>
        ) : items.length === 0 ? (
          <div style={{ padding: 40, textAlign: "center", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
            No normalized events match current filter.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="stitch-table">
              <thead>
                <tr>
                  <th style={{ width: 32 }}></th>
                  <th>Lineage ID</th>
                  <th>Activity</th>
                  <th>Endpoint Flow</th>
                  <th>Route Path</th>
                  <th>Normalized Time</th>
                  <th style={{ textAlign: "right" }}>Forensics</th>
                </tr>
              </thead>
              <tbody>
                {items.map(item => {
                  const ocsf = typeof item.ocsf_event === "string" ? JSON.parse(item.ocsf_event) : item.ocsf_event;
                  const src = ocsf?.src_endpoint?.ip ?? item.source_ip ?? "—";
                  const dst = ocsf?.dst_endpoint?.ip ?? "—";
                  const isExpanded = expandedId === item.lineage_id;
                  const jsonStr = JSON.stringify(ocsf, null, 2);

                  return (
                    <React.Fragment key={item.lineage_id}>
                      <tr
                        style={{ cursor: "pointer", background: isExpanded ? "var(--bg-subtle)" : undefined }}
                        onClick={() => setExpandedId(prev => prev === item.lineage_id ? null : item.lineage_id)}
                      >
                        <td style={{ textAlign: "center", color: isExpanded ? "var(--accent-blue)" : "var(--text-muted)", fontSize: 13, userSelect: "none" }}>
                          {isExpanded ? "▼" : "▶"}
                        </td>
                        <td style={{ fontFamily: "var(--font-mono)", fontWeight: 600, color: "var(--accent-blue)" }}>
                          {item.lineage_id.slice(0, 18)}...
                        </td>
                        <td>
                          <strong>{ocsf?.activity_name || "Traffic"}</strong>
                          <span style={{ marginLeft: 6, fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                            (Class {ocsf?.class_uid || 4001})
                          </span>
                        </td>
                        <td>
                          <span className="text-mono" style={{ color: "var(--text-secondary)" }}>{src} → {dst}</span>
                        </td>
                        <td>
                          <span className={`status-tag ${item.path_taken === "HOT" ? "status-tag-confirmed" : "status-tag-pending"}`}>
                            {item.path_taken || "HOT"}
                          </span>
                        </td>
                        <td style={{ color: "var(--text-muted)", fontSize: 11 }}>
                          <TimeAgo iso={item.normalized_at} />
                        </td>
                        <td style={{ textAlign: "right" }} onClick={e => e.stopPropagation()}>
                          <Link
                            href={`/trace/${item.lineage_id}`}
                            className="btn-secondary"
                            style={{ fontSize: 10, padding: "2px 8px", textDecoration: "none", display: "inline-flex" }}
                          >
                            Trace →
                          </Link>
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr style={{ background: "var(--bg-canvas)" }}>
                          <td colSpan={7} style={{ padding: "16px 20px" }}>
                            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                              {/* Top Bar: Ingestion Source Provenance Details */}
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: "var(--bg-subtle)", padding: "10px 14px", borderRadius: 6, border: "1px solid var(--border-subtle)", fontFamily: "var(--font-mono)", fontSize: 11, flexWrap: "wrap", gap: 8 }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                                  <span>Source Socket: <strong style={{ color: "var(--text-primary)" }}>{item.source_ip || "127.0.0.1"}:514</strong></span>
                                  <span style={{ color: "var(--border-muted)" }}>·</span>
                                  <span>Protocol: <strong>{item.transport_protocol || "UDP"}</strong></span>
                                  <span style={{ color: "var(--border-muted)" }}>·</span>
                                  <span>Storage Pointer: <strong style={{ color: "var(--accent-blue)" }}>{item.storage_pointer || "offset_0"}</strong></span>
                                </div>
                                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                  <span className="status-tag status-tag-confirmed" style={{ fontSize: 9 }}>OCSF 4001 VALID</span>
                                  <Link
                                    href={`/trace/${item.lineage_id}`}
                                    className="btn-secondary"
                                    style={{ fontSize: 10, padding: "2px 8px", textDecoration: "none" }}
                                  >
                                    Full Forensic DAG Trace →
                                  </Link>
                                  <button
                                    className="btn-secondary"
                                    style={{ fontSize: 10, padding: "2px 8px", color: "var(--accent-rose)", borderColor: "var(--border-subtle)" }}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setExpandedId(null);
                                    }}
                                    title="Close details"
                                  >
                                    ✕ Close
                                  </button>
                                </div>
                              </div>

                              {/* Two Column Layout: Raw Log vs Final Normalized OCSF JSON */}
                              <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)", gap: 14 }}>
                                {/* Left Column: Verbatim Raw Log from Source */}
                                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                      <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--accent-amber)" }} />
                                      <span className="label-caps" style={{ color: "var(--text-primary)", fontWeight: 700 }}>
                                        01 // Verbatim Raw Log (From Source)
                                      </span>
                                    </div>
                                    <button
                                      className="btn-secondary"
                                      style={{ fontSize: 10, padding: "2px 8px" }}
                                      onClick={() => handleCopy("raw-" + item.lineage_id, item.raw_log_text || "")}
                                    >
                                      {copiedId === "raw-" + item.lineage_id ? "Copied!" : "Copy Raw Log"}
                                    </button>
                                  </div>
                                  <div className="code-terminal-box" style={{ borderRadius: 6, height: 280, overflowY: "auto" }}>
                                    <pre className="code-terminal-content" style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", color: "#fde68a", fontSize: 11 }}>
                                      {item.raw_log_text || `SRC=${item.source_ip || "127.0.0.1"} PROTO=${item.transport_protocol || "UDP"} POINTER=${item.storage_pointer}`}
                                    </pre>
                                  </div>
                                </div>

                                {/* Right Column: Final Normalized OCSF Event JSON */}
                                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                      <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--accent-emerald)" }} />
                                      <span className="label-caps" style={{ color: "var(--accent-blue)", fontWeight: 700 }}>
                                        02 // Final Normalized Log (OCSF 4001 JSON)
                                      </span>
                                    </div>
                                    <button
                                      className="btn-secondary"
                                      style={{ fontSize: 10, padding: "2px 8px" }}
                                      onClick={() => handleCopy("ocsf-" + item.lineage_id, jsonStr)}
                                    >
                                      {copiedId === "ocsf-" + item.lineage_id ? "Copied!" : "Copy JSON"}
                                    </button>
                                  </div>
                                  <div className="code-terminal-box" style={{ borderRadius: 6, height: 280, overflowY: "auto" }}>
                                    <pre className="code-terminal-content" style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", fontSize: 11 }}>
                                      {jsonStr}
                                    </pre>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        <Pagination
          page={page}
          limit={limit}
          total={total}
          onPageChange={setPage}
          onLimitChange={setLimit}
        />
      </div>
    </div>
  );
}
