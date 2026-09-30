"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { API, StatusTag, ScoreBar, TimeAgo, Pagination } from "../../components/Common";
import { IconLayers, IconSearch, IconRefresh } from "../../components/Icons";

export default function QueuePage() {
  const [clusters, setClusters] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [sortBy, setSortBy] = useState<string>("newest");
  const [searchQuery, setSearchQuery] = useState("");
  const [assigningId, setAssigningId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(20);
  const [total, setTotal] = useState(0);

  const fetchClusters = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams();
    params.set("page", String(page));
    params.set("limit", String(limit));
    params.set("sort", sortBy);
    if (filterStatus !== "all") params.set("status", filterStatus);
    if (searchQuery.trim()) params.set("search", searchQuery.trim());

    fetch(`${API}/queue/clusters?${params.toString()}`)
      .then(r => r.json())
      .then(d => {
        setClusters(d.clusters || []);
        setTotal(d.total || 0);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [page, limit, filterStatus, searchQuery, sortBy]);

  useEffect(() => {
    fetchClusters();
  }, [fetchClusters]);

  const handleStatusFilterChange = (st: string) => {
    setFilterStatus(st);
    setPage(1);
  };

  const handleSearchChange = (val: string) => {
    setSearchQuery(val);
    setPage(1);
  };

  const handleAssign = async (clusterId: string) => {
    setAssigningId(clusterId);
    try {
      const actor = typeof window !== "undefined" ? localStorage.getItem("ulpf_actor") || "kartik vashishtha" : "kartik vashishtha";
      await fetch(`${API}/queue/clusters/${clusterId}/assign`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ assigned_analyst: actor }),
      });
      fetchClusters();
    } catch {
      // ignore
    } finally {
      setAssigningId(null);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="panel-card" style={{ padding: 0, overflow: "hidden" }}>
        {/* Header Toolbar */}
        <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", background: "var(--bg-subtle)", borderBottom: "1px solid var(--border-subtle)", gap: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <IconLayers style={{ width: 18, height: 18, color: "var(--accent-blue)" }} />
            <div>
              <strong style={{ fontSize: 13, color: "var(--text-primary)" }}>Cold-Path Review Queue</strong>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>Drain3 Discovered Template Clusters ({total.toLocaleString()} total · Newest First)</div>
            </div>
          </div>

          <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}>
            <button className="btn-secondary" style={{ fontSize: 11, padding: "3px 8px" }} onClick={fetchClusters}>
              <IconRefresh className="nav-icon" style={{ width: 12, height: 12 }} />
              <span>Refresh</span>
            </button>

            {/* Sort Toggle */}
            <div style={{ display: "flex", background: "var(--border-subtle)", padding: 2, borderRadius: 6 }}>
              {[
                { id: "newest", label: "NEWEST FIRST" },
                { id: "samples", label: "MOST SAMPLES" },
                { id: "oldest", label: "OLDEST" },
              ].map(s => (
                <button
                  key={s.id}
                  className={`filter-tab ${sortBy === s.id ? "active" : ""}`}
                  onClick={() => { setSortBy(s.id); setPage(1); }}
                  title={`Sort clusters by ${s.label.toLowerCase()}`}
                >
                  {s.label}
                </button>
              ))}
            </div>

            {/* Filter Tabs */}
            <div style={{ display: "flex", background: "var(--border-subtle)", padding: 2, borderRadius: 6 }}>
              {["all", "pending", "in_review", "confirmed", "rejected"].map(st => (
                <button
                  key={st}
                  className={`filter-tab ${filterStatus === st ? "active" : ""}`}
                  onClick={() => handleStatusFilterChange(st)}
                >
                  {st.replace("_", " ").toUpperCase()}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Search Bar within table */}
        <div style={{ padding: "8px 16px", background: "#ffffff", borderBottom: "1px solid var(--border-subtle)", display: "flex", alignItems: "center", gap: 8 }}>
          <IconSearch style={{ width: 14, height: 14, color: "var(--text-muted)" }} />
          <input
            placeholder="Search by cluster ID or source device (e.g. cluster-0288, cisco_asa)..."
            value={searchQuery}
            onChange={e => handleSearchChange(e.target.value)}
            style={{ width: 340, border: "none", outline: "none", fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--text-primary)" }}
          />
          {searchQuery && (
            <button onClick={() => handleSearchChange("")} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)", fontSize: 12 }}>
              ✕
            </button>
          )}
        </div>

        {loading ? (
          <div style={{ padding: 40, textAlign: "center", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
            Loading clusters from database...
          </div>
        ) : clusters.length === 0 ? (
          <div style={{ padding: 40, textAlign: "center", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
            No clusters match current filter.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="stitch-table">
              <thead>
                <tr>
                  <th>Cluster ID</th>
                  <th>Status</th>
                  <th>Device Source</th>
                  <th>Samples</th>
                  <th>Confidence</th>
                  <th>Latest Event</th>
                  <th>Analyst Assigned</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {clusters.map(c => (
                  <tr key={c.cluster_id}>
                    <td>
                      <span className="text-mono" style={{ fontWeight: 700, color: "var(--accent-blue)" }}>
                        {c.cluster_id}
                      </span>
                    </td>
                    <td>
                      <StatusTag status={c.status || "pending"} />
                    </td>
                    <td>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, background: "var(--bg-subtle)", padding: "2px 6px", borderRadius: 4 }}>
                        {c.source_type || "cisco_asa"}
                      </span>
                    </td>
                    <td>
                      <strong style={{ color: "var(--text-primary)" }}>{c.sample_count}</strong>
                    </td>
                    <td>
                      <ScoreBar score={c.status === "confirmed" ? 0.95 : 0.72} />
                    </td>
                    <td style={{ color: "var(--text-muted)", fontSize: 11 }}>
                      <TimeAgo iso={c.newest_at || c.oldest_at} />
                    </td>
                    <td>
                      {c.assigned_analyst ? (
                        <span style={{ fontSize: 11, color: "var(--text-primary)", fontWeight: 600 }}>
                          {c.assigned_analyst}
                        </span>
                      ) : (
                        <button
                          id="cluster-assign-btn"
                          className="btn-secondary"
                          style={{ fontSize: 10, padding: "2px 6px" }}
                          onClick={() => handleAssign(c.cluster_id)}
                          disabled={assigningId === c.cluster_id}
                        >
                          {assigningId === c.cluster_id ? "Assigning..." : "Assign to Me"}
                        </button>
                      )}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <Link
                        href={`/queue/${c.cluster_id}`}
                        className="btn-primary"
                        style={{ fontSize: 11, padding: "4px 10px", textDecoration: "none", display: "inline-flex" }}
                      >
                        Inspect &amp; Map →
                      </Link>
                    </td>
                  </tr>
                ))}
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
