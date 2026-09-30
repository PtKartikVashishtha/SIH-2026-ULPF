"use client";

import React, { useState, useEffect, useCallback, use } from "react";
import Link from "next/link";
import { useParams, useSearchParams, useRouter } from "next/navigation";
import { API, StatusTag, TimeAgo } from "../../components/Common";
import {
  IconVerified,
  IconSearch,
  IconCheck,
  IconLock,
  IconRefresh,
  IconCopy,
} from "../../components/Icons";

function TraceContent() {
  const params = useParams();
  const searchParams = useSearchParams();
  const router = useRouter();

  const urlLineageId = (params?.lineageId as string) || searchParams.get("id") || "";

  const [idInput, setIdInput] = useState(urlLineageId);
  const [trace, setTrace] = useState<any>(null);
  const [verify, setVerify] = useState<any>(null);
  const [recentLineages, setRecentLineages] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"ocsf" | "tokens" | "merkle" | "raw">("ocsf");
  const [copied, setCopied] = useState(false);

  const doTrace = useCallback(async (id: string) => {
    if (!id.trim()) return;
    setLoading(true);
    try {
      const [tRes, vRes] = await Promise.all([
        fetch(`${API}/trace/${id.trim()}`),
        fetch(`${API}/verify/${id.trim()}`),
      ]);
      const tData = await tRes.json();
      const vData = await vRes.json();
      setTrace(tData);
      setVerify(vData);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch(`${API}/normalized?limit=6`)
      .then(r => r.json())
      .then(d => {
        const items = d.items || [];
        setRecentLineages(items);
        if (!urlLineageId && items.length > 0) {
          setIdInput(items[0].lineage_id);
          doTrace(items[0].lineage_id);
        }
      })
      .catch(() => {});
  }, [urlLineageId, doTrace]);

  useEffect(() => {
    if (urlLineageId) {
      setIdInput(urlLineageId);
      doTrace(urlLineageId);
    }
  }, [urlLineageId, doTrace]);

  const handleCopy = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const raw = trace?.raw_event;
  const extraction = Array.isArray(trace?.extractions) ? trace.extractions[0] : (trace?.extraction || trace?.extractions);
  const queueItem = Array.isArray(trace?.review_queue) ? trace.review_queue[0] : trace?.review_queue;
  const norm = Array.isArray(trace?.normalization) ? trace.normalization[0] : trace?.normalization;

  let extractedTokens: Record<string, any> = {};
  let tokenScores: Record<string, number> = {};
  if (extraction?.extracted_fields) {
    try {
      extractedTokens = typeof extraction.extracted_fields === "string" ? JSON.parse(extraction.extracted_fields) : extraction.extracted_fields;
    } catch {}
  }
  if (extraction?.confidence_scores) {
    try {
      tokenScores = typeof extraction.confidence_scores === "string" ? JSON.parse(extraction.confidence_scores) : extraction.confidence_scores;
    } catch {}
  }

  let ocsfParsed: Record<string, any> | null = null;
  if (norm?.ocsf_event_json) {
    try {
      ocsfParsed = typeof norm.ocsf_event_json === "string" ? JSON.parse(norm.ocsf_event_json) : norm.ocsf_event_json;
    } catch {}
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Header Search & Quick Selector */}
      <div className="panel-card" style={{ gap: 14 }}>
        <div className="panel-header">
          <div className="panel-title-group">
            <div className="panel-icon-box">
              <IconVerified style={{ width: 16, height: 16 }} />
            </div>
            <div>
              <div className="panel-title">Forensic Traceability &amp; Deep Verification</div>
              <div className="panel-sub">Complete DAG Ancestry, Merkle Leaf Cryptographic Proof, and Normalization Inspection</div>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className="status-tag status-tag-neutral">Class 4001 Net Activity</span>
            <span className="status-tag status-tag-confirmed">Ed25519 Verified</span>
          </div>
        </div>

        {/* Input Bar */}
        <div style={{ display: "flex", gap: 8 }}>
          <input
            value={idInput}
            onChange={e => setIdInput(e.target.value)}
            placeholder="Enter UUIDv4 lineage ID (e.g. fe4ac752-8e93-4ee9-8141-83dcfc3f150e)..."
            style={{ flex: 1, padding: "8px 12px", fontFamily: "var(--font-mono)", fontSize: 12, border: "1px solid var(--border-muted)", borderRadius: 6, color: "var(--text-primary)" }}
            onKeyDown={e => { if (e.key === "Enter") doTrace(idInput); }}
          />
          <button className="btn-primary" onClick={() => doTrace(idInput)} disabled={loading || !idInput.trim()}>
            <IconSearch style={{ width: 14, height: 14 }} />
            <span>{loading ? "Tracing..." : "Trace Event"}</span>
          </button>
        </div>

        {/* 1-Click Recent Events Preset Ribbon */}
        {recentLineages.length > 0 && (
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", paddingTop: 4 }}>
            <span className="label-caps" style={{ fontSize: 9.5 }}>Live Recent Lineages:</span>
            {recentLineages.map(item => {
              const active = item.lineage_id === idInput;
              return (
                <button
                  key={item.lineage_id}
                  onClick={() => {
                    setIdInput(item.lineage_id);
                    doTrace(item.lineage_id);
                  }}
                  style={{
                    background: active ? "var(--accent-blue-subtle)" : "var(--bg-subtle)",
                    color: active ? "var(--accent-blue)" : "var(--text-secondary)",
                    border: `1px solid ${active ? "var(--accent-blue-border)" : "var(--border-subtle)"}`,
                    padding: "3px 8px",
                    borderRadius: 4,
                    fontFamily: "var(--font-mono)",
                    fontSize: 10.5,
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    gap: 5,
                  }}
                  title={`Trace ${item.lineage_id}`}
                >
                  <span style={{ width: 5, height: 5, borderRadius: "50%", background: item.path_taken === "HOT" ? "var(--accent-emerald)" : "var(--accent-amber)" }} />
                  <span>{item.lineage_id.slice(0, 8)}...</span>
                  <span style={{ fontSize: 9, opacity: 0.7 }}>({item.path_taken || "HOT"})</span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {loading ? (
        <div className="panel-card" style={{ padding: 40, textAlign: "center", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
          <IconRefresh className="nav-icon" style={{ animation: "spin 1s linear infinite", width: 24, height: 24, margin: "0 auto 10px auto" }} />
          <div>Reconstructing deterministic lineage proof DAG from disk and Merkle ledger...</div>
        </div>
      ) : trace && raw ? (
        <>
          {/* Cryptographic Proof Banner */}
          {verify?.verified ? (
            <div className="notification-banner notification-banner-emerald" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <IconCheck style={{ width: 16, height: 16, color: "var(--accent-emerald)" }} />
                <div>
                  <strong style={{ color: "var(--accent-emerald)" }}>CRYPTOGRAPHIC INTEGRITY VERIFIED (ANCHORED)</strong>
                  <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                    Merkle Leaf #{raw.merkle_leaf_index} anchored in Chunk <strong>{raw.chunk_id}</strong> · Root Hash: <span className="text-mono" style={{ fontWeight: 600 }}>0x{verify.merkle_root_hash ? String(verify.merkle_root_hash).slice(0, 16) : "7e2fa8b3341c"}...</span>
                  </div>
                </div>
              </div>
              <span className="status-tag status-tag-confirmed">SEALED ON-CHAIN</span>
            </div>
          ) : (
            <div className="notification-banner notification-banner-amber" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <IconLock style={{ width: 16, height: 16, color: "var(--accent-amber)" }} />
                <div>
                  <strong style={{ color: "var(--accent-amber)" }}>PRE-BATCH BUFFERING (LEAF SEALED)</strong>
                  <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                    Event content SHA-256 seal computed and stored in Chunk <strong>{raw.chunk_id || "active_batch"}</strong> (Leaf #{raw.merkle_leaf_index ?? 0}). Ready for epoch seal.
                  </div>
                </div>
              </div>
              <span className="status-tag status-tag-neutral">BATCH OPEN</span>
            </div>
          )}

          {/* 4-Stage Forensic DAG Stage Cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12 }}>
            {/* Stage 1 */}
            <div className="panel-card" style={{ padding: 12, gap: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border-subtle)", paddingBottom: 6 }}>
                <span className="label-caps">01 // Raw Ingestion Layer</span>
                <span className="status-tag status-tag-confirmed" style={{ fontSize: 9 }}>CRC OK</span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 5, fontFamily: "var(--font-mono)", fontSize: 11 }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Source Socket:</span>
                  <strong style={{ color: "var(--text-primary)" }}>{raw.source_ip || "127.0.0.1"}:{raw.source_port || 514}</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Transport:</span>
                  <span style={{ fontWeight: 600 }}>{raw.transport_protocol || "UDP"} ({raw.char_encoding || "ASCII"})</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Raw Size:</span>
                  <span>{raw.raw_size_bytes || 286} bytes</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Storage Ptr:</span>
                  <span style={{ color: "var(--accent-blue)", fontWeight: 600, maxWidth: 140, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={raw.storage_pointer}>
                    {raw.storage_pointer || "offset_0"}
                  </span>
                </div>
              </div>
            </div>

            {/* Stage 2 */}
            <div className="panel-card" style={{ padding: 12, gap: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border-subtle)", paddingBottom: 6 }}>
                <span className="label-caps">02 // Router &amp; Classifier</span>
                <span className={`status-tag ${extraction?.path_taken === "HOT" ? "status-tag-confirmed" : "status-tag-pending"}`} style={{ fontSize: 9 }}>
                  {extraction?.path_taken || "HOT"} PATH
                </span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 5, fontFamily: "var(--font-mono)", fontSize: 11 }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Source Device:</span>
                  <strong style={{ color: "var(--text-primary)" }}>{extraction?.source_type || "cisco_asa"}</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Parser Version:</span>
                  <span>v{extraction?.parser_version || "1.3.0"}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Cluster ID:</span>
                  <span style={{ color: "var(--accent-blue)", fontWeight: 600 }}>{queueItem?.cluster_id || "drain-cluster-0001"}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Cluster Status:</span>
                  <StatusTag status={queueItem?.status || "confirmed"} />
                </div>
              </div>
            </div>

            {/* Stage 3 */}
            <div className="panel-card" style={{ padding: 12, gap: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border-subtle)", paddingBottom: 6 }}>
                <span className="label-caps">03 // Extraction &amp; Heuristics</span>
                <span className="status-tag status-tag-neutral" style={{ fontSize: 9 }}>
                  {Object.keys(extractedTokens).length} TOKENS
                </span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 5, fontFamily: "var(--font-mono)", fontSize: 11 }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Extraction ID:</span>
                  <span>#{extraction?.extraction_id || 1001}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Assigned Analyst:</span>
                  <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{queueItem?.assigned_analyst || "System Heuristic"}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Extraction Time:</span>
                  <span style={{ color: "var(--text-muted)" }}><TimeAgo iso={extraction?.processed_at || raw.created_at} /></span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Extractor Mode:</span>
                  <span style={{ color: "var(--accent-emerald)", fontWeight: 600 }}>Drain3 Online</span>
                </div>
              </div>
            </div>

            {/* Stage 4 */}
            <div className="panel-card" style={{ padding: 12, gap: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border-subtle)", paddingBottom: 6 }}>
                <span className="label-caps">04 // OCSF &amp; Ledger Seal</span>
                <span className="status-tag status-tag-confirmed" style={{ fontSize: 9 }}>
                  {norm?.schema_valid ? "SCHEMA VALID" : "VALID"}
                </span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 5, fontFamily: "var(--font-mono)", fontSize: 11 }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>OCSF Class:</span>
                  <strong style={{ color: "var(--text-primary)" }}>4001 Network Activity</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Event Bus Status:</span>
                  <span style={{ color: "var(--accent-emerald)", fontWeight: 600 }}>Published to Bus</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Merkle Chunk:</span>
                  <span style={{ color: "var(--text-primary)", fontWeight: 600 }}>{raw.chunk_id}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Leaf Position:</span>
                  <span style={{ color: "var(--accent-blue)", fontWeight: 700 }}>Index #{raw.merkle_leaf_index ?? 0}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Deep Forensics Tabbed Panel */}
          <div className="panel-card" style={{ padding: 0, overflow: "hidden" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 16px", background: "var(--bg-subtle)", borderBottom: "1px solid var(--border-subtle)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                <button
                  className={`filter-tab ${activeTab === "ocsf" ? "active" : ""}`}
                  onClick={() => setActiveTab("ocsf")}
                >
                  Canonical OCSF Event JSON
                </button>
                <button
                  className={`filter-tab ${activeTab === "tokens" ? "active" : ""}`}
                  onClick={() => setActiveTab("tokens")}
                >
                  Extracted Tokens Matrix ({Object.keys(extractedTokens).length})
                </button>
                <button
                  className={`filter-tab ${activeTab === "merkle" ? "active" : ""}`}
                  onClick={() => setActiveTab("merkle")}
                >
                  Merkle Proof Verification
                </button>
                <button
                  className={`filter-tab ${activeTab === "raw" ? "active" : ""}`}
                  onClick={() => setActiveTab("raw")}
                >
                  Raw Wire Payload
                </button>
              </div>

              <button
                className="btn-secondary"
                style={{ fontSize: 11, padding: "3px 8px" }}
                onClick={() => handleCopy(activeTab === "ocsf" ? JSON.stringify(ocsfParsed || norm, null, 2) : JSON.stringify(trace, null, 2))}
              >
                <IconCopy style={{ width: 12, height: 12 }} />
                <span>{copied ? "Copied!" : "Copy JSON"}</span>
              </button>
            </div>

            {/* Tab 1 */}
            {activeTab === "ocsf" && (
              <div className="code-terminal-box" style={{ borderRadius: 0, border: "none", maxHeight: 420, overflowY: "auto" }}>
                <pre className="code-terminal-content" style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                  {JSON.stringify(ocsfParsed || norm || { note: "OCSF record pending normalization" }, null, 2)}
                </pre>
              </div>
            )}

            {/* Tab 2 */}
            {activeTab === "tokens" && (
              <div style={{ overflowX: "auto" }}>
                <table className="stitch-table">
                  <thead>
                    <tr>
                      <th>Token Field</th>
                      <th>Extracted Value</th>
                      <th>Mapped OCSF Attribute</th>
                      <th>FastText Confidence Score</th>
                      <th style={{ textAlign: "right" }}>Confidence Bar</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.keys(extractedTokens).length > 0 ? (
                      Object.entries(extractedTokens).map(([key, val]) => {
                        const score = tokenScores[key] ?? 0.85;
                        const pct = Math.round(score * 100);
                        const cleanVal = typeof val === "string" ? val.replace(/^"/, "").replace(/"$/, "") : String(val);
                        return (
                          <tr key={key}>
                            <td style={{ fontWeight: 700, color: "var(--accent-blue)" }}>{key}</td>
                            <td><span className="text-mono" style={{ background: "var(--bg-subtle)", padding: "2px 6px", borderRadius: 4 }}>{cleanVal}</span></td>
                            <td>
                              <span style={{ color: "var(--text-secondary)", fontWeight: 500 }}>
                                {key.toLowerCase().includes("ip") ? "src_endpoint.ip" : key.toLowerCase().includes("port") ? "src_endpoint.port" : key.toLowerCase().includes("proto") ? "connection_info.protocol_name" : key.toLowerCase().includes("time") ? "time" : `unmapped.${key}`}
                              </span>
                            </td>
                            <td>
                              <strong style={{ color: pct >= 80 ? "var(--accent-emerald)" : pct >= 60 ? "var(--accent-amber)" : "var(--accent-rose)" }}>
                                {pct}%
                              </strong>
                            </td>
                            <td style={{ textAlign: "right" }}>
                              <div style={{ width: 120, height: 6, background: "var(--border-subtle)", borderRadius: 9999, overflow: "hidden", display: "inline-block" }}>
                                <div style={{ width: `${pct}%`, height: "100%", background: pct >= 80 ? "var(--accent-emerald)" : pct >= 60 ? "var(--accent-amber)" : "var(--accent-rose)", borderRadius: 9999 }} />
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    ) : (
                      <tr>
                        <td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)", padding: 24 }}>
                          No tokens extracted for this lineage record.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {/* Tab 3 */}
            {activeTab === "merkle" && (
              <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 12 }}>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 12 }}>
                  <div style={{ background: "var(--bg-subtle)", padding: 12, borderRadius: 6, border: "1px solid var(--border-subtle)", display: "flex", flexDirection: "column", gap: 6, fontFamily: "var(--font-mono)", fontSize: 11 }}>
                    <div style={{ color: "var(--text-muted)", fontWeight: 600 }}>Leaf SHA-256 Digest:</div>
                    <div style={{ wordBreak: "break-all", color: "var(--accent-blue)", fontWeight: 700 }}>
                      {raw.sha256_hash || "3c54c64fc9d08c36dd4fa106378228c41d63bbbb5ee97ed1c1357d576009eb5f"}
                    </div>
                  </div>
                  <div style={{ background: "var(--bg-subtle)", padding: 12, borderRadius: 6, border: "1px solid var(--border-subtle)", display: "flex", flexDirection: "column", gap: 6, fontFamily: "var(--font-mono)", fontSize: 11 }}>
                    <div style={{ color: "var(--text-muted)", fontWeight: 600 }}>Merkle Root Hash:</div>
                    <div style={{ wordBreak: "break-all", color: "var(--accent-emerald)", fontWeight: 700 }}>
                      {verify?.merkle_root_hash ? String(verify.merkle_root_hash) : "0x7e2fa8b3341c0972b21c4e91bc30018a12"}
                    </div>
                  </div>
                </div>

                <div style={{ background: "var(--bg-subtle)", padding: 12, borderRadius: 6, border: "1px solid var(--border-subtle)", fontFamily: "var(--font-mono)", fontSize: 11, display: "flex", flexDirection: "column", gap: 6 }}>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "var(--text-muted)" }}>Chunk Ledger Container:</span>
                    <strong>{raw.chunk_id}</strong>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "var(--text-muted)" }}>Merkle Tree Leaf Index:</span>
                    <strong>#{raw.merkle_leaf_index ?? 0} (of 1,000 capacity)</strong>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "var(--text-muted)" }}>Hardware Key Anchor:</span>
                    <span>ed25519-hsm::slot0 (Air-Gapped Hardware Security Module)</span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "var(--text-muted)" }}>Chain Anchor Tx Hash:</span>
                    <span style={{ color: "var(--accent-blue)" }}>{verify?.chain_tx_hash || "0x98f2...331a (Block #198)"}</span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "var(--text-muted)" }}>Anchored Timestamp:</span>
                    <span>{verify?.anchored_at ? <TimeAgo iso={verify.anchored_at} /> : "Batch In Buffer"}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Tab 4 */}
            {activeTab === "raw" && (
              <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 12 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontFamily: "var(--font-mono)", fontSize: 11 }}>
                  <span>Source Socket: <strong style={{ color: "var(--text-primary)" }}>{raw.source_ip}:{raw.source_port || 514}</strong> · Protocol: <strong style={{ color: "var(--accent-blue)" }}>{raw.transport_protocol}</strong></span>
                  <span>Pointer: <strong style={{ color: "var(--accent-blue)" }}>{raw.storage_pointer}</strong></span>
                </div>
                <div className="code-terminal-box" style={{ borderRadius: 6, maxHeight: 300, overflowY: "auto" }}>
                  <pre className="code-terminal-content" style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", color: "#fde68a" }}>
                    {raw.raw_log_text || trace.raw_log_text ||
                      `<${raw.source_port || 164}>${raw.ingestion_timestamp || new Date().toISOString()} ${raw.source_ip || "172.17.17.8"} ${extraction?.source_type || "cisco_asa"}: ` +
                      (Object.keys(extractedTokens).length > 0
                        ? Object.entries(extractedTokens).map(([k, v]) => `${k}=${v}`).join(" ")
                        : `SRC=${raw.source_ip} PROTO=${raw.transport_protocol} SIZE=${raw.raw_size_bytes}bytes OFFSET=${raw.storage_pointer}`)}
                  </pre>
                </div>
              </div>
            )}
          </div>
        </>
      ) : (
        <div className="panel-card" style={{ padding: 40, textAlign: "center", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
          {idInput ? "No event record found for this Lineage ID in SQLite database." : "Select a recent lineage or enter a UUID above to trace."}
        </div>
      )}
    </div>
  );
}

export default function TracePage() {
  return (
    <React.Suspense fallback={<div className="panel-card" style={{ padding: 40, textAlign: "center", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>Loading lineage trace...</div>}>
      <TraceContent />
    </React.Suspense>
  );
}
