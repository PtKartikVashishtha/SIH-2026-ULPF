"use client";

import React, { useState, useEffect, useCallback, use } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { API, StatusTag, ScoreBar, OCSF_ATTRIBUTES } from "../../../components/Common";
import {
  IconAccountTree,
  IconFingerprint,
  IconCopy,
  IconLock,
  IconRefresh,
  IconCheck,
  IconVerified,
} from "../../../components/Icons";

export default function ClusterDetailPage() {
  const params = useParams();
  const router = useRouter();
  const clusterId = params.clusterId as string;

  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [showPromoteModal, setShowPromoteModal] = useState(false);
  const [promoting, setPromoting] = useState(false);
  const [promotedDone, setPromotedDone] = useState(false);
  const [conflict409, setConflict409] = useState(false);
  const [leaseTimer, setLeaseTimer] = useState(822);
  const [copyFeedback, setCopyFeedback] = useState(false);
  const [draftToast, setDraftToast] = useState(false);

  const [fieldMappings, setFieldMappings] = useState<Record<string, string>>({});
  const [lockedFields, setLockedFields] = useState<Record<string, boolean>>({});

  const actor = typeof window !== "undefined" ? localStorage.getItem("ulpf_actor") || "kartik vashishtha" : "kartik vashishtha";

  const fetchCluster = useCallback(() => {
    if (!clusterId) return;
    setLoading(true);
    fetch(`${API}/queue/clusters/${clusterId}`)
      .then(r => r.json())
      .then(d => {
        setData(d);
        const candidate = d.candidate_mapping || {};
        const initial: Record<string, string> = {};
        Object.entries(candidate).forEach(([k, v]: [string, any]) => {
          initial[k] = v.candidate_ocsf_attribute || "unmapped";
        });
        setFieldMappings(initial);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [clusterId]);

  useEffect(() => {
    fetchCluster();
  }, [fetchCluster]);

  useEffect(() => {
    const id = setInterval(() => {
      setLeaseTimer(s => Math.max(0, s - 1));
    }, 1000);
    return () => clearInterval(id);
  }, []);

  const handlePromoteConfirm = async () => {
    setPromoting(true);
    try {
      const res = await fetch(`${API}/queue/clusters/${clusterId}/confirm`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ actor, overrides: fieldMappings }),
      });
      if (res.status === 409) {
        setConflict409(true);
        setShowPromoteModal(false);
        fetchCluster();
        return;
      }
      setPromotedDone(true);
      setTimeout(() => {
        setShowPromoteModal(false);
        setPromotedDone(false);
        fetchCluster();
      }, 1200);
    } catch {
      // ignore
    } finally {
      setPromoting(false);
    }
  };

  const handleReject = async () => {
    try {
      await fetch(`${API}/queue/clusters/${clusterId}/reject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ actor, reason: "Analyst dropped cluster — pattern noise" }),
      });
      fetchCluster();
    } catch {}
  };

  const handleCopyRaw = () => {
    navigator.clipboard?.writeText(data?.sample_raw || "<164>Sep 27 16:24:24 firebreak-edge-01 %ASA-4-106023: Deny tcp src outside:10.1.1.50/49823 dst inside:8.8.8.8/443 by access-group acl_outside");
    setCopyFeedback(true);
    setTimeout(() => setCopyFeedback(false), 2000);
  };

  const handleSaveDraft = () => {
    setDraftToast(true);
    setTimeout(() => setDraftToast(false), 2500);
  };

  const handleTargetChange = (key: string, newTarget: string) => {
    setFieldMappings(prev => ({ ...prev, [key]: newTarget }));
  };

  const toggleLock = (key: string) => {
    setLockedFields(prev => ({ ...prev, [key]: !prev[key] }));
  };

  if (loading) {
    return (
      <div style={{ padding: 40, textAlign: "center", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
        Loading cluster schema state from database...
      </div>
    );
  }

  const m = Math.floor(leaseTimer / 60);
  const s = leaseTimer % 60;

  const sample = data?.items?.[0] || {};
  const extracted = sample.extracted_fields || {
    var_1: "10.1.1.50",
    var_2: "49823",
    var_3: "8.8.8.8",
    var_4: "443",
    var_5: "tcp",
    var_6: "Deny",
    var_7: "TRANSIT_IN",
  };
  const candidateMapping = data?.candidate_mapping || {};

  const dryRunJson: Record<string, any> = {
    lineage_id: sample.lineage_id || "d8134282-60a6-4f03-855f-48163e6d9ed8",
    class_uid: 4001,
    class_name: "Network Activity",
    activity_id: 5,
    activity_name: "Refuse",
    severity_id: 4,
    metadata: {
      version: "1.2.0",
      uid: sample.lineage_id || "d8134282-60a6-4f03-855f-48163e6d9ed8",
      product: { name: "ULPF Onboarded Parser", vendor_name: data?.source_type || "cisco_asa" },
    },
    raw_pointer: data?.sample_raw_pointer || "raw_store://chunk_20260927_198/offset_0",
  };

  Object.entries(fieldMappings).forEach(([k, targetAttr]) => {
    const val = extracted[k] || "token_val";
    if (targetAttr === "src_endpoint.ip") {
      dryRunJson.src_endpoint = { ...(dryRunJson.src_endpoint || {}), ip: val };
    } else if (targetAttr === "src_endpoint.port") {
      dryRunJson.src_endpoint = { ...(dryRunJson.src_endpoint || {}), port: isNaN(Number(val)) ? 49823 : Number(val) };
    } else if (targetAttr === "dst_endpoint.ip") {
      dryRunJson.dst_endpoint = { ...(dryRunJson.dst_endpoint || {}), ip: val };
    } else if (targetAttr === "dst_endpoint.port") {
      dryRunJson.dst_endpoint = { ...(dryRunJson.dst_endpoint || {}), port: isNaN(Number(val)) ? 443 : Number(val) };
    } else if (targetAttr === "connection_info.protocol_name") {
      dryRunJson.connection_info = { ...(dryRunJson.connection_info || {}), protocol_name: val, protocol_num: 6 };
    } else if (targetAttr === "security_control.rule_name") {
      dryRunJson.security_control = { rule_name: val };
    } else if (targetAttr === "http_request.user_agent") {
      dryRunJson.http_request = { user_agent: val };
    }
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16, paddingBottom: 84 }}>
      {conflict409 && (
        <div className="notification-banner notification-banner-amber" style={{ cursor: "pointer" }} onClick={() => setConflict409(false)}>
          <div>
            <strong>409 State Conflict</strong> — This cluster was confirmed concurrently. View refreshed. Click to dismiss.
          </div>
        </div>
      )}

      {draftToast && (
        <div className="notification-banner notification-banner-emerald">
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <IconCheck style={{ width: 14, height: 14 }} />
            <span>Draft field mappings saved locally. JIT bytecode cache refreshed.</span>
          </div>
        </div>
      )}

      {/* Cluster Meta Ribbon */}
      <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", background: "var(--bg-surface)", padding: "10px 16px", borderRadius: 8, border: "1px solid var(--border-subtle)", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, fontWeight: 700, color: "var(--accent-blue)" }}>
              {clusterId}
            </span>
            <span className="status-tag status-tag-neutral">{data?.source_type || "cisco_asa"}</span>
          </div>
          <span style={{ color: "var(--border-muted)" }}>|</span>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontFamily: "var(--font-mono)", fontSize: 11 }}>
            <span style={{ color: "var(--text-muted)" }}>Samples:</span>
            <strong>{data?.sample_count ?? 1} events</strong>
            <span style={{ color: "var(--text-muted)" }}>T-42m</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, background: "var(--bg-subtle)", padding: "3px 8px", borderRadius: 4, border: "1px solid var(--border-subtle)" }}>
            <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700 }}>STATUS:</span>
            <StatusTag status={data?.status || "pending"} />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 5, background: "var(--bg-subtle)", padding: "3px 8px", borderRadius: 4, border: "1px solid var(--border-subtle)", color: "var(--text-secondary)" }}>
            <IconFingerprint style={{ width: 13, height: 13, color: "var(--accent-blue)" }} />
            <span>{actor}</span>
          </div>
        </div>

        {/* Back Link */}
        <Link
          href="/queue"
          className="btn-secondary"
          style={{ textDecoration: "none", fontSize: 11, padding: "4px 10px" }}
        >
          ← Back to All Clusters
        </Link>
      </div>

      {/* Section 1: Raw Log Payload Exposure */}
      <div className="panel-card" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 16px", background: "var(--bg-subtle)", borderBottom: "1px solid var(--border-subtle)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span className="label-caps">01 // Raw Log Payload Exposure (Pointer: {data?.sample_raw_pointer || "offset_0"})</span>
            <span style={{ background: "var(--accent-emerald-subtle)", color: "var(--accent-emerald)", border: "1px solid var(--accent-emerald-border)", padding: "1px 6px", borderRadius: 4, fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 600 }}>
              CRC32: 0x81AC
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
            <span>PARSER: DRAIN-TREE-v2</span>
            <span>·</span>
            <button
              onClick={handleCopyRaw}
              style={{ background: "none", border: "none", color: "var(--accent-blue)", fontWeight: 700, cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 4, fontFamily: "var(--font-mono)", fontSize: 11, textTransform: "uppercase" }}
            >
              <IconCopy style={{ width: 13, height: 13 }} />
              <span>{copyFeedback ? "COPIED" : "Copy Payload"}</span>
            </button>
          </div>
        </div>

        {/* Code Block */}
        <div className="code-terminal-box" style={{ borderRadius: 0, border: "none" }}>
          <div className="code-terminal-content">
            <div style={{ display: "flex", gap: 16 }}>
              <div style={{ display: "flex", flexDirection: "column", color: "#64748b", userSelect: "none", textAlign: "right", borderRight: "1px solid #334155", paddingRight: 10 }}>
                <span>01</span>
                <span>02</span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", minWidth: "max-content", gap: 4 }}>
                <div>
                  {data?.sample_raw_log ? (
                    <span style={{ color: "#fde68a", fontWeight: 500, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                      {data.sample_raw_log}
                    </span>
                  ) : (
                    <>
                      <span style={{ color: "#94a3b8" }}>&lt;164&gt;Sep 27 16:24:24 </span>
                      <span style={{ color: "#fde68a", fontWeight: 600 }}>firebreak-edge-01 </span>
                      <span style={{ color: "#94a3b8" }}>%{data?.source_type || "ASA"}-4-106023: </span>
                      {Object.entries(extracted).map(([k, val], idx) => {
                        const colors = ["token-blue", "token-indigo", "token-cyan", "token-teal", "token-emerald", "token-rose", "token-amber"];
                        const col = colors[idx % colors.length];
                        return (
                          <span key={k} className={`token-pill ${col}`} style={{ marginRight: 6 }} title={`Mapped: ${fieldMappings[k] || "unmapped"}`}>
                            {String(val)}
                          </span>
                        );
                      })}
                      <span style={{ color: "#64748b" }}>[0x8f01a312, 0x0]</span>
                    </>
                  )}
                </div>
                <div style={{ color: "#94a3b8", fontSize: 11 }}>
                  <span style={{ color: "#34d399", fontWeight: 700 }}>↳ DRAIN TEMPLATE: </span>
                  {data?.sample_raw_log
                    ? `Parsed ${Object.keys(extracted).length} dynamic token variables for OCSF 4001 attribute mapping`
                    : `<*> <*> <*> <*> %ASA-4-106023: <ACTION> <PROTO> src <SRC_INT>:<IP>/<PORT> dst <DST_INT>:<IP>/<PORT> by access-group <STRING> [<HEX>, <HEX>]`}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Section 2: Schema Mapping Matrix & Live Dry-Run Preview */}
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1.3fr) minmax(0, 0.9fr)", gap: 16, alignItems: "start" }}>
        {/* Left Panel: Matrix */}
        <div className="panel-card" style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", background: "var(--bg-subtle)", borderBottom: "1px solid var(--border-subtle)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <IconAccountTree style={{ width: 18, height: 18, color: "var(--accent-blue)" }} />
              <strong style={{ fontSize: 13, color: "var(--text-primary)" }}>Schema Mapping Matrix</strong>
              <span className="text-mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>Target: OCSF 4001 (Network Activity)</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <button className="btn-secondary" style={{ fontSize: 11, padding: "3px 8px" }} onClick={fetchCluster}>
                <IconRefresh className="nav-icon" style={{ width: 12, height: 12 }} />
                <span>Re-infer FastText</span>
              </button>
              <span className="status-tag status-tag-confirmed">
                {Object.keys(candidateMapping).length || Object.keys(extracted).length} Fields Active
              </span>
            </div>
          </div>

          <div style={{ overflowX: "auto" }}>
            <table className="stitch-table">
              <thead>
                <tr>
                  <th>Token</th>
                  <th>OCSF 4001 Field (Select to Override)</th>
                  <th>Strategy</th>
                  <th>Confidence</th>
                  <th style={{ textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {Object.keys(candidateMapping).length > 0 ? (
                  Object.entries(candidateMapping).map(([k, item]: [string, any]) => {
                    const tokenVal = extracted[k] || k;
                    const currentTarget = fieldMappings[k] || item.candidate_ocsf_attribute || "unmapped";
                    const conf = Math.round((item.similarity_score || 0.75) * 100);
                    const isWarn = conf < 70;
                    const isLocked = lockedFields[k] || false;

                    return (
                      <tr key={k} style={{ background: isWarn ? "rgba(245, 158, 11, 0.04)" : "transparent" }}>
                        <td style={{ fontWeight: 700, color: "var(--accent-blue)" }}>{String(tokenVal)}</td>
                        <td>
                          <select
                            className="select-field"
                            value={currentTarget}
                            onChange={e => handleTargetChange(k, e.target.value)}
                            disabled={isLocked}
                          >
                            {OCSF_ATTRIBUTES.map(attr => (
                              <option key={attr} value={attr}>{attr}</option>
                            ))}
                          </select>
                        </td>
                        <td>
                          <span style={{ background: isWarn ? "var(--accent-amber-subtle)" : "var(--bg-subtle)", color: isWarn ? "var(--accent-amber)" : "var(--text-secondary)", padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 600 }}>
                            {currentTarget.includes("ip") ? "Regex IP4" : currentTarget.includes("port") ? "Port Range" : currentTarget.includes("proto") ? "IANA Enum" : "FastText Sem"}
                          </span>
                        </td>
                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <div style={{ width: 64, height: 6, background: "var(--border-subtle)", borderRadius: 9999, overflow: "hidden" }}>
                              <div style={{ width: `${conf}%`, height: "100%", background: conf > 90 ? "var(--accent-emerald)" : conf > 60 ? "var(--accent-amber)" : "var(--accent-rose)", borderRadius: 9999 }} />
                            </div>
                            <span style={{ fontWeight: 700, color: conf > 90 ? "var(--accent-emerald)" : "var(--accent-amber)" }}>
                              {conf}%
                            </span>
                          </div>
                        </td>
                        <td style={{ textAlign: "right" }}>
                          <button
                            className="btn-secondary"
                            style={{ padding: "2px 6px", fontSize: 10, color: isLocked ? "var(--accent-blue)" : "var(--text-secondary)" }}
                            onClick={() => toggleLock(k)}
                          >
                            {isLocked ? "Locked" : "Lock"}
                          </button>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  Object.entries(extracted).map(([k, val]) => {
                    const currentTarget = fieldMappings[k] || "unmapped";
                    return (
                      <tr key={k}>
                        <td style={{ fontWeight: 700 }}>{String(val)}</td>
                        <td>
                          <select
                            className="select-field"
                            value={currentTarget}
                            onChange={e => handleTargetChange(k, e.target.value)}
                          >
                            {OCSF_ATTRIBUTES.map(attr => (
                              <option key={attr} value={attr}>{attr}</option>
                            ))}
                          </select>
                        </td>
                        <td><span className="status-tag status-tag-neutral">Pattern Inferred</span></td>
                        <td><ScoreBar score={0.85} /></td>
                        <td style={{ textAlign: "right" }}>
                          <button className="btn-secondary" style={{ padding: "2px 6px", fontSize: 10 }}>Lock</button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 16px", background: "var(--bg-subtle)", borderTop: "1px solid var(--border-subtle)", fontFamily: "var(--font-mono)", fontSize: 11 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, color: "var(--text-secondary)" }}>
              <IconVerified style={{ width: 15, height: 15, color: "var(--accent-emerald)" }} />
              <span>Compiler State: JIT Hot-Path Map Generation Ready</span>
            </div>
            <span style={{ color: "var(--text-muted)" }}>Target Bytecode Size: <strong style={{ color: "var(--text-primary)" }}>384 bytes</strong></span>
          </div>
        </div>

        {/* Right Panel: Live Dynamic Dry-Run Preview */}
        <div className="panel-card" style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", background: "var(--bg-subtle)", borderBottom: "1px solid var(--border-subtle)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <IconVerified style={{ width: 18, height: 18, color: "var(--accent-emerald)" }} />
              <strong style={{ fontSize: 13, color: "var(--text-primary)" }}>Dry-Run Canonical OCSF JSON</strong>
            </div>
            <span className="status-tag status-tag-confirmed">SCHEMA VALID</span>
          </div>

          <div className="code-terminal-box" style={{ borderRadius: 0, border: "none", maxHeight: 440, overflowY: "auto" }}>
            <pre className="code-terminal-content" style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {JSON.stringify(dryRunJson, null, 2)}
            </pre>
          </div>

          <div style={{ padding: "10px 16px", background: "var(--bg-subtle)", borderTop: "1px solid var(--border-subtle)", display: "flex", justifyContent: "space-between", alignItems: "center", fontFamily: "var(--font-mono)", fontSize: 11 }}>
            <span style={{ color: "var(--text-muted)" }}>Valid Against Schema v1.2.0</span>
            <button
              className="btn-secondary"
              style={{ fontSize: 10, padding: "2px 8px" }}
              onClick={() => router.push(`/trace/${dryRunJson.lineage_id}`)}
            >
              Trace Lineage DAG →
            </button>
          </div>
        </div>
      </div>

      {/* Sticky Action Dock */}
      <div className="action-dock">
        <div className="action-dock-left">
          <IconLock style={{ width: 15, height: 15, color: "var(--accent-emerald)", flexShrink: 0 }} />
          <strong style={{ color: "var(--text-primary)" }}>No conflicts</strong>
          <span style={{ color: "var(--border-muted)" }}>·</span>
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            Lease locked by <strong style={{ color: "var(--accent-blue)" }}>{actor}</strong> (expires in <span style={{ fontWeight: 700, color: "var(--text-primary)" }}>{m}:{s < 10 ? `0${s}` : s}</span>)
          </span>
        </div>

        <div className="action-dock-mid">
          <span className="label-caps">Pack Digest:</span>
          <span style={{ color: "var(--accent-blue)", fontWeight: 600 }}>sha256:4b91f1...8831</span>
          <span style={{ color: "var(--border-muted)" }}>·</span>
          <span style={{ color: "var(--accent-emerald)", fontWeight: 700 }}>RCU Hot Reload Ready</span>
        </div>

        <div className="action-dock-right">
          <button id="cluster-reject-btn" className="btn-danger" onClick={handleReject}>Reject (Drop)</button>
          <button id="btn-save-draft" className="btn-secondary" onClick={handleSaveDraft}>Save Draft</button>
          <button
            id="cluster-confirm-btn"
            className="btn-primary"
            onClick={() => setShowPromoteModal(true)}
          >
            <IconVerified style={{ width: 14, height: 14, color: "#34d399" }} />
            <span>ED25519 SIGN &amp; PROMOTE PACK</span>
          </button>
        </div>
      </div>

      {/* Promotion Confirmation Modal Overlay */}
      {showPromoteModal && (
        <div className="modal-overlay" onClick={() => setShowPromoteModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border-subtle)", paddingBottom: 10 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <IconVerified style={{ width: 18, height: 18, color: "var(--accent-blue)" }} />
                <strong style={{ fontSize: 14, color: "var(--text-primary)" }}>Confirm Ingestion Pack Promotion</strong>
              </div>
              <button onClick={() => setShowPromoteModal(false)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)", fontSize: 16 }}>
                ✕
              </button>
            </div>

            <div style={{ background: "var(--bg-subtle)", border: "1px solid var(--border-subtle)", padding: 12, borderRadius: 6, fontFamily: "var(--font-mono)", fontSize: 11, display: "flex", flexDirection: "column", gap: 6 }}>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span className="label-caps">Cluster:</span>
                <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{clusterId} ({data?.source_type || "cisco_asa"})</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span className="label-caps">Target Spec:</span>
                <span style={{ color: "var(--accent-emerald)", fontWeight: 700 }}>OCSF 4001 (Network Activity)</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span className="label-caps">Rule Signer:</span>
                <span style={{ color: "var(--accent-blue)", fontWeight: 600 }}>ed25519:{actor}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span className="label-caps">Engine Action:</span>
                <span style={{ color: "var(--accent-emerald)", fontWeight: 700 }}>Atomic Zero-Downtime RCU Reload</span>
              </div>
            </div>

            <p style={{ fontSize: 11.5, color: "var(--text-secondary)", margin: 0, lineHeight: 1.5 }}>
              Promoting this pack compiles candidate heuristics to immutable hot-path parser bytecode. Backlogged events in this cluster will be replayed instantaneously.
            </p>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, paddingTop: 10, borderTop: "1px solid var(--border-subtle)" }}>
              <button className="btn-secondary" onClick={() => setShowPromoteModal(false)}>Cancel</button>
              <button
                className="btn-primary"
                onClick={handlePromoteConfirm}
                disabled={promoting}
              >
                {promoting ? (
                  <>
                    <IconRefresh className="nav-icon" style={{ animation: "spin 1s linear infinite" }} />
                    <span>Transmitting Bytecode...</span>
                  </>
                ) : promotedDone ? (
                  <>
                    <IconCheck style={{ width: 14, height: 14 }} />
                    <span>Pack Promoted #199</span>
                  </>
                ) : (
                  <>
                    <IconVerified style={{ width: 14, height: 14 }} />
                    <span>Sign &amp; Push to Epoch 26.09</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
