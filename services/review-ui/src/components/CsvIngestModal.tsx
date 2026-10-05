"use client";

import React, { useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { API, SAMPLE_CSV } from "./Common";
import { IconUpload, IconFile, IconRefresh, IconCheck, IconVerified } from "./Icons";

export function CsvIngestModal({
  isOpen,
  onClose,
  onIngestSuccess,
}: {
  isOpen: boolean;
  onClose: () => void;
  onIngestSuccess?: () => void;
}) {
  const router = useRouter();
  const [csvContent, setCsvContent] = useState("");
  const [filename, setFilename] = useState("universal_logs.csv");
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFilename(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setCsvContent(text);
      setError(null);
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (!file) return;
    setFilename(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setCsvContent(text);
      setError(null);
    };
    reader.readAsText(file);
  };

  const handleIngest = async () => {
    if (!csvContent.trim()) {
      setError("Please paste CSV data or choose a file first.");
      return;
    }
    setUploading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${API}/ingest/csv`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ csv_content: csvContent, filename }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error?.message || data.message || `Ingest failed: HTTP ${res.status}`);
      }
      setResult(data);
      if (onIngestSuccess) onIngestSuccess();
    } catch (err: any) {
      setError(err.message || "Failed to submit CSV log ingestion batch.");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: 640 }} onClick={e => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border-subtle)", paddingBottom: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <IconUpload style={{ width: 18, height: 18, color: "var(--accent-blue)" }} />
            <strong style={{ fontSize: 14, color: "var(--text-primary)" }}>Ingest Universal Logs via CSV</strong>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)", fontSize: 16 }}>
            ✕
          </button>
        </div>

        {error && (
          <div className="notification-banner notification-banner-amber">
            <strong>Ingestion Error:</strong> {error}
          </div>
        )}

        {result ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div className="notification-banner notification-banner-emerald" style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <IconCheck style={{ width: 16, height: 16, color: "var(--accent-emerald)" }} />
              <div>
                <strong>Ingestion Complete:</strong> {result.ingested_count} of {result.total_rows} rows ingested into Merkle Chunk Store!
              </div>
            </div>

            <div style={{ background: "var(--bg-subtle)", border: "1px solid var(--border-subtle)", padding: 12, borderRadius: 6, fontFamily: "var(--font-mono)", fontSize: 11, display: "flex", flexDirection: "column", gap: 6 }}>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span className="label-caps">Chunk Storage ID:</span>
                <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{result.chunks?.[0] || "chunk_active"}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span className="label-caps">Routing Summary:</span>
                <span>
                  <strong style={{ color: "var(--accent-emerald)" }}>{result.summary?.hot_path_count || 0} HOT</strong>
                  {" · "}
                  <strong style={{ color: "var(--accent-amber)" }}>{result.summary?.cold_path_count || 0} COLD</strong>
                </span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span className="label-caps">Cryptographic State:</span>
                <span style={{ color: "var(--accent-blue)", fontWeight: 600 }}>SHA-256 Leaves Anchored</span>
              </div>
            </div>

            <div style={{ maxHeight: 180, overflowY: "auto", border: "1px solid var(--border-subtle)", borderRadius: 6 }}>
              <table className="stitch-table" style={{ fontSize: 11 }}>
                <thead>
                  <tr>
                    <th>Lineage ID</th>
                    <th>Route</th>
                    <th>SHA-256 Digest</th>
                    <th style={{ textAlign: "right" }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {(result.records || []).slice(0, 10).map((r: any, idx: number) => {
                    const route = r.path_taken || r.route || "COLD";
                    const sha = r.sha256_hash || r.sha256;
                    return (
                      <tr key={r.lineage_id || idx}>
                        <td style={{ fontFamily: "var(--font-mono)", fontWeight: 600, color: "var(--accent-blue)" }}>
                          {r.lineage_id ? r.lineage_id.slice(0, 16) + "..." : `row-${idx}`}
                        </td>
                        <td>
                          <span className={`status-tag ${route === "HOT" ? "status-tag-confirmed" : "status-tag-pending"}`} style={{ fontSize: 9 }}>
                            {route}
                          </span>
                        </td>
                        <td style={{ fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                          {sha ? `0x${sha.slice(0, 8)}...` : "—"}
                        </td>
                      <td style={{ textAlign: "right" }}>
                        <button
                          className="btn-secondary"
                          style={{ fontSize: 10, padding: "2px 6px" }}
                          onClick={() => {
                            onClose();
                            router.push(`/trace/${r.lineage_id}`);
                          }}
                        >
                          Trace →
                        </button>
                      </td>
                    </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, paddingTop: 8, borderTop: "1px solid var(--border-subtle)" }}>
              <button className="btn-secondary" onClick={() => { setResult(null); setCsvContent(""); }}>Ingest Another</button>
              <button className="btn-primary" onClick={onClose}>Done</button>
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div
              className="dropzone"
              onDragOver={e => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                type="file"
                ref={fileInputRef}
                style={{ display: "none" }}
                accept=".csv,.txt,.log"
                onChange={handleFileChange}
              />
              <IconFile style={{ width: 24, height: 24, margin: "0 auto 8px auto", color: "var(--text-muted)" }} />
              <div style={{ fontWeight: 600, fontSize: 12, color: "var(--text-primary)" }}>
                Click to browse or drag &amp; drop CSV/Log file
              </div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
                Accepted: .csv, .txt, .log (Syslog RFC3164/5424 headers supported)
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span className="label-caps">Raw CSV Content Editor</span>
              <button
                id="btn-load-sample-csv"
                type="button"
                className="btn-secondary"
                style={{ fontSize: 10.5, padding: "3px 8px" }}
                onClick={() => setCsvContent(SAMPLE_CSV)}
              >
                + Load Sample Cisco &amp; Web Logs
              </button>
            </div>

            <textarea
              className="textarea-code"
              rows={7}
              placeholder="Paste raw CSV or log lines with header (timestamp,source_ip,destination_ip,protocol,action,raw_log)..."
              value={csvContent}
              onChange={e => setCsvContent(e.target.value)}
            />

            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, paddingTop: 8, borderTop: "1px solid var(--border-subtle)" }}>
              <button className="btn-secondary" onClick={onClose}>Cancel</button>
              <button
                id="btn-process-csv"
                className="btn-primary"
                onClick={handleIngest}
                disabled={uploading || !csvContent.trim()}
              >
                {uploading ? (
                  <>
                    <IconRefresh className="nav-icon" style={{ animation: "spin 1s linear infinite" }} />
                    <span>Processing &amp; Sealing Logs...</span>
                  </>
                ) : (
                  <>
                    <IconVerified style={{ width: 14, height: 14 }} />
                    <span>Process &amp; Ingest CSV</span>
                  </>
                )}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
