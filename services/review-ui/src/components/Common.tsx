import React, { useState, useEffect } from "react";

export const API = process.env.NEXT_PUBLIC_REVIEW_API_URL || "http://localhost:4000";

export const OCSF_ATTRIBUTES = [
  "src_endpoint.ip",
  "src_endpoint.port",
  "dst_endpoint.ip",
  "dst_endpoint.port",
  "connection_info.protocol_name",
  "connection_info.protocol_num",
  "security_control.rule_name",
  "http_request.user_agent",
  "http_request.url.path",
  "http_response.code",
  "actor.user.name",
  "device.hostname",
  "time",
  "activity_name",
  "severity",
  "unmapped",
];

export const SAMPLE_CSV = `timestamp,source_ip,destination_ip,protocol,action,raw_log
2026-09-27T16:24:24Z,10.1.1.50,8.8.8.8,tcp,Deny,<164>Sep 27 2026 16:24:24: %ASA-4-106023: Deny tcp src outside:10.1.1.50/49823 dst inside:8.8.8.8/443 by access-group "acl_outside"
2026-09-27T16:24:25Z,172.16.0.4,192.168.10.25,tcp,Allow,Sep 27 16:24:25 edge-fw-02 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 172.16.0.4/51234->192.168.10.25/80 None None 6 test-policy untrust trust 1243
2026-09-27T16:24:26Z,192.168.1.100,10.0.0.1,udp,Drop,<189>date=2026-09-27 time=16:24:26 devname="FGT60D" type="traffic" level="notice" action="deny" srcip=192.168.1.100 dstip=10.0.0.1
`;

export function TimeAgo({ iso }: { iso?: string | null }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted || !iso) return <span suppressHydrationWarning>{iso ? "recently" : "—"}</span>;
  try {
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 60000) return <span suppressHydrationWarning>just now</span>;
    if (diff < 3600000) return <span suppressHydrationWarning>{Math.floor(diff / 60000)}m ago</span>;
    if (diff < 86400000) return <span suppressHydrationWarning>{Math.floor(diff / 3600000)}h ago</span>;
    return <span suppressHydrationWarning>{Math.floor(diff / 86400000)}d ago</span>;
  } catch {
    return <span suppressHydrationWarning>{iso}</span>;
  }
}

export function StatusTag({ status }: { status: string }) {
  const st = (status || "pending").toLowerCase();
  if (st === "confirmed" || st === "promoted" || st === "active") {
    return <span className="status-tag status-tag-confirmed">CONFIRMED</span>;
  }
  if (st === "rejected" || st === "dropped") {
    return <span className="status-tag status-tag-rejected">REJECTED</span>;
  }
  if (st === "in_review" || st === "draft") {
    return <span className="status-tag status-tag-in-review">IN REVIEW</span>;
  }
  return <span className="status-tag status-tag-pending">PENDING</span>;
}

export function ScoreBar({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, Math.round(score * 100)));
  const color = pct >= 80 ? "var(--accent-emerald)" : pct >= 60 ? "var(--accent-amber)" : "var(--accent-rose)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ width: 64, height: 6, background: "var(--border-subtle)", borderRadius: 9999, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 9999 }} />
      </div>
      <span className="text-mono" style={{ fontSize: 11, fontWeight: 700, color }}>{pct}%</span>
    </div>
  );
}

export function Pagination({
  page,
  limit,
  total,
  onPageChange,
  onLimitChange,
}: {
  page: number;
  limit: number;
  total: number;
  onPageChange: (newPage: number) => void;
  onLimitChange?: (newLimit: number) => void;
}) {
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const start = total === 0 ? 0 : (page - 1) * limit + 1;
  const end = Math.min(total, page * limit);

  return (
    <div style={{
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center",
      padding: "10px 16px",
      background: "var(--bg-subtle)",
      borderTop: "1px solid var(--border-subtle)",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      flexWrap: "wrap",
      gap: 10,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ color: "var(--text-secondary)" }}>
          Showing <strong style={{ color: "var(--text-primary)" }}>{start}–{end}</strong> of <strong style={{ color: "var(--accent-blue)" }}>{total.toLocaleString()}</strong>
        </span>
        {onLimitChange && (
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ color: "var(--text-muted)", fontSize: 10 }}>Per Page:</span>
            <select
              value={limit}
              onChange={(e) => {
                onLimitChange(Number(e.target.value));
                onPageChange(1);
              }}
              style={{
                background: "var(--bg-card)",
                border: "1px solid var(--border-muted)",
                borderRadius: 4,
                padding: "2px 6px",
                fontFamily: "var(--font-mono)",
                fontSize: 10,
                color: "var(--text-primary)",
                cursor: "pointer",
              }}
            >
              <option value={10}>10</option>
              <option value={20}>20</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>
        )}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
        <button
          className="btn-secondary"
          style={{ fontSize: 10, padding: "3px 8px" }}
          disabled={page <= 1}
          onClick={() => onPageChange(1)}
          title="First Page"
        >
          « First
        </button>
        <button
          className="btn-secondary"
          style={{ fontSize: 10, padding: "3px 8px" }}
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
          title="Previous Page"
        >
          ‹ Prev
        </button>
        <span style={{ padding: "0 8px", color: "var(--text-primary)", fontWeight: 600 }}>
          Page {page} of {totalPages}
        </span>
        <button
          className="btn-secondary"
          style={{ fontSize: 10, padding: "3px 8px" }}
          disabled={page >= totalPages}
          onClick={() => onPageChange(page + 1)}
          title="Next Page"
        >
          Next ›
        </button>
        <button
          className="btn-secondary"
          style={{ fontSize: 10, padding: "3px 8px" }}
          disabled={page >= totalPages}
          onClick={() => onPageChange(totalPages)}
          title="Last Page"
        >
          Last »
        </button>
      </div>
    </div>
  );
}
