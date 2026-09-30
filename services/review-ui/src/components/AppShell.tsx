"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { API } from "./Common";
import { CsvIngestModal } from "./CsvIngestModal";
import {
  IconDashboard,
  IconLayers,
  IconPacks,
  IconTerminal,
  IconVerified,
  IconSearch,
  IconLock,
  IconUpload,
} from "./Icons";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [csvModalOpen, setCsvModalOpen] = useState(false);
  const [actor, setActor] = useState("kartik vashishtha");
  const [searchFilter, setSearchFilter] = useState("");
  const [apiOk, setApiOk] = useState<boolean | null>(null);
  const [stats, setStats] = useState<any>(null);

  useEffect(() => {
    try {
      const stored = localStorage.getItem("ulpf_actor");
      if (stored) setActor(stored);
    } catch {}
  }, []);

  function setActorPersisted(v: string) {
    setActor(v);
    try {
      if (typeof window !== "undefined") localStorage.setItem("ulpf_actor", v);
    } catch {}
  }

  const fetchHealthAndStats = useCallback(() => {
    fetch(`${API}/health`).then(r => setApiOk(r.ok)).catch(() => setApiOk(false));
    fetch(`${API}/stats`).then(r => r.json()).then(d => setStats(d)).catch(() => {});
  }, []);

  useEffect(() => {
    fetchHealthAndStats();
    const id = setInterval(fetchHealthAndStats, 5000);
    return () => clearInterval(id);
  }, [fetchHealthAndStats]);

  const handleGlobalSearch = (val: string) => {
    if (!val.trim()) return;
    const clean = val.trim();
    if (clean.includes("-") && clean.length > 20) {
      router.push(`/trace/${clean}`);
    } else if (clean.startsWith("drain-cluster")) {
      router.push(`/queue/${clean}`);
    } else {
      router.push(`/trace?id=${encodeURIComponent(clean)}`);
    }
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        const input = document.getElementById("global-search-input") as HTMLInputElement;
        if (input) input.focus();
      }
      if (e.key === "Escape") {
        setCsvModalOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const pendingClustersCount = stats?.status_counts?.find((s: any) => s.status === "pending")?.count ?? 5461;
  const activePacksCount = stats?.packs?.find((p: any) => p.status === "active")?.count ?? 62;

  // Derive route crumb
  let routeCrumb = "dashboard-session";
  if (pathname.startsWith("/queue")) routeCrumb = "queue-session";
  else if (pathname.startsWith("/packs")) routeCrumb = "packs-ledger";
  else if (pathname.startsWith("/normalized")) routeCrumb = "ocsf-stream";
  else if (pathname.startsWith("/trace")) routeCrumb = "trace-verify";

  return (
    <div className="layout" suppressHydrationWarning>
      <CsvIngestModal
        isOpen={csvModalOpen}
        onClose={() => setCsvModalOpen(false)}
        onIngestSuccess={fetchHealthAndStats}
      />

      {/* Left Tactical Sidebar (Restored) */}
      <aside className="sidebar">
        <div>
          {/* Logo Branding Header */}
          <div className="sidebar-header">
            <div className="brand-badge">
              <div className="brand-icon-box">U</div>
              <div style={{ display: "flex", flexDirection: "column" }}>
                <span className="brand-title">ULPF Console</span>
                <span className="brand-sub">v0.1 Air-Gapped</span>
              </div>
            </div>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--accent-emerald)" }} title="System Operational" />
          </div>

          {/* Navigation Links */}
          <nav className="sidebar-nav">
            <div className="nav-group-label">Telemetry</div>
            <Link
              id="nav-dashboard"
              href="/"
              className={`nav-btn ${pathname === "/" || pathname === "/dashboard" ? "active" : ""}`}
            >
              <div className="nav-btn-inner">
                <IconDashboard className="nav-icon" style={{ color: pathname === "/" || pathname === "/dashboard" ? "var(--accent-blue)" : "var(--text-muted)" }} />
                <span>Dashboard</span>
              </div>
              <span className="text-mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>/</span>
            </Link>

            <div className="nav-group-label" style={{ marginTop: 8 }}>Cold-Path Analysis</div>
            <Link
              id="nav-queue"
              href="/queue"
              className={`nav-btn ${pathname.startsWith("/queue") ? "active" : ""}`}
            >
              <div className="nav-btn-inner">
                <IconLayers className="nav-icon" style={{ color: pathname.startsWith("/queue") ? "var(--accent-blue)" : "var(--text-muted)" }} />
                <span>Review Queue</span>
              </div>
              <span className="nav-pill nav-pill-rose">{pendingClustersCount}</span>
            </Link>

            <Link
              id="nav-packs"
              href="/packs"
              className={`nav-btn ${pathname === "/packs" ? "active" : ""}`}
            >
              <div className="nav-btn-inner">
                <IconPacks className="nav-icon" style={{ color: pathname === "/packs" ? "var(--accent-blue)" : "var(--text-muted)" }} />
                <span>Mapping Packs</span>
              </div>
              <span className="nav-pill nav-pill-slate">{activePacksCount}</span>
            </Link>

            <div className="nav-group-label" style={{ marginTop: 8 }}>Streams &amp; Ledger</div>
            <Link
              id="nav-normalized"
              href="/normalized"
              className={`nav-btn ${pathname === "/normalized" ? "active" : ""}`}
            >
              <div className="nav-btn-inner">
                <IconTerminal className="nav-icon" style={{ color: pathname === "/normalized" ? "var(--accent-blue)" : "var(--text-muted)" }} />
                <span>OCSF Stream</span>
              </div>
              <div className="nav-live-dot">
                <span className="live-dot-pulse" />
                <span className="text-mono" style={{ fontSize: 10, fontWeight: 700, color: "var(--accent-emerald)" }}>LIVE</span>
              </div>
            </Link>

            <Link
              id="nav-trace"
              href="/trace"
              className={`nav-btn ${pathname.startsWith("/trace") ? "active" : ""}`}
            >
              <div className="nav-btn-inner">
                <IconVerified className="nav-icon" style={{ color: pathname.startsWith("/trace") ? "var(--accent-blue)" : "var(--text-muted)" }} />
                <span>Trace &amp; Verify</span>
              </div>
              <IconLock style={{ width: 13, height: 13, color: "var(--text-muted)" }} />
            </Link>
          </nav>
        </div>

        {/* Sidebar Operator Footer */}
        <div className="sidebar-footer">
          <div className="profile-card">
            <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
              <div className="profile-avatar">
                {actor.slice(0, 2).toUpperCase()}
              </div>
              <div style={{ display: "flex", flexDirection: "column", minWidth: 0 }}>
                <input
                  suppressHydrationWarning
                  value={actor}
                  onChange={e => setActorPersisted(e.target.value)}
                  style={{ background: "transparent", border: "none", outline: "none", fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, color: "var(--text-primary)", padding: 0 }}
                  title="Click to edit analyst signature"
                />
                <span className="text-mono" style={{ fontSize: 9, color: "var(--text-muted)" }}>
                  0x8f2a...c014
                </span>
              </div>
            </div>
            <span style={{ background: "var(--bg-subtle)", padding: "1px 5px", borderRadius: 3, border: "1px solid var(--border-subtle)", fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 600 }}>
              Ed25519
            </span>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontFamily: "var(--font-mono)", fontSize: 11 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, color: apiOk ? "var(--accent-emerald)" : "var(--accent-rose)" }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: apiOk ? "var(--accent-emerald)" : "var(--accent-rose)" }} />
              <strong>:4000 {apiOk ? "ONLINE" : "OFFLINE"}</strong>
            </div>
            <span style={{ color: "var(--text-muted)", fontSize: 10 }}>0.4ms</span>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", borderTop: "1px solid var(--border-subtle)", paddingTop: 6, fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>
            <span>⌘K Search</span>
            <span>ESC Dismiss</span>
          </div>
        </div>
      </aside>

      {/* Main Viewport Container */}
      <div className="main-viewport">
        {/* Top Header Bar */}
        <header className="top-bar">
          <div className="top-bar-left">
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <IconTerminal style={{ width: 14, height: 14, color: "var(--text-muted)" }} />
              <strong style={{ color: "var(--text-primary)" }}>ULPF</strong>
              <span className="top-bar-crumb">/</span>
              <span className="top-bar-crumb-active">{routeCrumb}</span>
            </div>
            <div style={{ width: 1, height: 16, background: "var(--border-subtle)" }} />
            <div className="header-chip">
              <IconVerified style={{ width: 13, height: 13, color: "var(--accent-emerald)" }} />
              <span>Anchored Block #198</span>
              <span style={{ color: "var(--border-muted)" }}>·</span>
              <span style={{ color: "var(--text-muted)" }}>Epoch 26.09</span>
            </div>
            <div className="header-chip" style={{ display: "flex" }}>
              <span style={{ color: "var(--text-muted)" }}>PATH:</span>
              <strong style={{ color: "var(--accent-emerald)" }}>HOT-PATH ACTIVE</strong>
            </div>
          </div>

          <div className="top-bar-right">
            {/* Global Search Bar (⌘K) */}
            <div style={{ display: "flex", alignItems: "center", gap: 6, background: "var(--bg-subtle)", border: "1px solid var(--border-subtle)", borderRadius: 6, padding: "4px 8px", width: 220 }}>
              <IconSearch style={{ width: 13, height: 13, color: "var(--text-muted)" }} />
              <input
                id="global-search-input"
                placeholder="Filter events, hashes..."
                value={searchFilter}
                onChange={e => setSearchFilter(e.target.value)}
                onKeyDown={e => {
                  if (e.key === "Enter") handleGlobalSearch(searchFilter);
                }}
                style={{ background: "transparent", border: "none", outline: "none", fontSize: 11, fontFamily: "var(--font-sans)", color: "var(--text-primary)", width: "100%" }}
              />
              <span style={{ background: "#ffffff", padding: "1px 4px", borderRadius: 3, border: "1px solid var(--border-subtle)", fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)" }}>
                ⌘K
              </span>
            </div>

            {/* Ingest CSV Action Button */}
            <button
              id="btn-ingest-csv-header"
              className="btn-primary"
              style={{ background: "var(--accent-emerald)", fontSize: 11, padding: "5px 10px" }}
              onClick={() => setCsvModalOpen(true)}
            >
              <IconUpload style={{ width: 13, height: 13 }} />
              <span>+ Ingest CSV</span>
            </button>

            {/* User Profile Pill */}
            <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 8px", borderRadius: 6, border: "1px solid var(--border-subtle)", background: "#ffffff" }}>
              <div style={{ width: 18, height: 18, borderRadius: "50%", background: "var(--accent-blue)", color: "#ffffff", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 9, fontWeight: 700 }}>
                {actor.slice(0, 2).toUpperCase()}
              </div>
              <span className="text-mono" style={{ fontSize: 11, fontWeight: 600 }}>{actor}</span>
            </div>
          </div>
        </header>

        {/* Dynamic Route Content */}
        <main className="content-pane">
          {children}
        </main>
      </div>
    </div>
  );
}
