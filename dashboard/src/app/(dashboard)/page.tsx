"use client";

import { useEffect, useState, useCallback } from "react";

import StatCards from "@/components/StatCards";
import TimelineChart from "@/components/TimelineChart";
import AttackPieChart from "@/components/AttackPieChart";
import ProtocolBar from "@/components/ProtocolBar";
import IncidentTable from "@/components/IncidentTable";
import { useSSE } from "@/hooks/useSSE";
import {
  fetchSummary,
  fetchIncidents,
  type SummaryResponse,
  type Incident,
} from "@/services/api";

/** Maximum number of incidents to keep in client-side state */
const MAX_INCIDENTS = 200;

/** SSE endpoint URL */
const SSE_URL =
  (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080/api/v1") +
  "/incidents/stream";

export default function DashboardPage() {
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newCount, setNewCount] = useState(0);

  // ── Initial Data Load (ONE-TIME) ────────────────────────────────
  const loadData = useCallback(async () => {
    try {
      const [summaryData, incidentData] = await Promise.all([
        fetchSummary(),
        fetchIncidents({ limit: 50 }),
      ]);
      setSummary(summaryData);
      setIncidents(incidentData.data ?? []);
      setError(null);
      setNewCount(0);
    } catch (err) {
      console.error("Dashboard fetch error:", err);
      setError("Failed to connect to API");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // ── SSE: Live Incident Stream ───────────────────────────────────
  const handleNewIncident = useCallback((incident: Incident) => {
    setIncidents((prev) => {
      // Prepend new incident, cap at MAX_INCIDENTS to prevent memory leak
      const updated = [incident, ...prev];
      return updated.length > MAX_INCIDENTS
        ? updated.slice(0, MAX_INCIDENTS)
        : updated;
    });
    setNewCount((c) => c + 1);
  }, []);

  const sseStatus = useSSE<Incident>({
    url: SSE_URL,
    event: "incident",
    onMessage: handleNewIncident,
    enabled: !loading,
  });

  // ── Manual Refresh (re-fetch summary from materialized views) ───
  const handleRefresh = useCallback(async () => {
    try {
      const summaryData = await fetchSummary();
      setSummary(summaryData);
      setNewCount(0);
    } catch (err) {
      console.error("Refresh error:", err);
    }
  }, []);

  return (
    <>
          {/* Error Banner */}
          {error && (
            <div className="rounded-lg border border-red/30 bg-red/10 px-4 py-3 text-sm text-red">
              ⚠ {error}
            </div>
          )}

          {/* SSE Status + Refresh Bar */}
          {!loading && (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {/* SSE connection indicator */}
                <div className="flex items-center gap-1.5">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      sseStatus === "connected"
                        ? "bg-green pulse-dot"
                        : sseStatus === "connecting"
                          ? "bg-amber animate-pulse"
                          : "bg-red"
                    }`}
                  />
                  <span className="text-xs font-mono text-muted uppercase tracking-wider">
                    {sseStatus === "connected"
                      ? "Live"
                      : sseStatus === "connecting"
                        ? "Connecting…"
                        : "Disconnected"}
                  </span>
                </div>

                {/* New incidents badge */}
                {newCount > 0 && (
                  <span className="text-xs font-mono text-cyan bg-cyan/10 border border-cyan/20 px-2 py-0.5 rounded-full">
                    +{newCount} new
                  </span>
                )}
              </div>

              {/* Manual refresh button */}
              <button
                onClick={handleRefresh}
                className="text-xs font-medium text-muted hover:text-foreground bg-surface hover:bg-surface-hover border border-border px-3 py-1.5 rounded-lg transition-colors cursor-pointer"
              >
                ↻ Refresh Stats
              </button>
            </div>
          )}

          {/* Loading Skeleton */}
          {loading ? (
            <DashboardSkeleton />
          ) : (
            <>
              {/* Row 1: Stat Cards */}
              <StatCards summary={summary} />

              {/* Row 2: Charts */}
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                {/* Timeline — takes 2 cols */}
                <div className="xl:col-span-2">
                  <TimelineChart
                    data={summary?.recent_timeline ?? []}
                  />
                </div>

                {/* Right column: Pie + Protocol */}
                <div className="flex flex-col gap-4">
                  <AttackPieChart
                    data={summary?.top_attack_types ?? []}
                    totalIncidents={summary?.total_incidents ?? 0}
                  />
                  <ProtocolBar
                    data={summary?.protocol_breakdown ?? []}
                    totalIncidents={summary?.total_incidents ?? 0}
                  />
                </div>
              </div>

              {/* Row 3: Incident Table */}
              <IncidentTable incidents={incidents} />
            </>
          )}
    </>
  );
}

/* ── Skeleton Loader ──────────────────────────────────────────────────────── */

function DashboardSkeleton() {
  return (
    <div className="space-y-6 animate-pulse">
      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="card p-5 h-32">
            <div className="h-3 w-28 bg-border rounded mb-4" />
            <div className="h-8 w-20 bg-border rounded mb-2" />
            <div className="h-3 w-36 bg-border rounded" />
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-2 card h-80" />
        <div className="flex flex-col gap-4">
          <div className="card h-64" />
          <div className="card h-32" />
        </div>
      </div>

      {/* Table */}
      <div className="card h-64" />
    </div>
  );
}
