"use client";

import { useEffect, useState, useCallback } from "react";
import Sidebar from "@/components/Sidebar";
import TopBar from "@/components/TopBar";
import StatCards from "@/components/StatCards";
import TimelineChart from "@/components/TimelineChart";
import AttackPieChart from "@/components/AttackPieChart";
import ProtocolBar from "@/components/ProtocolBar";
import IncidentTable from "@/components/IncidentTable";
import {
  fetchSummary,
  fetchIncidents,
  type SummaryResponse,
  type Incident,
} from "@/services/api";

const POLL_INTERVAL = 5_000; // 5 seconds

export default function DashboardPage() {
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [summaryData, incidentData] = await Promise.all([
        fetchSummary(),
        fetchIncidents({ limit: 20 }),
      ]);
      setSummary(summaryData);
      setIncidents(incidentData.data ?? []);
      setError(null);
    } catch (err) {
      console.error("Dashboard fetch error:", err);
      setError("Failed to connect to API");
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial load + polling
  useEffect(() => {
    loadData();
    const timer = setInterval(loadData, POLL_INTERVAL);
    return () => clearInterval(timer);
  }, [loadData]);

  return (
    <div className="flex w-full min-h-screen bg-background">
      <Sidebar />

      <div className="flex-1 flex flex-col min-w-0">
        <TopBar />

        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Error Banner */}
          {error && (
            <div className="rounded-lg border border-red/30 bg-red/10 px-4 py-3 text-sm text-red">
              ⚠ {error} — Retrying every {POLL_INTERVAL / 1000}s...
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
        </main>
      </div>
    </div>
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
