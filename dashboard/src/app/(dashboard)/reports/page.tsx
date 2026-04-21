"use client";

import { useEffect, useState } from "react";
import StatCards from "@/components/StatCards";
import TimelineChart from "@/components/TimelineChart";
import { fetchSummary, type SummaryResponse } from "@/services/api";

export default function ReportsPage() {
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSummary()
      .then(setSummary)
      .catch((err) => console.error("Failed to load reports", err))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground tracking-tight">Analytics Reports</h1>
        <p className="text-muted text-sm mt-1">Aggregated historical metrics and attack trends.</p>
      </div>

      {loading ? (
        <div className="space-y-6 animate-pulse">
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="card p-5 h-32" />
            ))}
          </div>
          <div className="card h-80" />
        </div>
      ) : (
        <>
          <StatCards summary={summary} />
          <div className="card p-5">
            <h2 className="text-lg font-semibold text-foreground mb-4">Traffic Volume Trends</h2>
            <TimelineChart data={summary?.recent_timeline ?? []} />
          </div>
        </>
      )}
    </div>
  );
}
