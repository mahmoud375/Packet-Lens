"use client";

import { useEffect, useState } from "react";
import IncidentTable from "@/components/IncidentTable";
import { fetchIncidents, type Incident } from "@/services/api";

export default function AlertsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchIncidents({ limit: 100 })
      .then((data) => setIncidents(data.data ?? []))
      .catch((err) => console.error("Failed to load incidents", err))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground tracking-tight">Security Alerts</h1>
        <p className="text-muted text-sm mt-1">Comprehensive log of all detected network anomalies.</p>
      </div>

      {loading ? (
        <div className="card h-96 animate-pulse" />
      ) : (
        <IncidentTable incidents={incidents} />
      )}
    </div>
  );
}
