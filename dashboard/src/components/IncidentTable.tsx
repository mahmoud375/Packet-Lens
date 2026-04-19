"use client";

import { motion } from "framer-motion";
import { Filter } from "lucide-react";
import StatusBadge from "./StatusBadge";
import type { Incident } from "@/services/api";

interface IncidentTableProps {
  incidents: Incident[];
}

const protocolMap: Record<number, string> = {
  6: "TCP",
  17: "UDP",
  1: "ICMP",
};

export default function IncidentTable({ incidents }: IncidentTableProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.5, duration: 0.5 }}
      className="card overflow-hidden"
    >
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-border">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-amber pulse-dot" />
          <h3 className="text-sm font-semibold text-foreground">
            Live Incident Feed
          </h3>
        </div>
        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs text-muted hover:text-foreground hover:bg-surface-hover border border-border transition-colors cursor-pointer">
          <Filter className="w-3.5 h-3.5" />
          Filter
        </button>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              {[
                "Timestamp",
                "Source IP:Port",
                "Destination IP:Port",
                "Protocol",
                "Attack Classification",
                "Confidence",
                "Status",
              ].map((header) => (
                <th
                  key={header}
                  className="px-5 py-3 text-left text-[10px] font-mono text-muted uppercase tracking-[0.15em]"
                >
                  {header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {incidents.length === 0 && (
              <tr>
                <td
                  colSpan={7}
                  className="px-5 py-12 text-center text-sm text-muted"
                >
                  No incidents detected yet. The system is monitoring...
                </td>
              </tr>
            )}
            {incidents.map((inc) => (
              <tr
                key={inc.id}
                className="incident-row border-b border-border/50 last:border-b-0"
              >
                <td className="px-5 py-3 text-xs font-mono text-muted whitespace-nowrap">
                  {formatTimestamp(inc.detected_at)}
                </td>
                <td className="px-5 py-3 text-xs font-mono text-cyan whitespace-nowrap">
                  {inc.src_ip}:{inc.src_port}
                </td>
                <td className="px-5 py-3 text-xs font-mono text-foreground/70 whitespace-nowrap">
                  {inc.dst_ip}:{inc.dst_port}
                </td>
                <td className="px-5 py-3 text-xs font-mono text-muted">
                  {protocolMap[inc.protocol] || `IP/${inc.protocol}`}
                </td>
                <td className="px-5 py-3 text-xs text-foreground">
                  {inc.attack_type}
                </td>
                <td className="px-5 py-3">
                  <ConfidenceBar value={inc.confidence} />
                </td>
                <td className="px-5 py-3">
                  <StatusBadge status={inc.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </motion.div>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color =
    pct >= 90 ? "#ef4444" : pct >= 70 ? "#f59e0b" : "#10b981";

  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-border rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-xs font-mono text-muted">{pct}%</span>
    </div>
  );
}

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      fractionalSecondDigits: 3,
      hour12: false,
    });
  } catch {
    return iso;
  }
}
