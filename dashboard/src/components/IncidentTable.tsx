"use client";

import { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
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

/** Estimated height of each row in pixels (py-3 top + py-3 bottom + content) */
const ROW_HEIGHT = 44;

/** Height of the scrollable viewport */
const TABLE_HEIGHT = 520;

const COLUMNS = [
  "Timestamp",
  "Source IP:Port",
  "Destination IP:Port",
  "Protocol",
  "Attack Classification",
  "Confidence",
  "Status",
];

export default function IncidentTable({ incidents }: IncidentTableProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: incidents.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20, // render 20 extra rows above/below viewport for smooth scrolling
  });

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
          <span className="text-xs font-mono text-muted ml-2">
            ({incidents.length.toLocaleString()} total)
          </span>
        </div>
        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs text-muted hover:text-foreground hover:bg-surface-hover border border-border transition-colors cursor-pointer">
          <Filter className="w-3.5 h-3.5" />
          Filter
        </button>
      </div>

      {/* Sticky Column Headers */}
      <div className="overflow-x-auto">
        <div className="min-w-[900px]">
          <div className="grid grid-cols-[140px_160px_160px_80px_1fr_120px_100px] border-b border-border">
            {COLUMNS.map((header) => (
              <div
                key={header}
                className="px-5 py-3 text-left text-[10px] font-mono text-muted uppercase tracking-[0.15em]"
              >
                {header}
              </div>
            ))}
          </div>

          {/* Virtualized Scrollable Rows */}
          {incidents.length === 0 ? (
            <div className="px-5 py-12 text-center text-sm text-muted">
              No incidents detected yet. The system is monitoring...
            </div>
          ) : (
            <div
              ref={scrollRef}
              className="overflow-y-auto"
              style={{ height: TABLE_HEIGHT }}
            >
              {/* Total height spacer — this is what makes scrollbar accurate */}
              <div
                style={{
                  height: virtualizer.getTotalSize(),
                  width: "100%",
                  position: "relative",
                }}
              >
                {virtualizer.getVirtualItems().map((virtualRow) => {
                  const inc = incidents[virtualRow.index];
                  return (
                    <div
                      key={inc.id}
                      data-index={virtualRow.index}
                      ref={virtualizer.measureElement}
                      className="grid grid-cols-[140px_160px_160px_80px_1fr_120px_100px] border-b border-border/50 incident-row absolute w-full"
                      style={{
                        transform: `translateY(${virtualRow.start}px)`,
                      }}
                    >
                      <div className="px-5 py-3 text-xs font-mono text-muted whitespace-nowrap">
                        {formatTimestamp(inc.detected_at)}
                      </div>
                      <div className="px-5 py-3 text-xs font-mono text-cyan whitespace-nowrap">
                        {inc.src_ip}:{inc.src_port}
                      </div>
                      <div className="px-5 py-3 text-xs font-mono text-foreground/70 whitespace-nowrap">
                        {inc.dst_ip}:{inc.dst_port}
                      </div>
                      <div className="px-5 py-3 text-xs font-mono text-muted">
                        {protocolMap[inc.protocol] || `IP/${inc.protocol}`}
                      </div>
                      <div className="px-5 py-3 text-xs text-foreground">
                        {inc.attack_type}
                      </div>
                      <div className="px-5 py-3">
                        <ConfidenceBar value={inc.confidence} />
                      </div>
                      <div className="px-5 py-3">
                        <StatusBadge status={inc.status} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
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
