"use client";

import { motion } from "framer-motion";
import type { ProtocolStat } from "@/services/api";

interface ProtocolBarProps {
  data: ProtocolStat[];
  totalIncidents: number;
}

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: "#3b82f6",
  UDP: "#8b5cf6",
  ICMP: "#f59e0b",
};

export default function ProtocolBar({ data, totalIncidents }: ProtocolBarProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.45, duration: 0.5 }}
      className="card p-5"
    >
      <h3 className="text-sm font-semibold text-foreground mb-4">
        Network Protocols
      </h3>

      <div className="space-y-4">
        {data.map((proto) => {
          const pct =
            totalIncidents > 0
              ? Math.round((proto.count / totalIncidents) * 100)
              : 0;
          const color =
            PROTOCOL_COLORS[proto.protocol_name] || "#64748b";

          return (
            <div key={proto.protocol}>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-mono text-muted">
                  {proto.protocol_name}
                </span>
                <span className="text-xs font-mono text-foreground">
                  {pct}%
                </span>
              </div>
              <div className="h-2 bg-border rounded-full overflow-hidden">
                <motion.div
                  className="h-full rounded-full"
                  style={{ backgroundColor: color }}
                  initial={{ width: 0 }}
                  animate={{ width: `${pct}%` }}
                  transition={{
                    delay: 0.6,
                    duration: 0.7,
                    ease: "easeOut",
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </motion.div>
  );
}
