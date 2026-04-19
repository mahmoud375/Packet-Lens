"use client";

import { motion } from "framer-motion";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type { TimelineBucket } from "@/services/api";

interface TimelineChartProps {
  data: TimelineBucket[];
}

export default function TimelineChart({ data }: TimelineChartProps) {
  const formatted = data.map((d) => ({
    hour: new Date(d.hour).toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }),
    count: d.count,
  }));

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.3, duration: 0.5 }}
      className="card p-5 flex flex-col"
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-foreground">
            Threat Volume Topology
          </h3>
          <p className="text-xs text-muted mt-0.5">
            24-Hour rolling window vs baseline
          </p>
        </div>
        <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-cyan/10 border border-cyan/20 text-[10px] font-mono text-cyan uppercase tracking-wider">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan pulse-dot" />
          Live
        </span>
      </div>

      {/* Chart */}
      <div className="flex-1 min-h-[280px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={formatted}
            margin={{ top: 10, right: 10, left: -10, bottom: 0 }}
          >
            <defs>
              <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#1a2744"
              vertical={false}
            />
            <XAxis
              dataKey="hour"
              tick={{ fill: "#64748b", fontSize: 11 }}
              axisLine={{ stroke: "#1a2744" }}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: "#64748b", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v: number) =>
                v >= 1000 ? `${(v / 1000).toFixed(1)}k` : String(v)
              }
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#0c1322",
                border: "1px solid #1e3a5f",
                borderRadius: "8px",
                fontSize: "12px",
                color: "#e2e8f0",
              }}
              labelStyle={{ color: "#64748b", marginBottom: 4 }}
              formatter={(value) => [
                Number(value).toLocaleString(),
                "Incidents",
              ]}
            />
            <Area
              type="monotone"
              dataKey="count"
              stroke="#22d3ee"
              strokeWidth={2}
              fill="url(#cyanGrad)"
              dot={false}
              activeDot={{
                r: 4,
                fill: "#22d3ee",
                stroke: "#0c1322",
                strokeWidth: 2,
              }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );
}
