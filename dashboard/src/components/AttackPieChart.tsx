"use client";

import { motion } from "framer-motion";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import type { AttackTypeStat } from "@/services/api";

interface AttackPieChartProps {
  data: AttackTypeStat[];
  totalIncidents: number;
}

const COLORS = ["#ef4444", "#f59e0b", "#8b5cf6", "#3b82f6", "#10b981"];

export default function AttackPieChart({
  data,
  totalIncidents,
}: AttackPieChartProps) {
  const chartData = data.map((d) => ({
    name: d.attack_type,
    value: d.count,
    pct:
      totalIncidents > 0 ? Math.round((d.count / totalIncidents) * 100) : 0,
  }));

  const totalDisplay =
    totalIncidents >= 1000
      ? `${(totalIncidents / 1000).toFixed(1)}k`
      : String(totalIncidents);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.4, duration: 0.5 }}
      className="card p-5"
    >
      <h3 className="text-sm font-semibold text-foreground mb-4">
        Top 5 Attack Types
      </h3>

      {/* Donut */}
      <div className="relative h-44">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={75}
              paddingAngle={3}
              dataKey="value"
              stroke="none"
            >
              {chartData.map((_, i) => (
                <Cell key={i} fill={COLORS[i % COLORS.length]} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-[10px] text-muted uppercase tracking-wider">
            Total
          </span>
          <span className="text-xl font-bold text-foreground">
            {totalDisplay}
          </span>
        </div>
      </div>

      {/* Legend */}
      <div className="mt-4 space-y-2">
        {chartData.map((item, i) => (
          <div key={item.name} className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span
                className="w-2.5 h-2.5 rounded-sm shrink-0"
                style={{ backgroundColor: COLORS[i % COLORS.length] }}
              />
              <span className="text-xs text-muted truncate max-w-[120px]">
                {item.name}
              </span>
            </div>
            <span className="text-xs font-mono text-foreground">
              {item.pct}%
            </span>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
