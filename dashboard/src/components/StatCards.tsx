"use client";

import { motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  Crosshair,
  BrainCircuit,
} from "lucide-react";
import type { SummaryResponse } from "@/services/api";

interface StatCardsProps {
  summary: SummaryResponse | null;
}

export default function StatCards({ summary }: StatCardsProps) {
  const totalIncidents = summary?.total_incidents ?? 0;
  const openIncidents = summary?.open_incidents ?? 0;

  const topAttack = summary?.top_attack_types?.[0];
  const topAttackLabel = topAttack?.attack_type ?? "—";
  const topAttackPct =
    totalIncidents > 0 && topAttack
      ? Math.round((topAttack.count / totalIncidents) * 100)
      : 0;

  // Weighted average confidence from top attacks
  const avgConfidence =
    summary?.top_attack_types && summary.top_attack_types.length > 0
      ? summary.top_attack_types.reduce(
          (sum, a) => sum + a.avg_confidence * a.count,
          0
        ) /
        summary.top_attack_types.reduce((sum, a) => sum + a.count, 0)
      : 0;

  const cards = [
    {
      label: "TOTAL INCIDENTS",
      value: formatNumber(totalIncidents),
      sub: "All time recorded",
      icon: Activity,
      accent: "cyan",
      accentColor: "#22d3ee",
    },
    {
      label: "ACTIVE THREATS",
      value: formatNumber(openIncidents),
      sub: openIncidents > 100 ? "Requires immediate triage" : "Under control",
      icon: AlertTriangle,
      accent: "red",
      accentColor: "#ef4444",
      urgent: openIncidents > 100,
    },
    {
      label: "PRIMARY ATTACK VECTOR",
      value: topAttackLabel,
      sub: `${topAttackPct}% of total volume`,
      icon: Crosshair,
      accent: "amber",
      accentColor: "#f59e0b",
      isText: true,
    },
    {
      label: "AVG AI CONFIDENCE",
      value: `${(avgConfidence * 100).toFixed(1)}%`,
      sub: null,
      icon: BrainCircuit,
      accent: "cyan",
      accentColor: "#22d3ee",
      showBar: true,
      barValue: avgConfidence,
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      {cards.map((card, i) => (
        <motion.div
          key={card.label}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: i * 0.08, duration: 0.4 }}
          className="stat-card card p-5"
          style={
            { "--accent-color": card.accentColor } as React.CSSProperties
          }
        >
          <div className="flex items-center justify-between mb-3">
            <span className="text-[10px] font-mono text-muted uppercase tracking-[0.15em]">
              {card.label}
            </span>
            <card.icon
              className="w-4 h-4"
              style={{ color: card.accentColor }}
            />
          </div>

          <div
            className={`font-bold tracking-tight ${
              card.isText ? "text-xl" : "text-3xl"
            } ${card.urgent ? "text-red" : "text-foreground"}`}
          >
            {card.value}
          </div>

          {card.sub && (
            <p
              className={`text-xs mt-1.5 ${
                card.urgent ? "text-red/70" : "text-muted"
              }`}
            >
              {card.sub}
            </p>
          )}

          {card.showBar && (
            <div className="mt-3 h-1.5 bg-border rounded-full overflow-hidden">
              <motion.div
                className="h-full rounded-full"
                style={{ backgroundColor: card.accentColor }}
                initial={{ width: 0 }}
                animate={{ width: `${(card.barValue ?? 0) * 100}%` }}
                transition={{ delay: 0.5, duration: 0.8, ease: "easeOut" }}
              />
            </div>
          )}
        </motion.div>
      ))}
    </div>
  );
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return n.toLocaleString("en-US");
  return String(n);
}
