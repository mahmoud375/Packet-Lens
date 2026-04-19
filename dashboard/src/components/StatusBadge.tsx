"use client";

interface StatusBadgeProps {
  status: string;
}

const statusStyles: Record<string, string> = {
  open: "bg-green/15 text-green border-green/30",
  acknowledged: "bg-amber/15 text-amber border-amber/30",
  blocked: "bg-red/15 text-red border-red/30",
  false_positive: "bg-muted/15 text-muted border-muted/30",
};

export default function StatusBadge({ status }: StatusBadgeProps) {
  const style = statusStyles[status] || statusStyles.open;
  const label = status
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-md text-[10px] font-semibold uppercase tracking-wider border ${style}`}
    >
      {label}
    </span>
  );
}
