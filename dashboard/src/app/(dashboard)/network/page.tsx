"use client";

import { Globe } from "lucide-react";

export default function NetworkPage() {
  return (
    <div className="space-y-6 h-full flex flex-col">
      <div>
        <h1 className="text-2xl font-bold text-foreground tracking-tight">Network Map</h1>
        <p className="text-muted text-sm mt-1">Live visualization of network nodes and traffic flows.</p>
      </div>

      <div className="card flex-1 flex flex-col items-center justify-center text-center p-10 min-h-[500px]">
        <div className="w-16 h-16 rounded-2xl bg-cyan/10 border border-cyan/20 flex items-center justify-center mb-4">
          <Globe className="w-8 h-8 text-cyan animate-pulse" />
        </div>
        <h2 className="text-xl font-semibold text-foreground mb-2">Topology Mapper</h2>
        <p className="text-muted max-w-md">
          The interactive network topology map is currently analyzing node relationships. 
          This feature will be fully activated in an upcoming update.
        </p>
      </div>
    </div>
  );
}
