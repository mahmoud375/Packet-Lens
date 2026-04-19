"use client";

import { Search, Bell, LayoutGrid, UserCircle } from "lucide-react";

export default function TopBar() {
  return (
    <header className="h-14 bg-surface border-b border-border flex items-center justify-between px-6 shrink-0">
      {/* Title */}
      <h2 className="text-base font-bold tracking-wide text-foreground font-mono">
        PacketLens
      </h2>

      {/* Search */}
      <div className="flex-1 max-w-md mx-8">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
          <input
            type="text"
            placeholder="Search threats, IPs, rules..."
            className="w-full bg-background border border-border rounded-lg pl-10 pr-4 py-2 text-sm text-foreground placeholder:text-muted focus:outline-none focus:border-cyan/40 focus:ring-1 focus:ring-cyan/20 transition-colors"
          />
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-3">
        <button className="relative p-2 rounded-lg text-muted hover:text-foreground hover:bg-surface-hover transition-colors cursor-pointer">
          <Bell className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-red" />
        </button>
        <button className="p-2 rounded-lg text-muted hover:text-foreground hover:bg-surface-hover transition-colors cursor-pointer">
          <LayoutGrid className="w-5 h-5" />
        </button>
        <button className="p-2 rounded-lg text-muted hover:text-foreground hover:bg-surface-hover transition-colors cursor-pointer">
          <UserCircle className="w-5 h-5" />
        </button>
      </div>
    </header>
  );
}
