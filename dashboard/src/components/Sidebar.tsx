"use client";

import {
  Shield,
  LayoutDashboard,
  Bell,
  FileBarChart,
  Globe,
  Settings,
} from "lucide-react";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navItems = [
  { icon: LayoutDashboard, label: "Dashboard", href: "/" },
  { icon: Bell, label: "Alerts", href: "/alerts" },
  { icon: FileBarChart, label: "Reports", href: "/reports" },
  { icon: Globe, label: "Network Map", href: "/network" },
  { icon: Settings, label: "Settings", href: "/settings" },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-52 min-h-screen bg-surface border-r border-border flex flex-col shrink-0">
      {/* Logo */}
      <div className="px-5 py-6 flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-cyan/10 border border-cyan/30 flex items-center justify-center">
          <Shield className="w-5 h-5 text-cyan" />
        </div>
        <div>
          <h1 className="text-sm font-bold text-foreground tracking-wide">
            PacketLens
          </h1>
          <div className="flex items-center gap-1.5 mt-0.5">
            <span className="w-1.5 h-1.5 rounded-full bg-green pulse-dot" />
            <span className="text-[10px] font-mono text-muted uppercase tracking-widest">
              Sentinel Active
            </span>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 mt-2">
        <ul className="space-y-1">
          {navItems.map((item) => {
            const isActive = pathname === item.href;
            return (
              <li key={item.label}>
                <Link
                  href={item.href}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 cursor-pointer ${
                    isActive
                      ? "bg-cyan/10 text-cyan border border-cyan/20"
                      : "text-muted hover:text-foreground hover:bg-surface-hover border border-transparent"
                  }`}
                >
                  <item.icon className="w-[18px] h-[18px]" />
                  <span className="font-medium">{item.label}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Export */}
      <div className="p-4">
        <button className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-cyan/10 text-cyan text-sm font-semibold border border-cyan/20 hover:bg-cyan/20 transition-colors cursor-pointer">
          <FileBarChart className="w-4 h-4" />
          Export Logs
        </button>
      </div>
    </aside>
  );
}
