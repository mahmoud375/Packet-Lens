"use client";

import { ShieldCheck, Webhook, Palette } from "lucide-react";

export default function SettingsPage() {
  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-foreground tracking-tight">System Configuration</h1>
        <p className="text-muted text-sm mt-1">Manage network interfaces, alerts, and dashboard preferences.</p>
      </div>

      <div className="grid gap-6">
        {/* Webhook Configuration */}
        <div className="card p-6">
          <div className="flex items-center gap-3 mb-4">
            <Webhook className="text-cyan w-5 h-5" />
            <h2 className="text-lg font-semibold text-foreground">Alert Webhooks</h2>
          </div>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-muted mb-1.5">Telegram Bot Token</label>
              <input 
                type="password" 
                defaultValue="*****************"
                className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-sm text-foreground focus:outline-none focus:border-cyan/50 focus:ring-1 focus:ring-cyan/50 transition-all"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-muted mb-1.5">Telegram Chat ID</label>
              <input 
                type="text" 
                defaultValue="-100123456789"
                className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-sm text-foreground focus:outline-none focus:border-cyan/50 focus:ring-1 focus:ring-cyan/50 transition-all"
              />
            </div>
            <button className="bg-cyan/10 text-cyan border border-cyan/20 px-4 py-2 rounded-lg text-sm font-medium hover:bg-cyan/20 transition-colors">
              Save Webhook Configuration
            </button>
          </div>
        </div>

        {/* Inference Settings */}
        <div className="card p-6">
          <div className="flex items-center gap-3 mb-4">
            <ShieldCheck className="text-green w-5 h-5" />
            <h2 className="text-lg font-semibold text-foreground">Inference Engine</h2>
          </div>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-medium text-foreground">Strict Mode</h3>
                <p className="text-xs text-muted mt-0.5">Block all flagged packets immediately</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" className="sr-only peer" defaultChecked />
                <div className="w-11 h-6 bg-surface-hover peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green"></div>
              </label>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
