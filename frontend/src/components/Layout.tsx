import { NavLink, Outlet } from "react-router-dom";
import {
  Brain,
  Code2,
  FileJson,
  GitBranch,
  MessageSquare,
  Search,
  Settings,
  Shield,
  Terminal,
  Upload,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { DownloadBanner } from "./DownloadBanner";
import { StatusBar } from "./StatusBar";
import { useCodeSession } from "@/context/CodeSessionContext";
import type { AppSettings } from "@/lib/types";

const codeNav = [
  { to: "/code/scan", icon: Code2, label: "Scan" },
  { to: "/code/results", icon: Shield, label: "Results" },
  { to: "/code/burp", icon: Upload, label: "Burp" },
  { to: "/code/analysis", icon: Terminal, label: "LLM" },
  { to: "/code/correlation", icon: GitBranch, label: "Correlate" },
];

const graphqlNav = [
  { to: "/graphql", icon: FileJson, label: "Analyze" },
  { to: "/graphql/schema", icon: Search, label: "Schema" },
  { to: "/graphql/findings", icon: Shield, label: "Findings" },
  { to: "/graphql/queries", icon: Terminal, label: "Queries" },
];

const sharedNav = [
  { to: "/models", icon: Brain, label: "Models" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

interface LayoutProps {
  settings: AppSettings;
  onOpenChat: () => void;
}

export function Layout({ settings, onOpenChat }: LayoutProps) {
  const { session } = useCodeSession();

  return (
    <div className="flex h-full">
      <aside className="w-56 flex-shrink-0 border-r border-[var(--color-border)] bg-[var(--color-surface-elevated)] flex flex-col overflow-y-auto">
        <div className="p-5 border-b border-[var(--color-border)]">
          <div className="flex items-center gap-2">
            <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="font-semibold text-white tracking-tight">StackRaider</h1>
              <p className="text-[10px] text-slate-500 uppercase tracking-widest">Pentest Platform</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-3 space-y-4">
          <div>
            <p className="px-3 text-[10px] uppercase tracking-widest text-slate-600 mb-1">Code</p>
            <div className="space-y-1">
              {codeNav.map(({ to, icon: Icon, label }) => {
                let badge: string | undefined;
                if (to === "/code/results" && session?.scan_findings) badge = String(session.scan_findings);
                if (to === "/code/burp" && session?.burp_summary?.total) badge = String(session.burp_summary.total);
                return (
                  <NavLink key={to} to={to} className={({ isActive }) =>
                    cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm", isActive ? "bg-indigo-500/15 text-indigo-300 border border-indigo-500/30" : "text-slate-400 hover:bg-slate-800/50")
                  }>
                    <Icon className="h-4 w-4" />
                    <span className="flex-1">{label}</span>
                    {badge && <span className="text-xs opacity-70">{badge}</span>}
                  </NavLink>
                );
              })}
            </div>
          </div>
          <div>
            <p className="px-3 text-[10px] uppercase tracking-widest text-slate-600 mb-1">GraphQL</p>
            <div className="space-y-1">
              {graphqlNav.map(({ to, icon: Icon, label }) => (
                <NavLink key={to} to={to} end={to === "/graphql"} className={({ isActive }) =>
                  cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm", isActive ? "bg-indigo-500/15 text-indigo-300 border border-indigo-500/30" : "text-slate-400 hover:bg-slate-800/50")
                }>
                  <Icon className="h-4 w-4" />
                  {label}
                  {to === "/graphql/findings" && session?.graphql_findings_count ? (
                    <span className="ml-auto text-xs opacity-70">{session.graphql_findings_count}</span>
                  ) : null}
                </NavLink>
              ))}
            </div>
          </div>
          <div>
            <p className="px-3 text-[10px] uppercase tracking-widest text-slate-600 mb-1">Shared</p>
            <div className="space-y-1">
              {sharedNav.map(({ to, icon: Icon, label }) => (
                <NavLink key={to} to={to} className={({ isActive }) =>
                  cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm", isActive ? "bg-indigo-500/15 text-indigo-300" : "text-slate-400 hover:bg-slate-800/50")
                }>
                  <Icon className="h-4 w-4" />
                  {label}
                </NavLink>
              ))}
            </div>
          </div>
        </nav>

        <div className="p-4 border-t border-[var(--color-border)]">
          <StatusBar settings={settings} />
        </div>
      </aside>

      <main className="flex-1 overflow-hidden flex flex-col relative">
        <DownloadBanner />
        <Outlet />
        <button
          onClick={onOpenChat}
          className="fixed bottom-6 right-6 z-40 h-14 w-14 rounded-full bg-gradient-to-br from-indigo-500 to-violet-600 text-white shadow-xl flex items-center justify-center hover:scale-105 transition-transform"
          title="Chat with LLM"
        >
          <MessageSquare className="h-6 w-6" />
        </button>
      </main>
    </div>
  );
}
