import { useEffect, useState } from "react";
import { Activity, Circle, Download } from "lucide-react";
import { fetchHealth } from "@/lib/api";
import { useModelDownloadContext } from "@/context/ModelDownloadContext";
import type { AppSettings } from "@/lib/types";

export function StatusBar({ settings }: { settings: AppSettings }) {
  const [connected, setConnected] = useState<boolean | null>(null);
  const [modelCount, setModelCount] = useState(0);
  const { activeJobs, models } = useModelDownloadContext();

  useEffect(() => {
    const check = async () => {
      try {
        const data = await fetchHealth();
        setConnected(data.connected);
        setModelCount(data.model_count ?? 0);
      } catch {
        setConnected(false);
      }
    };
    check();
    const id = setInterval(check, 15000);
    return () => clearInterval(id);
  }, [settings.ollamaHost]);

  const installedCount = models.length || modelCount;
  const download = activeJobs[0];

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-4 text-xs text-slate-400 flex-wrap">
        <div className="flex items-center gap-1.5">
          <Circle
            className={`h-2 w-2 fill-current ${
              connected === null
                ? "text-slate-500"
                : connected
                  ? "text-emerald-400"
                  : "text-red-400"
            }`}
          />
          <span>
            Ollama {connected ? "connected" : connected === false ? "offline" : "checking..."}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <Activity className="h-3 w-3" />
          <span>{installedCount} model{installedCount !== 1 ? "s" : ""}</span>
        </div>
        {download && (
          <div className="flex items-center gap-1.5 text-indigo-400">
            <Download className="h-3 w-3 animate-pulse" />
            <span className="font-mono truncate max-w-[120px]">{download.name}</span>
            <span>{download.percent != null ? `${Math.round(download.percent)}%` : "…"}</span>
          </div>
        )}
        <span className="text-slate-600 hidden sm:inline">|</span>
        <span className="font-mono text-slate-500 truncate">{settings.model}</span>
      </div>
    </div>
  );
}
