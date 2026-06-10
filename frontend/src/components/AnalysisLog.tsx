import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Loader2, Terminal } from "lucide-react";
import { Card } from "./ui/Card";
import type { AnalysisLogEntry, AnalysisPhase } from "@/lib/types";
import { cn } from "@/lib/utils";

const LEVEL_STYLES: Record<AnalysisLogEntry["level"], string> = {
  info: "text-slate-400",
  success: "text-emerald-400",
  error: "text-red-400",
  llm: "text-indigo-300",
};

interface AnalysisLogProps {
  logs: AnalysisLogEntry[];
  phase: AnalysisPhase;
  loading: boolean;
  findingCount: number;
  queryCount: number;
}

function formatElapsed(seconds: number) {
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

export function AnalysisLog({
  logs,
  phase,
  loading,
  findingCount,
  queryCount,
}: AnalysisLogProps) {
  const bottomRef = useRef<HTMLDivElement>(null);
  const startRef = useRef<number | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const [lastActivity, setLastActivity] = useState(Date.now());

  useEffect(() => {
    if (loading && startRef.current === null) {
      startRef.current = Date.now();
    }
    if (!loading) {
      startRef.current = null;
    }
  }, [loading]);

  useEffect(() => {
    if (!loading) return;
    const id = setInterval(() => {
      if (startRef.current) {
        setElapsed(Math.floor((Date.now() - startRef.current) / 1000));
      }
    }, 1000);
    return () => clearInterval(id);
  }, [loading]);

  useEffect(() => {
    setLastActivity(Date.now());
  }, [logs]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  if (!loading && logs.length === 0) return null;

  const llmStream = logs
    .filter((l) => l.level === "llm" && l.chunk)
    .map((l) => l.chunk)
    .join("");

  const lineLogs = logs.filter((l) => l.message);
  const idleSeconds = Math.floor((Date.now() - lastActivity) / 1000);
  const showIdleHint = loading && idleSeconds >= 4 && phase === "llm";

  return (
    <Card className="flex flex-col min-h-[220px] max-h-[40vh] w-full p-0 overflow-hidden border-indigo-500/20">
      <div className="flex items-center justify-between px-4 py-2 border-b border-[var(--color-border)] bg-slate-900/60">
        <div className="flex items-center gap-2 text-sm flex-wrap">
          {loading ? (
            <Loader2 className="h-4 w-4 text-indigo-400 animate-spin" />
          ) : (
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          )}
          <Terminal className="h-4 w-4 text-slate-500" />
          <span className="text-slate-300 font-medium">Analysis Log</span>
          <span className="text-xs text-slate-500 capitalize">— {phase.replace("_", " ")}</span>
          {loading && elapsed > 0 && (
            <span className="text-xs text-slate-600 font-mono">{formatElapsed(elapsed)}</span>
          )}
        </div>
        {(findingCount > 0 || queryCount > 0) && (
          <div className="flex gap-3 text-xs">
            {findingCount > 0 && (
              <Link to="/findings" className="text-indigo-400 hover:text-indigo-300">
                {findingCount} findings →
              </Link>
            )}
            {queryCount > 0 && (
              <Link to="/queries" className="text-indigo-400 hover:text-indigo-300">
                {queryCount} queries →
              </Link>
            )}
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto p-4 font-mono text-xs leading-relaxed space-y-1 bg-[#080a0f]">
        {lineLogs.map((entry) => (
          <div key={entry.id} className="flex gap-2">
            <span className="text-slate-600 shrink-0">{entry.time}</span>
            <span className={cn("uppercase w-14 shrink-0", LEVEL_STYLES[entry.level])}>
              {entry.level === "llm" ? "model" : entry.level}
            </span>
            <span className={LEVEL_STYLES[entry.level]}>{entry.message}</span>
          </div>
        ))}

        {showIdleHint && (
          <p className="text-amber-400/90 pl-[4.5rem] animate-pulse">
            Model still thinking — no new output for {idleSeconds}s. Large models like
            deepseek-r1 can take a minute to load on first request.
          </p>
        )}

        {llmStream && (
          <div className="mt-2 pt-2 border-t border-slate-800">
            <div className="flex gap-2 mb-1">
              <span className="text-slate-600">··</span>
              <span className="text-indigo-400 uppercase w-14">stream</span>
            </div>
            <pre className="text-indigo-200/90 whitespace-pre-wrap break-words pl-[4.5rem] max-h-48 overflow-y-auto">
              {llmStream}
              {loading && phase === "llm" && (
                <span className="inline-block w-2 h-3 bg-indigo-400 ml-0.5 animate-pulse" />
              )}
            </pre>
          </div>
        )}

        {loading && logs.length <= 1 && (
          <p className="text-slate-500 animate-pulse pl-[4.5rem]">
            Waiting for server response...
          </p>
        )}

        <div ref={bottomRef} />
      </div>
    </Card>
  );
}
