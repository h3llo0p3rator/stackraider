import { useEffect, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { useCodeSession } from "@/context/CodeSessionContext";
import type { AppSettings } from "@/lib/types";
import {
  getLatestCodeAnalysis,
  startCodeAnalysis,
  streamCodeAnalysis,
} from "@/lib/codeApi";

type LogEntry = { time: string; message: string; level?: string };

export function AnalysisPage({ settings }: { settings: AppSettings }) {
  const { scanResult, burpTraffic } = useCodeSession();
  const [filePath, setFilePath] = useState("");
  const [scope, setScope] = useState("file");
  const [output, setOutput] = useState("");
  const [log, setLog] = useState<LogEntry[]>([]);
  const [context, setContext] = useState<Record<string, unknown> | null>(null);
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const streamRef = useRef<(() => void) | null>(null);

  const files = scanResult
    ? [...new Set(scanResult.findings.map((f) => String(f.file_path)))].sort()
    : [];

  useEffect(() => () => streamRef.current?.(), []);

  useEffect(() => {
    getLatestCodeAnalysis().then((data) => {
      if (data.full_text) setOutput(String(data.full_text));
      if (data.log) setLog(data.log as LogEntry[]);
      if (data.context) setContext(data.context as Record<string, unknown>);
    }).catch(() => {});
  }, []);

  const run = async () => {
    if (!scanResult || !settings.model) return;
    setStreaming(true);
    setError(null);
    setOutput("");
    setLog([]);
    try {
      const { analysis_id, context: ctx, log: initialLog } = await startCodeAnalysis({
        model: settings.model,
        file_path: scope === "file" ? filePath || files[0] : null,
        scope,
        ollama_host: settings.ollamaHost,
      });
      setContext(ctx);
      setLog(initialLog);
      streamRef.current = streamCodeAnalysis(analysis_id, {
        onToken: (t) => setOutput((p) => p + t),
        onDone: (d) => {
          setStreaming(false);
          if (d.full_text) setOutput(String(d.full_text));
          if (d.log) setLog(d.log as LogEntry[]);
        },
        onError: (m) => { setError(m); setStreaming(false); },
      });
    } catch (e) {
      setError((e as Error).message);
      setStreaming(false);
    }
  };

  if (!scanResult) {
    return <div className="p-6 text-slate-400">Run a static scan first.</div>;
  }

  return (
    <div className="p-6 space-y-4 overflow-y-auto h-full max-w-4xl">
      {burpTraffic?.summary?.total ? (
        <Card className="p-3 text-sm bg-green-500/10 border-green-500/30">
          Burp active: {burpTraffic.summary.total} requests included in analysis context
        </Card>
      ) : (
        <Card className="p-3 text-sm text-slate-400">No Burp traffic — import on Burp tab for cross-reference.</Card>
      )}
      <Card className="p-4 space-y-3">
        <h2 className="font-semibold">LLM Code Analysis</h2>
        <div className="flex gap-3 flex-wrap">
          <select value={scope} onChange={(e) => setScope(e.target.value)} className="bg-slate-900 border rounded px-2 py-1 text-sm">
            <option value="file">Single file</option>
            <option value="all">All vulnerable files</option>
          </select>
          {scope === "file" && (
            <select value={filePath} onChange={(e) => setFilePath(e.target.value)} className="bg-slate-900 border rounded px-2 py-1 text-sm max-w-md">
              <option value="">Select file...</option>
              {files.map((f) => <option key={f} value={f}>{f}</option>)}
            </select>
          )}
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
        <Button onClick={run} disabled={streaming || !settings.model}>
          {streaming ? "Analyzing..." : "Run LLM Analysis"}
        </Button>
      </Card>
      {log.length > 0 && (
        <Card className="p-4 font-mono text-xs space-y-1 max-h-48 overflow-y-auto">
          {log.map((l, i) => (
            <div key={i} className="text-slate-400"><span className="text-indigo-400">{l.time}</span> {l.message}</div>
          ))}
        </Card>
      )}
      {context && (
        <Card className="p-4 text-sm text-slate-400">
          <pre className="whitespace-pre-wrap">{JSON.stringify(context, null, 2)}</pre>
        </Card>
      )}
      {output && (
        <Card className="p-4 prose prose-invert max-w-none">
          <ReactMarkdown>{output}</ReactMarkdown>
        </Card>
      )}
    </div>
  );
}
