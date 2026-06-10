import { useCallback, useState } from "react";
import Editor from "@monaco-editor/react";
import { AlertCircle, Play, Upload } from "lucide-react";
import { AnalysisLog } from "./AnalysisLog";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import type { AnalysisLogEntry, AnalysisPhase } from "@/lib/types";

interface IntrospectionInputProps {
  onAnalyze: (data: unknown) => void;
  loading: boolean;
  status: string | null;
  error: string | null;
  onCancel: () => void;
  logs: AnalysisLogEntry[];
  phase: AnalysisPhase;
  findingCount: number;
  queryCount: number;
}

export function IntrospectionInput({
  onAnalyze,
  loading,
  status,
  error,
  onCancel,
  logs,
  phase,
  findingCount,
  queryCount,
}: IntrospectionInputProps) {
  const [value, setValue] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);

  const validateAndParse = useCallback(() => {
    try {
      const parsed = JSON.parse(value);
      if (!parsed.data?.__schema && !parsed.__schema) {
        setParseError("Missing __schema in introspection response");
        return null;
      }
      setParseError(null);
      return parsed;
    } catch (e) {
      setParseError((e as Error).message);
      return null;
    }
  }, [value]);

  const handleAnalyze = () => {
    const parsed = validateAndParse();
    if (parsed) onAnalyze(parsed);
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setValue(reader.result as string);
      setParseError(null);
    };
    reader.readAsText(file);
  }, []);

  const showLog = loading || logs.length > 0;

  return (
    <div className="flex flex-col h-full p-6 gap-4 min-h-0 overflow-y-auto">
      <div className="shrink-0">
        <h2 className="text-2xl font-semibold text-white">Introspection Input</h2>
        <p className="text-slate-400 text-sm mt-1">
          Paste or drop a GraphQL introspection response JSON to begin security analysis.
        </p>
      </div>

      <div className="flex flex-col gap-4 flex-1 min-h-0">
        <div
          className={
            showLog
              ? "h-[38vh] min-h-[220px] max-h-[420px] shrink-0"
              : "flex-1 min-h-[300px]"
          }
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
        >
          <Card
            className={`flex flex-col h-full min-h-0 p-0 overflow-hidden ${
              dragOver ? "border-indigo-500 ring-2 ring-indigo-500/30" : ""
            }`}
          >
            <div className="flex items-center justify-between px-4 py-2 border-b border-[var(--color-border)] bg-slate-900/50">
              <span className="text-xs text-slate-500 font-mono">introspection.json</span>
              <label className="cursor-pointer text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1">
                <Upload className="h-3 w-3" />
                Drop .json or click
                <input
                  type="file"
                  accept=".json,application/json"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (!file) return;
                    const reader = new FileReader();
                    reader.onload = () => setValue(reader.result as string);
                    reader.readAsText(file);
                  }}
                />
              </label>
            </div>
            <div className="flex-1 min-h-[200px]">
              <Editor
                height="100%"
                defaultLanguage="json"
                theme="vs-dark"
                value={value}
                onChange={(v) => {
                  setValue(v ?? "");
                  setParseError(null);
                }}
                options={{
                  minimap: { enabled: false },
                  fontSize: 13,
                  fontFamily: "JetBrains Mono, monospace",
                  padding: { top: 12 },
                  scrollBeyondLastLine: false,
                }}
              />
            </div>
          </Card>
        </div>

        {showLog && (
          <div className="shrink-0 w-full">
            <AnalysisLog
              logs={logs}
              phase={phase}
              loading={loading}
              findingCount={findingCount}
              queryCount={queryCount}
            />
          </div>
        )}
      </div>

      {(parseError || error) && (
        <div className="flex items-center gap-2 text-red-400 text-sm">
          <AlertCircle className="h-4 w-4" />
          {parseError || error}
        </div>
      )}

      {status && !showLog && (
        <p className="text-sm text-indigo-300 animate-pulse">{status}</p>
      )}

      <div className="flex gap-3 shrink-0">
        <Button onClick={handleAnalyze} disabled={loading || !value.trim()} size="lg">
          <Play className="h-4 w-4" />
          {loading ? "Analyzing..." : "Analyze"}
        </Button>
        {loading && (
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
        )}
      </div>
    </div>
  );
}
