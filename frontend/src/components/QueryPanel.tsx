import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import Editor from "@monaco-editor/react";
import { Check, Copy, Download, Terminal } from "lucide-react";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import type { GeneratedQuery } from "@/lib/types";

export function QueryPanel({
  queries,
  streaming = false,
}: {
  queries: GeneratedQuery[];
  streaming?: boolean;
}) {
  const [searchParams] = useSearchParams();
  const highlightId = searchParams.get("q");
  const [selected, setSelected] = useState(0);
  const [copied, setCopied] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!highlightId || !queries.length) return;
    const idx = queries.findIndex((q) => q.id === highlightId);
    if (idx >= 0) setSelected(idx);
  }, [highlightId, queries]);

  useEffect(() => {
    if (!highlightId || !listRef.current) return;
    const el = listRef.current.querySelector(`[data-query-id="${highlightId}"]`);
    el?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [highlightId, selected, queries]);

  if (!queries.length) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-500 p-8">
        <Terminal className="h-12 w-12 mb-4 opacity-40" />
        <p>
          {streaming
            ? "Test queries will stream in here as findings are discovered…"
            : "Generated test queries will appear here after analysis"}
        </p>
      </div>
    );
  }

  const current = queries[selected] ?? queries[0];

  const copyQuery = async () => {
    await navigator.clipboard.writeText(current.query);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const exportAll = () => {
    const content = queries
      .map(
        (q) =>
          `# ${q.title}\n# ${q.vulnerability}\n# Expected: ${q.expected_behavior}\n\n${q.query}\n`
      )
      .join("\n---\n\n");
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "graphraider-queries.graphql";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex h-full overflow-hidden">
      <div
        ref={listRef}
        className="w-72 border-r border-[var(--color-border)] overflow-y-auto p-3 space-y-1"
      >
        <div className="flex items-center justify-between px-2 py-2">
          <span className="text-xs text-slate-500 uppercase">
            {queries.length} queries
            {streaming && (
              <span className="ml-1 text-indigo-400 normal-case">· streaming</span>
            )}
          </span>
          <Button variant="ghost" size="sm" onClick={exportAll}>
            <Download className="h-3 w-3" />
            Export
          </Button>
        </div>
        {queries.map((q, i) => (
          <button
            key={q.id}
            data-query-id={q.id}
            onClick={() => setSelected(i)}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
              i === selected
                ? "bg-indigo-500/15 text-indigo-200 border border-indigo-500/30"
                : highlightId === q.id
                  ? "bg-indigo-500/10 text-indigo-300 border border-indigo-500/20"
                  : "text-slate-400 hover:bg-slate-800/50"
            }`}
          >
            <p className="truncate font-medium">{q.title}</p>
            <Badge severity={q.severity} className="mt-1 text-[10px]">
              {q.severity}
            </Badge>
          </button>
        ))}
      </div>

      <div className="flex-1 flex flex-col p-4 gap-3 overflow-hidden">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-white">{current.title}</h2>
            <p className="text-sm text-slate-400 mt-1">{current.vulnerability}</p>
            <p className="text-xs text-slate-500 mt-1">
              Expected: {current.expected_behavior}
            </p>
          </div>
          <Button variant="secondary" size="sm" onClick={copyQuery}>
            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>

        <Card className="flex-1 min-h-0 p-0 overflow-hidden">
          <Editor
            height="100%"
            language="graphql"
            theme="vs-dark"
            value={current.query}
            options={{
              readOnly: true,
              minimap: { enabled: false },
              fontSize: 13,
              fontFamily: "JetBrains Mono, monospace",
              wordWrap: "on",
            }}
          />
        </Card>
      </div>
    </div>
  );
}
