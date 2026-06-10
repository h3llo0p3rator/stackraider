import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { useCodeSession } from "@/context/CodeSessionContext";
import { exportSession } from "@/lib/codeApi";

export function CorrelationPage() {
  const { session } = useCodeSession();
  const [exporting, setExporting] = useState(false);

  const correlations = session?.correlations ?? [];

  const handleExport = async () => {
    setExporting(true);
    try {
      const data = await exportSession();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "stackraider-session-export.json";
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="p-6 max-w-3xl space-y-4">
      <Card className="p-4">
        <h2 className="font-semibold mb-2">Cross-Module Correlation</h2>
        <p className="text-sm text-slate-400 mb-4">
          Links code GraphQL rule hits (GQL-*) to GraphQL schema findings from introspection analysis.
        </p>
        <div className="flex gap-4 text-sm mb-4">
          <span>Scan: {session?.scan_findings ?? 0} findings</span>
          <span>Burp: {session?.burp_summary?.total ?? 0} reqs</span>
          <span>GraphQL: {session?.graphql_findings_count ?? 0} findings</span>
        </div>
        <Button onClick={handleExport} disabled={exporting}>
          {exporting ? "Exporting..." : "Export session bundle (JSON)"}
        </Button>
      </Card>
      {correlations.length === 0 ? (
        <p className="text-slate-500 text-sm">Load a code scan and GraphQL introspection to see correlations.</p>
      ) : (
        correlations.map((link, i) => (
          <Card key={i} className="p-3 text-sm">
            <p className="font-mono text-indigo-300">{String(link.code_rule)} @ {String(link.code_file)}:{String(link.code_line)}</p>
            <ul className="mt-2 text-slate-400">
              {(link.graphql_findings as Array<Record<string, string>>)?.map((g, j) => (
                <li key={j}>→ [{g.severity}] {g.title}</li>
              )) || <li>No matching GraphQL findings</li>}
            </ul>
          </Card>
        ))
      )}
    </div>
  );
}
