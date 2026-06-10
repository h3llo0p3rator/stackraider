import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { useCodeSession } from "@/context/CodeSessionContext";

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-300",
  HIGH: "bg-orange-500/20 text-orange-300",
  MEDIUM: "bg-yellow-500/20 text-yellow-300",
  LOW: "bg-blue-500/20 text-blue-300",
  INFO: "bg-slate-500/20 text-slate-300",
};

export function ResultsPage() {
  const { scanResult } = useCodeSession();
  if (!scanResult) {
    return (
      <div className="p-6 text-slate-400">Run a scan first from the Code → Scan tab.</div>
    );
  }

  return (
    <div className="p-6 space-y-4 overflow-y-auto h-full">
      <Card className="p-4">
        <h2 className="text-lg font-semibold mb-2">Scan Summary</h2>
        <p className="text-sm text-slate-400">{scanResult.target_path}</p>
        <p className="text-2xl font-bold mt-2">{scanResult.total_findings} findings</p>
        <div className="flex flex-wrap gap-2 mt-3">
          {Object.entries(scanResult.findings_by_severity || {}).map(([sev, n]) => (
            <Badge key={sev} className={SEV_COLORS[sev] || ""}>{sev}: {n}</Badge>
          ))}
        </div>
      </Card>
      <div className="space-y-2">
        {scanResult.findings.slice(0, 100).map((f, i) => (
          <Card key={i} className="p-3 text-sm">
            <div className="flex gap-2 items-start">
              <Badge className={SEV_COLORS[String(f.severity)] || ""}>{String(f.severity)}</Badge>
              <span className="font-mono text-indigo-300">{String(f.rule_id)}</span>
            </div>
            <p className="text-slate-300 mt-1">{String(f.rule_name)}</p>
            <p className="text-slate-500 text-xs mt-1">{String(f.file_path)}:{String(f.line_number)}</p>
          </Card>
        ))}
      </div>
    </div>
  );
}
