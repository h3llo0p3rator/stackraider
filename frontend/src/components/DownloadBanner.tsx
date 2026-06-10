import { Download } from "lucide-react";
import { Link } from "react-router-dom";
import { useModelDownloadContext } from "@/context/ModelDownloadContext";

export function DownloadBanner() {
  const { activeJobs } = useModelDownloadContext();
  if (!activeJobs.length) return null;

  return (
    <div className="border-b border-indigo-500/30 bg-indigo-500/10 px-4 py-2">
      <div className="flex flex-wrap items-center gap-4">
        {activeJobs.map((job) => (
          <div key={job.id} className="flex items-center gap-3 min-w-[200px] flex-1 max-w-md">
            <Download className="h-4 w-4 text-indigo-400 animate-pulse shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2 text-xs">
                <span className="font-mono text-indigo-200 truncate">{job.name}</span>
                <span className="text-slate-400 shrink-0">
                  {job.percent != null ? `${job.percent.toFixed(0)}%` : job.status}
                </span>
              </div>
              <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden mt-1">
                <div
                  className="h-full bg-gradient-to-r from-indigo-500 to-violet-500 transition-all duration-300"
                  style={{ width: `${job.percent ?? 5}%` }}
                />
              </div>
            </div>
          </div>
        ))}
        <Link
          to="/models"
          className="text-xs text-indigo-400 hover:text-indigo-300 shrink-0"
        >
          View in Models →
        </Link>
      </div>
    </div>
  );
}
