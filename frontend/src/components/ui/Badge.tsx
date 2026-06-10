import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";
import { SEVERITY_COLORS } from "@/lib/types";

interface BadgeProps {
  severity?: Severity;
  children: React.ReactNode;
  className?: string;
}

export function Badge({ severity, children, className }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium uppercase tracking-wide",
        severity ? SEVERITY_COLORS[severity] : "bg-slate-700/50 text-slate-300 border-slate-600",
        className
      )}
    >
      {children}
    </span>
  );
}
