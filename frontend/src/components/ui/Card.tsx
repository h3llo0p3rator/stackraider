import { cn } from "@/lib/utils";

export function Card({
  className,
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "glass rounded-xl p-4 transition-colors hover:border-slate-600/80",
        className
      )}
    >
      {children}
    </div>
  );
}
