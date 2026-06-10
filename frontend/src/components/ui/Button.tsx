import { cn } from "@/lib/utils";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "sm" | "md" | "lg";
}

export function Button({
  variant = "primary",
  size = "md",
  className,
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-all disabled:opacity-50 disabled:pointer-events-none",
        size === "sm" && "px-3 py-1.5 text-sm",
        size === "md" && "px-4 py-2 text-sm",
        size === "lg" && "px-6 py-3 text-base",
        variant === "primary" &&
          "bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-500/25",
        variant === "secondary" &&
          "bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-600",
        variant === "ghost" && "hover:bg-slate-800 text-slate-300",
        variant === "danger" && "bg-red-600/80 hover:bg-red-600 text-white",
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}
