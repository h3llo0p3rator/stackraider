import { useState } from "react";
import { ChevronDown, ChevronRight, Database, Zap } from "lucide-react";
import { Card } from "./ui/Card";
import type { ParsedSchema, SchemaField, SchemaType } from "@/lib/types";
import { cn } from "@/lib/utils";

function FieldDetail({ field }: { field: SchemaField }) {
  return (
    <div className="text-xs space-y-1 text-slate-400">
      <p>
        <span className="text-slate-300">{field.name}</span>
        {": "}
        <span className="font-mono text-indigo-300">
          {field.is_list ? "[" : ""}
          {field.type_name}
          {field.is_list ? "]" : ""}
          {field.is_required ? "!" : ""}
        </span>
      </p>
      {field.is_deprecated && (
        <p className="text-yellow-500/80">Deprecated: {field.deprecation_reason}</p>
      )}
      {field.args.length > 0 && (
        <p className="font-mono text-slate-500">
          args: {field.args.map((a) => `${a.name}: ${a.type_name}`).join(", ")}
        </p>
      )}
    </div>
  );
}

function TypeNode({ type, depth = 0 }: { type: SchemaType; depth?: number }) {
  const [open, setOpen] = useState(depth < 1);

  return (
    <div className="ml-2">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1 text-sm text-slate-300 hover:text-white py-0.5 w-full text-left"
      >
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        <span className="font-mono text-indigo-300">{type.name}</span>
        <span className="text-slate-600 text-xs">({type.kind})</span>
      </button>
      {open && type.fields.length > 0 && (
        <div className="ml-5 border-l border-slate-700 pl-3 space-y-2 py-1">
          {type.fields.map((f) => (
            <FieldDetail key={f.name} field={f} />
          ))}
        </div>
      )}
      {open && type.enum_values.length > 0 && (
        <div className="ml-5 text-xs text-slate-500 font-mono">
          {type.enum_values.join(" | ")}
        </div>
      )}
    </div>
  );
}

function OpList({ title, ops, icon: Icon }: { title: string; ops: SchemaField[]; icon: React.ElementType }) {
  const [open, setOpen] = useState(true);
  if (!ops.length) return null;

  return (
    <Card className="p-3">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 w-full text-left"
      >
        {open ? <ChevronDown className="h-4 w-4 text-slate-500" /> : <ChevronRight className="h-4 w-4" />}
        <Icon className="h-4 w-4 text-indigo-400" />
        <span className="font-medium text-white">{title}</span>
        <span className="text-xs text-slate-500 ml-auto">{ops.length}</span>
      </button>
      {open && (
        <div className="mt-3 space-y-3 max-h-64 overflow-y-auto">
          {ops.map((op) => (
            <div key={op.name} className="border-l-2 border-indigo-500/40 pl-3">
              <FieldDetail field={op} />
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

export function SchemaExplorer({ schema }: { schema: ParsedSchema | null }) {
  const [filter, setFilter] = useState("");
  const [tab, setTab] = useState<"ops" | "types">("ops");

  if (!schema) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-500 p-8">
        <Database className="h-12 w-12 mb-4 opacity-40" />
        <p>Run an analysis to explore the schema</p>
      </div>
    );
  }

  const filteredTypes = schema.types.filter((t) =>
    t.name.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="flex flex-col h-full p-6 gap-4 overflow-hidden">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-white">Schema Explorer</h2>
          <p className="text-slate-400 text-sm">
            {schema.type_count} types · {schema.query_count} queries · {schema.mutation_count} mutations
          </p>
        </div>
        <div className="flex gap-2">
          {(["ops", "types"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                "px-3 py-1.5 rounded-lg text-sm capitalize",
                tab === t ? "bg-indigo-500/20 text-indigo-300" : "text-slate-400 hover:bg-slate-800"
              )}
            >
              {t === "ops" ? "Operations" : "Types"}
            </button>
          ))}
        </div>
      </div>

      {schema.circular_references.length > 0 && (
        <Card className="border-yellow-500/30 bg-yellow-500/5">
          <p className="text-sm text-yellow-400">
            <Zap className="inline h-4 w-4 mr-1" />
            {schema.circular_references.length} circular reference(s) detected — DoS risk
          </p>
        </Card>
      )}

      {tab === "ops" ? (
        <div className="grid gap-4 md:grid-cols-2 overflow-y-auto">
          <OpList title="Queries" ops={schema.queries} icon={Database} />
          <OpList title="Mutations" ops={schema.mutations} icon={Zap} />
        </div>
      ) : (
        <>
          <input
            type="text"
            placeholder="Filter types..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="w-full max-w-md px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
          />
          <div className="flex-1 overflow-y-auto space-y-1">
            {filteredTypes.map((t) => (
              <TypeNode key={t.name} type={t} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}
