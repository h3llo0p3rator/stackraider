import { useEffect, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import { RotateCcw, Send, X } from "lucide-react";
import { Button } from "./ui/Button";
import { createChatSocket } from "@/lib/api";
import type { AppSettings, Finding, GeneratedQuery, ParsedSchema } from "@/lib/types";

interface Message {
  role: "user" | "assistant";
  content: string;
}

const SUGGESTIONS = [
  "Summarise the riskiest findings",
  "Generate a PoC script for IDOR tests",
  "Explain the circular reference DoS risk",
  "What mutations should I test first?",
];

interface ChatPanelProps {
  open: boolean;
  onClose: () => void;
  settings: AppSettings;
  schema: ParsedSchema | null;
  findings: Finding[];
  queries: GeneratedQuery[];
}

export function ChatPanel({
  open,
  onClose,
  settings,
  schema,
  findings,
  queries,
}: ChatPanelProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    return () => wsRef.current?.close();
  }, []);

  const send = (text: string) => {
    if (!text.trim() || streaming) return;

    const userMsg: Message = { role: "user", content: text.trim() };
    const history = [...messages, userMsg];
    setMessages([...history, { role: "assistant", content: "" }]);
    setInput("");
    setStreaming(true);

    wsRef.current?.close();
    const ws = createChatSocket((msg) => {
      if (msg.type === "token") {
        setMessages((prev) => {
          const next = [...prev];
          const last = next[next.length - 1];
          if (last?.role === "assistant") {
            last.content += msg.content as string;
          }
          return next;
        });
      }
      if (msg.type === "done" || msg.type === "error") {
        setStreaming(false);
        if (msg.type === "error") {
          setMessages((prev) => {
            const next = [...prev];
            const last = next[next.length - 1];
            if (last?.role === "assistant") {
              last.content = `Error: ${msg.content}`;
            }
            return next;
          });
        }
      }
    });
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(
        JSON.stringify({
          messages: history.map((m) => ({ role: m.role, content: m.content })),
          model: settings.model,
          ollama_host: settings.ollamaHost,
          schema: schema ?? undefined,
          findings: findings.length ? findings : undefined,
          queries: queries.length ? queries : undefined,
        })
      );
    };
  };

  const newChat = () => {
    setMessages([]);
    wsRef.current?.close();
    setStreaming(false);
  };

  if (!open) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-md flex flex-col glass border-l border-[var(--color-border)] shadow-2xl">
      <div className="flex items-center justify-between p-4 border-b border-[var(--color-border)]">
        <div>
          <h3 className="font-semibold text-white">Security Chat</h3>
          {schema && (
            <p className="text-xs text-indigo-400 mt-0.5">
              Schema: {schema.type_count} types, {schema.query_count} queries,{" "}
              {schema.mutation_count} mutations
            </p>
          )}
        </div>
        <div className="flex gap-1">
          <Button variant="ghost" size="sm" onClick={newChat} title="New chat">
            <RotateCcw className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="sm" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 && (
          <div className="space-y-3">
            <p className="text-sm text-slate-500">
              Brainstorm attack ideas, refine payloads, or ask for remediation advice.
            </p>
            <div className="flex flex-wrap gap-2">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => send(s)}
                  className="text-xs px-3 py-1.5 rounded-full bg-slate-800 text-slate-300 hover:bg-indigo-500/20 hover:text-indigo-300 border border-slate-700"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((m, i) => (
          <div
            key={i}
            className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}
          >
            <div
              className={`max-w-[90%] rounded-xl px-3 py-2 text-sm ${
                m.role === "user"
                  ? "bg-indigo-600 text-white"
                  : "bg-slate-800 text-slate-200"
              }`}
            >
              {m.role === "assistant" ? (
                <div className="prose prose-invert prose-sm max-w-none">
                  <ReactMarkdown>{m.content || (streaming && i === messages.length - 1 ? "..." : "")}</ReactMarkdown>
                </div>
              ) : (
                m.content
              )}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      <div className="p-4 border-t border-[var(--color-border)] flex gap-2">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && send(input)}
          placeholder="Ask about vulnerabilities..."
          disabled={streaming}
          className="flex-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
        />
        <Button onClick={() => send(input)} disabled={streaming || !input.trim()}>
          <Send className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
