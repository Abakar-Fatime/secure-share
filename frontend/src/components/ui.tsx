import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { fileKind } from "../lib/format";

export function LockIcon({ size = 22, className }: { size?: number; className?: string }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="7" fill="#9FD8C6" fillOpacity="0.16" />
      <path d="M10 14v-3a6 6 0 0 1 12 0v3" fill="none" stroke="#9FD8C6" strokeWidth="2.4" />
      <rect x="8" y="14" width="16" height="11" rx="2" fill="#9FD8C6" />
      <circle cx="16" cy="19.5" r="1.8" fill="#18213B" />
    </svg>
  );
}

const KIND_LABEL: Record<string, string> = {
  pdf: "PDF", doc: "DOC", sheet: "XLS", slides: "PPT", image: "IMG", archive: "ZIP", file: "",
};

export function FileBadge({ name }: { name: string }) {
  const kind = fileKind(name);
  return (
    <span className={`kind ${kind}`} aria-hidden="true">
      {KIND_LABEL[kind]}
    </span>
  );
}

export function ErrorText({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <p className="error" role="alert">
      {error}
    </p>
  );
}

export function useAsync<T>(load: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const run = useCallback(async () => {
    setLoading(true);
    try {
      setData(await load());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => {
    run();
  }, [run]);
  return { data, error, loading, reload: run, setData };
}

const ToastCtx = createContext<(msg: string) => void>(() => undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    if (!msg) return;
    const id = setTimeout(() => setMsg(null), 2600);
    return () => clearTimeout(id);
  }, [msg]);
  return (
    <ToastCtx.Provider value={setMsg}>
      {children}
      <div aria-live="polite">{msg && <div className="toast">{msg}</div>}</div>
    </ToastCtx.Provider>
  );
}

export const useToast = () => useContext(ToastCtx);

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
