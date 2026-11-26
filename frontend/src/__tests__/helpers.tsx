import { render } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { ToastProvider } from "../components/ui";
import { AuthProvider } from "../lib/auth";
import { I18nProvider, type Lang } from "../lib/i18n";

type Handler = (url: string, init?: RequestInit) => { status?: number; body?: unknown } | undefined;

/** Replace fetch with a tiny router: handlers return { status, body } for matching URLs. */
export function mockApi(handler: Handler) {
  const calls: { url: string; method: string; body: unknown }[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : undefined });
    if (url === "/api/health") document.cookie = "ss_csrf=test-token";
    const r = handler(url, init) ?? (url === "/api/health" ? { body: { status: "ok" } } : { status: 404, body: { detail: "Not found" } });
    return new Response(JSON.stringify(r.body ?? null), { status: r.status ?? 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}

export function renderApp(ui: ReactNode, { route = "/", lang = "en" as Lang } = {}) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <I18nProvider lang={lang}>
        <AuthProvider>
          <ToastProvider>{ui}</ToastProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}
