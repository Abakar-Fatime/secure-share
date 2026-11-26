import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import App from "../App";
import ShareDrawer from "../components/ShareDrawer";
import Ticket from "../components/Ticket";
import type { FileItem, Link } from "../lib/api";
import { formatBytes, relative, fileKind } from "../lib/format";
import { I18nProvider } from "../lib/i18n";
import { mockApi, renderApp } from "./helpers";

const member = {
  id: "u1", email: "idriss@demo.td", name: "Idriss", role: "member", status: "active",
  mfa_enabled: false, google_linked: false, created_at: "2026-11-01T00:00:00.000000Z", session_mfa: false,
};
const file: FileItem = {
  id: "f1", name: "Budget_2027.xlsx", size: 52_000, content_type: "application/octet-stream",
  status: "ready", owner_id: "u1", created_at: "2026-11-20T09:00:00.000000Z", is_owner: true,
};

describe("format helpers", () => {
  it("formats sizes and kinds", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(52 * 1024 * 1024)).toBe("52 MB");
    expect(fileKind("a.PDF")).toBe("pdf");
    expect(fileKind("photos.zip")).toBe("archive");
  });
  it("formats relative times in both languages", () => {
    const now = Date.parse("2026-11-26T10:00:00Z");
    expect(relative("2026-11-26T13:00:00Z", "en", now)).toBe("in 3 hours");
    expect(relative("2026-11-24T10:00:00Z", "fr", now)).toBe("avant-hier");
  });
});

describe("sign-in", () => {
  it("asks for the two-step code after the password, then lands on files", async () => {
    let signedIn = false;
    const calls = mockApi((url) => {
      if (url === "/api/auth/me") return signedIn ? { body: member } : { status: 401, body: { detail: "Not signed in" } };
      if (url === "/api/auth/config") return { body: { google_enabled: false } };
      if (url === "/api/auth/login") return { body: { mfa_required: true } };
      if (url === "/api/auth/mfa/verify") {
        signedIn = true;
        return { body: { user: member } };
      }
      if (url === "/api/files") return { body: { owned: [file], shared_with_me: [] } };
    });
    renderApp(<App />, { route: "/login" });
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Email"), "idriss@demo.td");
    await user.type(screen.getByLabelText("Password"), "Demo-Password-2026");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Two-step verification")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Code"), "123456");
    await user.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByText("Budget_2027.xlsx")).toBeInTheDocument();
    const login = calls.find((c) => c.url === "/api/auth/login");
    expect(login?.body).toEqual({ email: "idriss@demo.td", password: "Demo-Password-2026" });
  });

  it("shows the server's error message", async () => {
    mockApi((url) => {
      if (url === "/api/auth/me") return { status: 401, body: { detail: "Not signed in" } };
      if (url === "/api/auth/config") return { body: { google_enabled: true } };
      if (url === "/api/auth/login") return { status: 401, body: { detail: "Email or password is incorrect" } };
    });
    renderApp(<App />, { route: "/login" });
    const user = userEvent.setup();
    expect(await screen.findByRole("link", { name: /Sign in with Google/ })).toHaveAttribute("href", "/api/auth/google/login");
    await user.type(screen.getByLabelText("Email"), "a@b.td");
    await user.type(screen.getByLabelText("Password"), "x");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Email or password is incorrect");
  });

  it("explains Google sign-in errors in French", async () => {
    mockApi((url) => {
      if (url === "/api/auth/me") return { status: 401, body: {} };
      if (url === "/api/auth/config") return { body: { google_enabled: true } };
    });
    renderApp(<App />, { route: "/login?error=sso_no_account", lang: "fr" });
    expect(await screen.findByRole("alert")).toHaveTextContent("Demandez une invitation");
  });
});

describe("sharing", () => {
  it("sends the CSRF token and shows a new link exactly once", async () => {
    const created: Link = {
      id: "l1", file_id: "f1", expires_at: "2026-11-27T09:00:00.000000Z", max_downloads: 3, download_count: 0,
      password_protected: true, state: "active", created_at: "2026-11-26T09:00:00.000000Z",
      url: "https://share.example/s/secret-token",
    };
    let links: Link[] = [];
    const calls = mockApi((url, init) => {
      if (url === "/api/auth/me") return { body: member };
      if (url === "/api/files/f1/grants") return { body: [] };
      if (url === "/api/files/f1/links" && init?.method === "POST") {
        links = [created];
        return { status: 201, body: created };
      }
      if (url === "/api/files/f1/links") return { body: links };
    });
    renderApp(<ShareDrawer file={file} onClose={() => undefined} />);
    const user = userEvent.setup();
    await screen.findByText("No links yet.");
    await user.type(screen.getByLabelText("Download limit"), "3");
    await user.type(screen.getByLabelText("Password (optional)"), "tchad2026");
    await user.click(screen.getByRole("button", { name: "Create link" }));
    expect(await screen.findByDisplayValue("https://share.example/s/secret-token")).toBeInTheDocument();
    expect(await screen.findByText("0")).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST" && c.url === "/api/files/f1/links");
    expect(post?.body).toEqual({ expires_in_hours: 24, max_downloads: 3, password: "tchad2026" });
    const fetchMock = fetch as unknown as { mock: { calls: [string, RequestInit][] } };
    const postInit = fetchMock.mock.calls.find(([u, i]) => u === "/api/files/f1/links" && i?.method === "POST")?.[1];
    expect((postInit?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("test-token");
  });

  it("punches one hole per download on the ticket", () => {
    const link: Link = {
      id: "l1", file_id: "f1", expires_at: "2020-01-01T00:00:00.000000Z", max_downloads: 4, download_count: 4,
      password_protected: false, state: "used_up", created_at: "2019-12-31T00:00:00.000000Z",
    };
    const { container } = render(
      <I18nProvider lang="en">
        <Ticket link={link} />
      </I18nProvider>,
    );
    expect(container.querySelectorAll(".punches i.used")).toHaveLength(4);
    expect(screen.getByText("Used up")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
  });
});

describe("access control in the UI", () => {
  it("asks admins without two-step verification to turn it on", async () => {
    mockApi((url) => {
      if (url === "/api/auth/me") return { body: { ...member, role: "admin" } };
    });
    renderApp(
      <Routes>
        <Route path="*" element={<App />} />
      </Routes>,
      { route: "/admin/security" },
    );
    expect(await screen.findByText("Admins must use two-step verification to open admin pages.")).toBeInTheDocument();
  });

  it("sends signed-out visitors to the sign-in page", async () => {
    mockApi((url) => {
      if (url === "/api/auth/me") return { status: 401, body: {} };
      if (url === "/api/auth/config") return { body: { google_enabled: false } };
    });
    renderApp(<App />, { route: "/files" });
    await waitFor(() => expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument());
  });
});
