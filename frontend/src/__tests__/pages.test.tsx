import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import Audit from "../pages/Audit";
import People from "../pages/People";
import PublicLink from "../pages/PublicLink";
import Security from "../pages/Security";
import { mockApi, renderApp } from "./helpers";

const admin = {
  id: "a1", email: "admin@demo.td", name: "Amina", role: "admin", status: "active",
  mfa_enabled: true, google_linked: false, created_at: "2026-11-01T00:00:00.000000Z", session_mfa: true,
};

describe("security overview", () => {
  it("lists open alerts with their reasons and resolves one", async () => {
    let status = "open";
    const calls = mockApi((url) => {
      if (url === "/api/auth/me") return { body: admin };
      if (url.startsWith("/api/admin/summary"))
        return {
          body: {
            days: ["2026-11-25", "2026-11-26"],
            series: { logins: [3, 4], failed_logins: [0, 7], uploads: [1, 0], downloads: [2, 30] },
            totals: { events: 50, failed_logins: 7, external_downloads: 1, open_alerts: status === "open" ? 1 : 0, high_alerts: 1 },
            top_users: [["idriss@demo.td", 33]],
            countries: [["TD", 40], ["BR", 10]],
            alerts_by_rule: [["impossible_travel", 1]],
          },
        };
      if (url === "/api/admin/alerts")
        return {
          body: [{
            id: "al1", at: "2026-11-26T10:00:00.000000Z", rule: "impossible_travel", severity: "high",
            title: "Logins from two countries too close together", status, subject: "u1",
            reason: "idriss@demo.td signed in from TD and then from BR 35 minutes later.",
          }],
        };
      if (url === "/api/admin/alerts/al1/resolve") {
        status = "resolved";
        return { body: {} };
      }
    });
    renderApp(<Security />);
    expect(await screen.findByText(/from TD and then from BR 35 minutes later/)).toBeInTheDocument();
    expect(screen.getByText("Open alerts").previousSibling).toHaveTextContent("1");
    expect(screen.getByText("BR")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Mark as resolved" }));
    expect(await screen.findByText(/No open alerts/)).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST" && c.url === "/api/admin/alerts/al1/resolve")).toBe(true);
  });
});

describe("people", () => {
  it("invites someone and shows the one-time link; cannot demote yourself", async () => {
    const calls = mockApi((url, init) => {
      if (url === "/api/auth/me") return { body: admin };
      if (url === "/api/admin/users" && init?.method === "POST")
        return { status: 201, body: { invite_url: "https://share.example/invite/tok" } };
      if (url === "/api/admin/users") return { body: [admin] };
    });
    renderApp(<People />);
    const user = userEvent.setup();
    const row = (await screen.findByText("admin@demo.td")).closest("tr")!;
    expect(within(row).getByRole("combobox")).toBeDisabled();
    await user.type(screen.getByLabelText("Email"), "zara@demo.td");
    await user.type(screen.getByLabelText("Name"), "Zara");
    await user.selectOptions(screen.getByLabelText("Role"), "viewer");
    await user.click(screen.getByRole("button", { name: "Create invite" }));
    expect(await screen.findByDisplayValue("https://share.example/invite/tok")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ email: "zara@demo.td", name: "Zara", role: "viewer" });
  });
});

describe("activity log", () => {
  it("shows events in plain words and passes filters to the API", async () => {
    const calls = mockApi((url) => {
      if (url === "/api/auth/me") return { body: admin };
      if (url.startsWith("/api/admin/audit"))
        return {
          body: {
            day: "2026-11-26",
            events: [
              { id: "e1", at: "2026-11-26T09:00:00.000000Z", action: "link.download", outcome: "success", actor_id: null,
                actor_email: null, ip: "102.1.1.1", country: "TD", target_type: "link", target_id: "l1", details: null },
              { id: "e2", at: "2026-11-26T09:05:00.000000Z", action: "auth.login", outcome: "failure", actor_id: null,
                actor_email: null, ip: "185.1.1.1", country: "RU", target_type: null, target_id: null, details: { email: "halime@demo.td" } },
            ],
          },
        };
    });
    renderApp(<Audit />);
    expect(await screen.findByText("Downloaded through a link")).toBeInTheDocument();
    expect(screen.getByText("halime@demo.td")).toBeInTheDocument();
    expect(screen.getAllByText("Outside visitor")).toHaveLength(2);
    await userEvent.setup().selectOptions(screen.getByLabelText("Result"), "failure");
    expect(calls.some((c) => c.url.includes("outcome=failure"))).toBe(true);
  });
});

describe("public link page", () => {
  it("asks for the password and reports a wrong one", async () => {
    mockApi((url) => {
      if (url === "/api/auth/me") return { status: 401, body: {} };
      if (url === "/api/public/links/tok")
        return { body: { file_name: "Contrat.pdf", size: 2048, expires_at: "2099-01-01T00:00:00.000000Z", password_required: true, downloads_remaining: 2 } };
      if (url === "/api/public/links/tok/download") return { status: 401, body: { detail: "Wrong password" } };
    });
    renderApp(
      <Routes>
        <Route path="/s/:token" element={<PublicLink />} />
      </Routes>,
      { route: "/s/tok", lang: "fr" },
    );
    expect(await screen.findByText("Contrat.pdf")).toBeInTheDocument();
    expect(screen.getByText(/Téléchargements restants: 2/)).toBeInTheDocument();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/Ce fichier est protégé/), "guess");
    await user.click(screen.getByRole("button", { name: "Télécharger" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Wrong password");
  });

  it("explains when a link is gone", async () => {
    mockApi((url) => {
      if (url === "/api/auth/me") return { status: 401, body: {} };
      if (url === "/api/public/links/old") return { status: 410, body: { detail: "This link is no longer available" } };
    });
    renderApp(
      <Routes>
        <Route path="/s/:token" element={<PublicLink />} />
      </Routes>,
      { route: "/s/old" },
    );
    expect(await screen.findByText(/Ask the sender for a new one/)).toBeInTheDocument();
  });
});
