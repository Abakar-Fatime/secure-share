import { useState, type FormEvent } from "react";
import { copyText, ErrorText, useAsync, useToast } from "../components/ui";
import { api, type Role, type User } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDate } from "../lib/format";
import { useI18n, type TKey } from "../lib/i18n";

const STATUS_KEY: Record<User["status"], TKey> = { active: "statusActive", invited: "statusInvited", disabled: "statusDisabled" };

export default function People() {
  const { t, lang } = useI18n();
  const toast = useToast();
  const { user: me } = useAuth();
  const people = useAsync(() => api<User[]>("/admin/users"), []);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [inviteUrl, setInviteUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function invite(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const r = await api<{ invite_url: string }>("/admin/users", { method: "POST", body: { email, name, role } });
      setInviteUrl(r.invite_url);
      setEmail("");
      setName("");
      people.reload();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function update(id: string, body: Record<string, unknown>) {
    try {
      await api(`/admin/users/${id}`, { method: "PATCH", body });
      toast(t("saved"));
      people.reload();
    } catch (e) {
      toast((e as Error).message);
    }
  }

  async function resend(id: string) {
    const r = await api<{ invite_url: string }>(`/admin/users/${id}/invite`, { method: "POST" });
    setInviteUrl(r.invite_url);
  }

  return (
    <>
      <div className="page-head">
        <h1>{t("peopleTitle")}</h1>
      </div>
      <div className="sheet section stack" style={{ marginBottom: 20 }}>
        <h2>{t("invite")}</h2>
        <form className="row" style={{ alignItems: "end" }} onSubmit={invite}>
          <label style={{ flex: "2 1 220px" }}>
            {t("email")}
            <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label style={{ flex: "2 1 180px" }}>
            {t("name")}
            <input required value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label style={{ flex: "1 1 120px" }}>
            {t("role")}
            <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
              <option value="member">{t("roleMember")}</option>
              <option value="viewer">{t("roleViewer")}</option>
              <option value="admin">{t("roleAdmin")}</option>
            </select>
          </label>
          <button className="btn seal">{t("inviteSend")}</button>
        </form>
        <ErrorText error={error} />
        {inviteUrl && (
          <div className="stack" style={{ gap: 6 }}>
            <p className="notice">{t("inviteLinkReady")}</p>
            <div className="fresh-link">
              <input readOnly value={inviteUrl} aria-label="Invite link" onFocus={(e) => e.target.select()} />
              <button className="btn" onClick={async () => toast((await copyText(inviteUrl)) ? t("copied") : inviteUrl)}>
                {t("copy")}
              </button>
            </div>
          </div>
        )}
      </div>
      <ErrorText error={people.error} />
      <div className="sheet">
        <table className="table">
          <thead>
            <tr>
              <th>{t("name")}</th>
              <th>{t("role")}</th>
              <th>{t("status")}</th>
              <th className="hide-sm">{t("lastSignIn")}</th>
              <th className="actions">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {people.data?.map((p) => {
              const self = p.id === me?.id;
              return (
                <tr key={p.id}>
                  <td>
                    <strong>{p.name}</strong>
                    <div className="small muted">{p.email}</div>
                  </td>
                  <td>
                    <select
                      aria-label={`${t("role")} ${p.name}`}
                      value={p.role}
                      disabled={self}
                      onChange={(e) => update(p.id, { role: e.target.value })}
                    >
                      <option value="admin">{t("roleAdmin")}</option>
                      <option value="member">{t("roleMember")}</option>
                      <option value="viewer">{t("roleViewer")}</option>
                    </select>
                  </td>
                  <td>
                    <span className={`pill ${p.status === "active" ? "ok" : p.status === "disabled" ? "bad" : "warn"}`}>
                      {t(STATUS_KEY[p.status])}
                    </span>{" "}
                    {p.mfa_enabled && <span className="pill">2FA</span>}
                  </td>
                  <td className="hide-sm muted">{p.last_login_at ? formatDate(p.last_login_at, lang) : t("never")}</td>
                  <td className="actions">
                    <div className="row" style={{ justifyContent: "end" }}>
                      {p.status === "invited" && (
                        <button className="btn ghost small" onClick={() => resend(p.id)}>
                          {t("newInviteLink")}
                        </button>
                      )}
                      {p.mfa_enabled && !self && (
                        <button className="btn ghost small" onClick={() => update(p.id, { reset_mfa: true })}>
                          {t("resetMfa")}
                        </button>
                      )}
                      {!self && p.status === "active" && (
                        <button className="btn danger small" onClick={() => update(p.id, { status: "disabled" })}>
                          {t("disable")}
                        </button>
                      )}
                      {p.status === "disabled" && (
                        <button className="btn ghost small" onClick={() => update(p.id, { status: "active" })}>
                          {t("enable")}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}
