import QRCode from "qrcode";
import { useState, type FormEvent } from "react";
import { ErrorText, useAsync, useToast } from "../components/ui";
import { api, type AuditEvent } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDate } from "../lib/format";
import { useI18n, type TKey } from "../lib/i18n";

const ROLE_KEY: Record<string, TKey> = { admin: "roleAdmin", member: "roleMember", viewer: "roleViewer" };

function MfaSection() {
  const { t } = useI18n();
  const { user, refresh } = useAuth();
  const toast = useToast();
  const [setup, setSetup] = useState<{ secret: string; qr: string } | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [disabling, setDisabling] = useState(false);

  async function begin() {
    setError(null);
    try {
      const r = await api<{ secret: string; otpauth_uri: string }>("/auth/mfa/setup", { method: "POST" });
      setSetup({ secret: r.secret, qr: await QRCode.toDataURL(r.otpauth_uri, { margin: 1, width: 184 }) });
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function confirm(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api(disabling ? "/auth/mfa/disable" : "/auth/mfa/enable", { method: "POST", body: { code } });
      toast(disabling ? t("mfaDisabled") : t("mfaEnabled"));
      setSetup(null);
      setDisabling(false);
      setCode("");
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const codeForm = (
    <form className="row" onSubmit={confirm}>
      <input
        className="code-input"
        style={{ width: 200 }}
        inputMode="numeric"
        autoComplete="one-time-code"
        maxLength={6}
        aria-label={t("code")}
        value={code}
        onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
      />
      <button className="btn seal" disabled={code.length !== 6}>
        {t("verify")}
      </button>
    </form>
  );

  return (
    <section className="section stack">
      <div className="row">
        <h2>{t("mfaSection")}</h2>
        <span className={`pill ${user?.mfa_enabled ? "ok" : "warn"}`}>{user?.mfa_enabled ? t("stateActive") : t("mfaDisabled")}</span>
      </div>
      <p className="muted">
        {user?.mfa_enabled ? t("mfaOn") : t("mfaOff")} {user?.role === "admin" && t("mfaAdminNote")}
      </p>
      {!user?.mfa_enabled && !setup && (
        <div>
          <button className="btn seal" onClick={begin}>
            {t("turnOn")}
          </button>
        </div>
      )}
      {setup && (
        <div className="stack">
          <p>{t("scanQr")}</p>
          <img className="qr" src={setup.qr} alt="QR code for your authenticator app" width={184} height={184} />
          <p className="small muted">
            {t("manualKey")}: <span className="secret">{setup.secret}</span>
          </p>
          {codeForm}
        </div>
      )}
      {user?.mfa_enabled && user.role !== "admin" && (
        <div>
          {disabling ? codeForm : (
            <button className="btn ghost" onClick={() => setDisabling(true)}>
              {t("turnOff")}
            </button>
          )}
        </div>
      )}
      <ErrorText error={error} />
    </section>
  );
}

function PasswordSection() {
  const { t } = useI18n();
  const toast = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api("/auth/password", { method: "POST", body: { current_password: current, new_password: next } });
      setCurrent("");
      setNext("");
      toast(t("passwordSaved"));
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <section className="section stack">
      <h2>{t("changePassword")}</h2>
      <form className="stack" style={{ maxWidth: 420 }} onSubmit={submit}>
        <label>
          {t("currentPassword")}
          <input type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} />
        </label>
        <label>
          {t("newPassword")}
          <input type="password" autoComplete="new-password" required minLength={12} value={next} onChange={(e) => setNext(e.target.value)} />
        </label>
        <p className="small muted">{t("inviteHelp")}</p>
        <ErrorText error={error} />
        <div>
          <button className="btn">{t("savePassword")}</button>
        </div>
      </form>
    </section>
  );
}

export default function Account() {
  const { t, lang, action } = useI18n();
  const { user } = useAuth();
  const activity = useAsync(() => api<AuditEvent[]>("/me/activity"), []);
  if (!user) return null;
  return (
    <>
      <div className="page-head">
        <div>
          <h1>{user.name}</h1>
          <p className="muted">
            {user.email}. {t("role")}: {t(ROLE_KEY[user.role])}
          </p>
        </div>
      </div>
      <div className="sheet" style={{ marginBottom: 20 }}>
        <MfaSection />
        <PasswordSection />
      </div>
      <div className="sheet">
        <section className="section">
          <h2>{t("recentActivity")}</h2>
        </section>
        <table className="table">
          <tbody>
            {activity.data?.map((e) => (
              <tr key={e.id}>
                <td className="muted" style={{ whiteSpace: "nowrap" }}>
                  {formatDate(e.at, lang)}
                </td>
                <td>
                  {action(e.action)}
                  {e.outcome === "failure" && <span className="pill bad" style={{ marginLeft: 8 }}>{t("failure")}</span>}
                </td>
                <td className="muted hide-sm">
                  {e.country ?? ""} {e.ip}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
