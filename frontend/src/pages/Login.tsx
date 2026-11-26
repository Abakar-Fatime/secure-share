import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router-dom";
import { ErrorText, LockIcon } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n, type TKey } from "../lib/i18n";

const SSO_ERRORS: Record<string, TKey> = {
  sso_state: "ssoState",
  sso_failed: "ssoFailed",
  sso_no_account: "ssoNoAccount",
};

export function AuthFrame({ children }: { children: React.ReactNode }) {
  const { t, toggle } = useI18n();
  return (
    <div className="auth">
      <div className="auth-form">
        <div className="row">
          <strong style={{ fontFamily: "var(--display)", fontSize: "1.2rem" }}>{t("appName")}</strong>
          <span className="spacer" />
          <button className="linklike small" onClick={toggle}>
            {t("language")}
          </button>
        </div>
        {children}
      </div>
      <div className="auth-art guilloche" aria-hidden="true">
        <LockIcon className="lock" size={64} />
        <p>{t("tagline")}</p>
      </div>
    </div>
  );
}

export default function Login() {
  const { t } = useI18n();
  const { user, refresh } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [step, setStep] = useState<"password" | "mfa">(params.get("mfa") ? "mfa" : "password");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const ssoKey = SSO_ERRORS[params.get("error") ?? ""];
  const [error, setError] = useState<string | null>(ssoKey ? t(ssoKey) : null);
  const [google, setGoogle] = useState(false);

  useEffect(() => {
    api<{ google_enabled: boolean }>("/auth/config")
      .then((c) => setGoogle(c.google_enabled))
      .catch(() => setGoogle(false));
  }, []);

  if (user) return <Navigate to={user.role === "viewer" ? "/shared" : "/files"} replace />;

  async function submitPassword(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ mfa_required: boolean }>("/auth/login", { method: "POST", body: { email, password } });
      if (r.mfa_required) {
        setStep("mfa");
      } else {
        await refresh();
        navigate("/files");
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("/auth/mfa/verify", { method: "POST", body: { code } });
      await refresh();
      navigate("/files");
    } catch (err) {
      setError((err as Error).message);
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthFrame>
      {step === "password" ? (
        <>
          <h1>{t("signInTitle")}</h1>
          <form onSubmit={submitPassword}>
            <label>
              {t("email")}
              <input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
            </label>
            <label>
              {t("password")}
              <input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
            </label>
            <ErrorText error={error} />
            <button className="btn" disabled={busy}>
              {busy ? t("signingIn") : t("signIn")}
            </button>
          </form>
          {google && (
            <>
              <div className="divider">{t("orWith")}</div>
              <a className="btn ghost" href="/api/auth/google/login">
                <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
                  <path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.6l6.7-6.7C35.6 2.4 30.2 0 24 0 14.6 0 6.6 5.4 2.6 13.2l7.8 6C12.3 13.4 17.7 9.5 24 9.5z" />
                  <path fill="#4285F4" d="M46.1 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.4c-.5 2.9-2.2 5.3-4.6 6.9l7.4 5.7c4.3-4 6.9-9.9 6.9-17.1z" />
                  <path fill="#FBBC05" d="M10.4 28.8A14.5 14.5 0 0 1 9.5 24c0-1.7.3-3.3.9-4.8l-7.8-6A24 24 0 0 0 0 24c0 3.9.9 7.5 2.6 10.8l7.8-6z" />
                  <path fill="#34A853" d="M24 48c6.5 0 11.9-2.1 15.9-5.8l-7.4-5.7c-2.1 1.4-4.8 2.3-8.5 2.3-6.3 0-11.7-4.2-13.6-9.9l-7.8 6C6.6 42.6 14.6 48 24 48z" />
                </svg>
                {t("signInGoogle")}
              </a>
            </>
          )}
        </>
      ) : (
        <>
          <h1>{t("mfaTitle")}</h1>
          <p className="muted">{t("mfaHelp")}</p>
          <form onSubmit={submitCode}>
            <label>
              {t("code")}
              <input
                className="code-input"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                required
                autoFocus
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
              />
            </label>
            <ErrorText error={error} />
            <button className="btn" disabled={busy || code.length !== 6}>
              {t("verify")}
            </button>
          </form>
          <button className="linklike" onClick={() => { setStep("password"); setError(null); }}>
            {t("backToSignIn")}
          </button>
        </>
      )}
    </AuthFrame>
  );
}
