import { useState, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ErrorText } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n } from "../lib/i18n";
import { AuthFrame } from "./Login";

export default function Invite() {
  const { token = "" } = useParams();
  const { t } = useI18n();
  const { refresh } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("/auth/invite/accept", { method: "POST", body: { token, password, name: name || null } });
      await refresh();
      navigate("/account");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthFrame>
      <h1>{t("inviteTitle")}</h1>
      <p className="muted">{t("inviteHelp")}</p>
      <form onSubmit={submit}>
        <label>
          {t("yourName")}
          <input autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          {t("newPassword")}
          <input type="password" autoComplete="new-password" required minLength={12} value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <ErrorText error={error} />
        <button className="btn" disabled={busy}>
          {t("createAccount")}
        </button>
      </form>
    </AuthFrame>
  );
}
