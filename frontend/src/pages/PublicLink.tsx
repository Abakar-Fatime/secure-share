import { useState, type FormEvent } from "react";
import { useParams } from "react-router-dom";
import { ErrorText, FileBadge, useAsync } from "../components/ui";
import { api } from "../lib/api";
import { formatBytes, relative } from "../lib/format";
import { useI18n } from "../lib/i18n";
import { AuthFrame } from "./Login";

interface LinkInfo {
  file_name: string;
  size: number;
  expires_at: string;
  password_required: boolean;
  downloads_remaining: number | null;
}

export default function PublicLink() {
  const { token = "" } = useParams();
  const { t, lang } = useI18n();
  const info = useAsync(() => api<LinkInfo>(`/public/links/${encodeURIComponent(token)}`), [token]);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [started, setStarted] = useState(false);
  const [busy, setBusy] = useState(false);

  async function download(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ url: string }>(`/public/links/${encodeURIComponent(token)}/download`, {
        method: "POST",
        body: { password: password || null },
      });
      setStarted(true);
      window.location.assign(r.url);
      info.reload();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthFrame>
      {info.loading && !info.data ? (
        <p className="muted">{t("loading")}</p>
      ) : !info.data ? (
        <>
          <h1>{t("publicTitle")}</h1>
          <p className="error">{t("publicGone")}</p>
        </>
      ) : (
        <>
          <h1>{t("publicTitle")}</h1>
          <div className="sheet section stack">
            <span className="filename">
              <FileBadge name={info.data.file_name} />
              {info.data.file_name}
            </span>
            <span className="small muted">
              {formatBytes(info.data.size)}. {t("publicExpires")} {relative(info.data.expires_at, lang)}.
              {info.data.downloads_remaining !== null && ` ${t("publicRemaining")}: ${info.data.downloads_remaining}.`}
            </span>
          </div>
          <form onSubmit={download}>
            {info.data.password_required && (
              <label>
                {t("publicPassword")}
                <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} />
              </label>
            )}
            <ErrorText error={error} />
            {started && <p className="notice">{t("publicStarted")}</p>}
            <button className="btn seal" disabled={busy}>
              {t("download")}
            </button>
          </form>
        </>
      )}
    </AuthFrame>
  );
}
