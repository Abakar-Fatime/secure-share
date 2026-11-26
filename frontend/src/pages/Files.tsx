import { useState } from "react";
import ShareDrawer from "../components/ShareDrawer";
import { ErrorText, FileBadge, useAsync, useToast } from "../components/ui";
import Uploader from "../components/Uploader";
import { api, type FileItem } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatBytes, formatDate } from "../lib/format";
import { useI18n } from "../lib/i18n";

export async function startDownload(fileId: string) {
  const { url } = await api<{ url: string }>(`/files/${fileId}/download`);
  window.location.assign(url);
}

export function FileTable({
  files,
  onShare,
  onDelete,
}: {
  files: FileItem[];
  onShare?: (f: FileItem) => void;
  onDelete?: (f: FileItem) => void;
}) {
  const { t, lang } = useI18n();
  const toast = useToast();
  return (
    <table className="table">
      <thead>
        <tr>
          <th>{t("name")}</th>
          <th className="num hide-sm">{t("size")}</th>
          <th className="hide-sm">{t("added")}</th>
          <th className="actions">
            <span className="sr-only">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {files.map((f) => (
          <tr key={f.id}>
            <td>
              <span className="filename">
                <FileBadge name={f.name} />
                {f.name}
              </span>
            </td>
            <td className="num hide-sm">{formatBytes(f.size)}</td>
            <td className="hide-sm muted">{formatDate(f.created_at, lang)}</td>
            <td className="actions">
              <div className="row" style={{ justifyContent: "end", flexWrap: "nowrap" }}>
                <button className="btn ghost small" onClick={() => startDownload(f.id).catch((e) => toast(e.message))}>
                  {t("download")}
                </button>
                {onShare && (
                  <button className="btn small" onClick={() => onShare(f)}>
                    {t("share")}
                  </button>
                )}
                {onDelete && (
                  <button className="btn danger small" onClick={() => onDelete(f)}>
                    {t("delete")}
                  </button>
                )}
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Files() {
  const { t } = useI18n();
  const toast = useToast();
  const { user } = useAuth();
  const files = useAsync(() => api<{ owned: FileItem[] }>("/files"), []);
  const [sharing, setSharing] = useState<FileItem | null>(null);

  async function remove(f: FileItem) {
    if (!window.confirm(`${f.name}\n\n${t("confirmDelete")}`)) return;
    try {
      await api(`/files/${f.id}`, { method: "DELETE" });
      toast(t("deleted"));
      files.reload();
    } catch (e) {
      toast((e as Error).message);
    }
  }

  if (user?.role === "viewer") {
    return <p className="notice">{t("viewerNoUpload")}</p>;
  }

  const owned = files.data?.owned ?? [];
  return (
    <>
      <div className="page-head">
        <h1>{t("filesTitle")}</h1>
      </div>
      <Uploader onUploaded={files.reload} />
      <ErrorText error={files.error} />
      <div className="sheet">
        {files.loading && !files.data ? (
          <p className="empty">{t("loading")}</p>
        ) : owned.length === 0 ? (
          <p className="empty">{t("filesEmpty")}</p>
        ) : (
          <FileTable files={owned} onShare={setSharing} onDelete={remove} />
        )}
      </div>
      {sharing && <ShareDrawer file={sharing} onClose={() => setSharing(null)} />}
    </>
  );
}
