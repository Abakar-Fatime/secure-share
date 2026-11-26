import { ErrorText, useAsync } from "../components/ui";
import { api, type FileItem } from "../lib/api";
import { useI18n } from "../lib/i18n";
import { FileTable } from "./Files";

export default function Shared() {
  const { t } = useI18n();
  const files = useAsync(() => api<{ shared_with_me: FileItem[] }>("/files"), []);
  const list = files.data?.shared_with_me ?? [];
  return (
    <>
      <div className="page-head">
        <h1>{t("sharedTitle")}</h1>
      </div>
      <ErrorText error={files.error} />
      <div className="sheet">
        {files.loading && !files.data ? (
          <p className="empty">{t("loading")}</p>
        ) : list.length === 0 ? (
          <p className="empty">{t("sharedEmpty")}</p>
        ) : (
          <FileTable files={list} />
        )}
      </div>
    </>
  );
}
