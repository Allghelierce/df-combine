import { DragEvent, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { formatBytes } from "../lib/format";

const ACCEPTED = ".bin,.hex,.elf,.img,.zip,.tar,.gz,.tgz,.px4,.apj,.dfu,.squashfs,.ext4,.xz,.bz2";

export function Dropzone({ maxMb, onUploaded }: { maxMb?: number; onUploaded?: () => void }) {
  const [drag, setDrag] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [pct, setPct] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const [queue, setQueue] = useState<{ done: number; total: number } | null>(null);

  async function start(files: File[]) {
    setError(null);
    const problems: string[] = [];
    const ok = files.filter((f) => {
      if (maxMb && f.size > maxMb * 1024 * 1024) problems.push(`${f.name}: ${formatBytes(f.size)} exceeds the ${maxMb} MiB limit`);
      else if (f.size === 0) problems.push(`${f.name}: file is empty`);
      else return true;
      return false;
    });
    if (!ok.length) {
      setError(problems.join("\n"));
      return;
    }
    const ids: string[] = [];
    setQueue({ done: 0, total: ok.length });
    for (const [i, f] of ok.entries()) {
      setFile(f);
      setPct(0);
      try {
        const scan = await api.upload(f, setPct);
        ids.push(scan.id);
      } catch (e) {
        problems.push(`${f.name}: ${e instanceof Error ? e.message : String(e)}`);
      }
      setQueue({ done: i + 1, total: ok.length });
    }
    setPct(null);
    setQueue(null);
    onUploaded?.();
    if (problems.length) setError(problems.join("\n"));
    if (ids.length === 1 && !problems.length) navigate(`/scans/${ids[0]}`);
    else if (ids.length > 1 && !problems.length) navigate("/scans");
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDrag(false);
    const files = Array.from(e.dataTransfer.files ?? []);
    if (files.length) void start(files);
  }

  const busy = pct !== null && !error;
  return (
    <div
      className={`dropzone ${drag ? "drag" : ""} ${busy ? "busy" : ""}`}
      onDragOver={(e) => {
        e.preventDefault();
        setDrag(true);
      }}
      onDragLeave={() => setDrag(false)}
      onDrop={onDrop}
      onClick={() => !busy && input.current?.click()}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && !busy && input.current?.click()}
      aria-label="Upload firmware file"
      data-testid="dropzone"
    >
      <input
        ref={input}
        type="file"
        hidden
        multiple
        accept={ACCEPTED}
        data-testid="file-input"
        onChange={(e) => {
          const files = Array.from(e.target.files ?? []);
          if (files.length) void start(files);
          e.target.value = "";
        }}
      />
      {busy && file ? (
        <>
          <div className="dz-title">
            Uploading {file.name}
            {queue && queue.total > 1 ? ` (${queue.done + 1} of ${queue.total})` : ""}
          </div>
          <div className="progress">
            <span style={{ width: `${pct}%` }} />
          </div>
          <div className="dz-sub">
            {pct}% of {formatBytes(file.size)}
          </div>
        </>
      ) : (
        <>
          <div className="dz-title">Drop firmware files here, or click to choose</div>
          <div className="dz-sub">
            .px4, .apj, .bin, .hex, .elf, .img, .zip, .tar, .gz, DfuSe, SquashFS or ext4{maxMb ? `, up to ${maxMb} MiB each` : ""}. The
            format is read from the file contents, not the extension.
          </div>
        </>
      )}
      {error && (
        <div className="error-box" role="alert">
          {error}
        </div>
      )}
    </div>
  );
}
