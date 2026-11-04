import { DragEvent, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { formatBytes } from "../lib/format";
import { Icon } from "./ui";

const ACCEPTED = ".bin,.hex,.elf,.img,.zip,.tar,.gz,.tgz,.px4,.apj,.dfu,.squashfs,.ext4,.xz,.bz2";

export function Dropzone({ maxMb, onUploaded }: { maxMb?: number; onUploaded?: () => void }) {
  const [drag, setDrag] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [pct, setPct] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  async function start(f: File) {
    setError(null);
    setFile(f);
    if (maxMb && f.size > maxMb * 1024 * 1024) {
      setError(`File is ${formatBytes(f.size)}; the server limit is ${maxMb} MiB.`);
      return;
    }
    if (f.size === 0) {
      setError("File is empty.");
      return;
    }
    setPct(0);
    try {
      const scan = await api.upload(f, setPct);
      onUploaded?.();
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPct(null);
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDrag(false);
    const f = e.dataTransfer.files?.[0];
    if (f) void start(f);
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
        accept={ACCEPTED}
        data-testid="file-input"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) void start(f);
          e.target.value = "";
        }}
      />
      <div className="dz-icon">{Icon.upload}</div>
      {busy && file ? (
        <>
          <div className="dz-title">Uploading {file.name}</div>
          <div className="progress">
            <span style={{ width: `${pct}%` }} />
          </div>
          <div className="dz-sub mono">
            {pct}% of {formatBytes(file.size)}
          </div>
        </>
      ) : (
        <>
          <div className="dz-title">Drop firmware here or click to browse</div>
          <div className="dz-sub">
            PX4 (.px4), ArduPilot (.apj), .bin, .hex, .elf, .img, .zip, .tar, .gz / .tar.gz, DfuSe, SquashFS, ext4
            {maxMb ? ` · max ${maxMb} MiB` : ""}
          </div>
          <div className="dz-note">Format is detected from content, not the extension. Firmware is never executed.</div>
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
