import { useCallback, useRef, useState } from "react";
import type { DragEvent, ChangeEvent } from "react";
import { formatBytes, getExtension } from "../lib/extractor";

interface FileDropzoneProps {
  onFile: (file: File) => void;
  loading: boolean;
}

const ACCEPTED = ".txt,.csv,.pdf,.docx";

export function FileDropzone({ onFile, loading }: FileDropzoneProps) {
  const [dragOver, setDragOver] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileSize, setFileSize] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const validateAndHandle = useCallback(
    (file: File) => {
      setError(null);
      const ext = getExtension(file.name);
      if (!ext) {
        setError("Unsupported file type. Please upload .txt, .csv, .pdf, or .docx");
        return;
      }
      if (file.size > 10 * 1024 * 1024) {
        setError("File exceeds 10 MB limit.");
        return;
      }
      setFileName(file.name);
      setFileSize(file.size);
      onFile(file);
    },
    [onFile]
  );

  const onDrop = useCallback(
    (e: DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files?.[0];
      if (file) validateAndHandle(file);
    },
    [validateAndHandle]
  );

  const onChange = useCallback(
    (e: ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) validateAndHandle(file);
    },
    [validateAndHandle]
  );

  return (
    <div className="w-full">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          if (!loading) setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
        onClick={() => !loading && inputRef.current?.click()}
        className={[
          "relative cursor-pointer rounded-2xl border-2 border-dashed p-8 transition-all duration-200",
          dragOver
            ? "border-indigo-500 bg-indigo-50 scale-[1.01]"
            : "border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50",
          loading ? "opacity-60 pointer-events-none" : "",
        ].join(" ")}
      >
        <input
          ref={inputRef}
          type="file"
          accept={ACCEPTED}
          className="hidden"
          onChange={onChange}
        />

        <div className="flex flex-col items-center justify-center gap-4 text-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-600 shadow-lg shadow-indigo-200">
            <svg
              className="h-7 w-7 text-white"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="17 8 12 3 7 8" />
              <line x1="12" y1="3" x2="12" y2="15" />
            </svg>
          </div>

          {loading ? (
            <div>
              <p className="text-sm font-medium text-slate-700">Scanning document…</p>
              <p className="mt-1 text-xs text-slate-500">
                Extracting text and running detection patterns
              </p>
            </div>
          ) : fileName ? (
            <div>
              <p className="text-sm font-semibold text-slate-800">{fileName}</p>
              <p className="mt-1 text-xs text-slate-500">
                {fileSize !== null && formatBytes(fileSize)} · Click or drop to replace
              </p>
            </div>
          ) : (
            <div>
              <p className="text-sm font-semibold text-slate-800">
                Drop your document here
              </p>
              <p className="mt-1 text-xs text-slate-500">
                or <span className="font-medium text-indigo-600">click to browse</span>{" "}
                · TXT, CSV, PDF, DOCX · up to 10 MB
              </p>
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className="mt-3 flex items-start gap-2 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 ring-1 ring-red-200">
          <svg className="mt-0.5 h-4 w-4 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
            <path
              fillRule="evenodd"
              d="M18 10A8 8 0 11 2 10a8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
              clipRule="evenodd"
            />
          </svg>
          {error}
        </div>
      )}
    </div>
  );
}
