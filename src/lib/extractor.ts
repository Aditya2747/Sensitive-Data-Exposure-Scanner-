/**
 * extractor.ts
 * Browser-side text extraction. Supports .txt, .csv, .pdf (via pdfjs-dist),
 * and .docx (via mammoth).
 */
import * as pdfjsLib from "pdfjs-dist";
// @ts-expect-error – Vite worker import
import PdfWorker from "pdfjs-dist/build/pdf.worker.min.mjs?url";
import mammoth from "mammoth";

// Configure pdf.js worker
pdfjsLib.GlobalWorkerOptions.workerSrc = PdfWorker as string;

const MAX_BYTES = 10 * 1024 * 1024; // 10 MB

const SUPPORTED_EXT = ["txt", "csv", "pdf", "docx"] as const;
export type SupportedExt = (typeof SUPPORTED_EXT)[number];

export function getExtension(filename: string): SupportedExt | null {
  const ext = filename.split(".").pop()?.toLowerCase() ?? "";
  return (SUPPORTED_EXT as readonly string[]).includes(ext)
    ? (ext as SupportedExt)
    : null;
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export async function extractText(
  file: File
): Promise<{ text: string; sizeBytes: number }> {
  if (file.size > MAX_BYTES) {
    throw new Error(
      `File too large (${formatBytes(file.size)}). Maximum is 10 MB.`
    );
  }

  if (file.size === 0) throw new Error("Uploaded file is empty.");

  const ext = getExtension(file.name);
  if (!ext) {
    throw new Error(
      `Unsupported file type. Allowed: ${SUPPORTED_EXT.join(", ")}`
    );
  }

  const buffer = await file.arrayBuffer();

  switch (ext) {
    case "txt":
    case "csv":
      return { text: new TextDecoder("utf-8").decode(buffer), sizeBytes: file.size };
    case "pdf":
      return { text: await extractPdf(buffer), sizeBytes: file.size };
    case "docx":
      return { text: await extractDocx(buffer), sizeBytes: file.size };
  }
}

async function extractPdf(buffer: ArrayBuffer): Promise<string> {
  const pdf = await pdfjsLib.getDocument({ data: buffer }).promise;
  const pages: string[] = [];
  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const content = await page.getTextContent();
    const strings = content.items.map((it: unknown) => {
      const item = it as { str?: string };
      return item.str ?? "";
    });
    pages.push(strings.join(" "));
  }
  return pages.join("\n");
}

async function extractDocx(buffer: ArrayBuffer): Promise<string> {
  const result = await mammoth.extractRawText({ arrayBuffer: buffer });
  return result.value;
}
