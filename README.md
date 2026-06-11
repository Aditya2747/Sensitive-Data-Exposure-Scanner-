# Sensitive Data Exposure Scanner — MVP

A data-compliance platform that scans documents (`.txt`, `.csv`, `.pdf`, `.docx`) for **PII** and **Secrets**, computes a weighted risk score using a sophisticated multi-factor algorithm, and returns actionable compliance recommendations.

This repository contains two sides of the same application:

| Component | Stack | Location |
|---|---|---|
| **Backend API** | FastAPI · Pydantic · pypdf · python-docx | `backend/` |
| **Frontend** | React · Vite · Tailwind CSS · pdfjs-dist · mammoth | project root |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Frontend (Next.js / React SPA)                             │
│  ─────────────────────────                                  │
│  FileDropzone → extractor → detector → riskEngine → Report  │
│     (browser)     (browser)   (browser)   (browser)         │
└───────────────────────────┬─────────────────────────────────┘
                            │  POST /api/scan  (multipart)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Backend (FastAPI)                                          │
│  ─────────────────                                          │
│  main.py → services/extractor.py                            │
│          → services/detector.py                             │
│          → services/risk_engine.py                          │
│          → schemas.py   (Pydantic validation)               │
└─────────────────────────────────────────────────────────────┘
```

The frontend performs identical logic entirely client-side (zero-network scanning); the backend mirrors the same algorithms for server-side/integrated workloads.

---

## Compliance Risk Scoring Algorithm

The scoring engine implements a **multi-factor risk assessment** that considers **severity**, **confidence**, **volume**, and **co-occurrence** of detected data types.

### Formula

```
Final Score = MIN(100, RawScore + CoOccurrenceBonus)
RawScore    = Σ (SeverityWeight × ConfidenceFactor × VolumeMultiplier)
```

### Step 1 — Severity Weights (Base Points)

| Data Type | Weight |
|-----------|--------:|
| Aadhaar Number | 35 |
| PAN Number | 30 |
| Passport Number | 30 |
| Credit/Debit Card | 30 |
| AWS Credentials | 30 |
| API Key | 25 |
| JWT Token | 25 |
| DB Connection String | 25 |
| Password/Secret | 20 |
| Phone Number | 15 |
| Email Address | 10 |

### Step 2 — Confidence Factor

Each detection includes a confidence level based on validation depth:

| Confidence | Factor | Description |
|------------|--------|-------------|
| **HIGH** | × 1.0 | Checksum/structure validated (Luhn for cards, Verhoeff for Aadhaar, PAN structure) |
| **MEDIUM** | × 0.7 | Regex pattern match only |
| **LOW** | × 0.4 | Heuristic or context-based detection |

### Step 3 — Volume Multiplier

Repeated exposure amplifies risk non-linearly:

| Count | Multiplier |
|------:|-----------:|
| 0 | × 0 (skip) |
| 1 | × 1.0 |
| 2 – 5 | × 1.3 |
| 6 – 20 | × 1.6 |
| 21 – 100 | × 2.0 |
| > 100 | × 2.5 |

### Step 4 — Co-Occurrence Bonus

Multiple data types in the same document indicates systemic data handling issues:

| Categories Present | Bonus |
|-------------------:|------:|
| 1 | + 0 |
| 2 | + 5 |
| 3+ | + 12 |

### Risk Level Thresholds

| Score Range | Level | Action Required |
|-------------|-------|-----------------|
| 0 – 29 | **LOW** | Routine review, monitor |
| 30 – 59 | **MEDIUM** | Remediation recommended |
| 60 – 84 | **HIGH** | Immediate action required |
| 85 – 100 | **CRITICAL** | Emergency response, audit |

### Example Calculation

Document contains:
- 3 validated Aadhaar numbers (HIGH confidence)
- 1 AWS Access Key (HIGH confidence)  
- 5 email addresses (MEDIUM confidence)

```
Aadhaar: 35 × 1.0 × 1.3 = 45.5
AWS Key: 30 × 1.0 × 1.0 = 30.0
Emails:  10 × 0.7 × 1.3 = 9.1
────────────────────────────────
Raw Score:                 84.6
Co-occurrence (3 cats):    +12
────────────────────────────────
Final Score:               96.6 → 97 (CRITICAL)
```

---

## Engineering Assumptions

1. **10 MB hard cap** on uploaded files — generous enough for most compliance documents while protecting server memory.
2. **Checksum validation** — Aadhaar uses Verhoeff algorithm, credit cards use Luhn, PAN uses structure validation for HIGH confidence.
3. **Regex-first detection** — No ML models in MVP. Regexes anchored with `\b` / look-arounds minimize false positives.
4. **Redacted snippets** — API never returns full matching values; only `ab****yz`-style previews.
5. **Stateless API** — Each request independent; no files persisted to disk (streamed in memory via `io.BytesIO`).
6. **UTF-8 with fallbacks** — `.txt` / `.csv` try `utf-8-sig`, `utf-8`, then `latin-1`.

---

## Trade-offs

| Decision | Speed | Depth | Notes |
|---|---|---|---|
| Regex vs. ML/NER | 🟢 Fast | 🟡 Good | Regex O(n) per doc. ML 10–100× slower, requires model hosting. |
| Client-side parsing | 🟢 Zero network | 🟡 Same engine | Browser processing for demo. Production should use backend for auditing. |
| Checksum validation | 🟡 Slower | 🟢 Accurate | Luhn/Verhoeff add ~1ms per candidate but reduce false positives significantly. |
| Confidence tiers | 🟢 Granular | 🟢 Explainable | Three-tier system provides better risk differentiation than binary. |
| Co-occurrence bonus | 🟢 Simple | 🟢 Effective | Reflects real-world risk where mixed PII exposure is disproportionately dangerous. |

---

## Quick Start

### Prerequisites
- **Node.js ≥ 18** and npm
- **Python ≥ 3.10** and pip

---

### 1. Run the **Frontend** (React + Vite)

```bash
# From the project root:
npm install
npm run dev
# → open http://localhost:5173
```

Build for production:
```bash
npm run build
npm run preview
```

### 2. Run the **Backend** (FastAPI)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```


### 4. Configuration (Backend)

| Env var | Default | Description |
|---|---|---|
| `CORS_ORIGINS` | `*` | Comma-separated list of allowed origins |

---

## API Reference

### `POST /api/scan`

| Field | Value |
|---|---|
| Content-Type | `multipart/form-data` |
| Body | `file` — the document to scan |
| Max size | 10 MB |
| Supported | `.txt`, `.csv`, `.pdf`, `.docx` |

### Response Schema

```typescript
{
  status: "success",
  filename: string,
  size_bytes: number,
  total_characters: number,
  score: number,              // 0 – 100 (integer)
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  total_findings: number,
  findings: Array<{
    category: "PII" | "Secrets",
    label: string,
    count: number,
    severity: "low" | "medium" | "high" | "critical",
    confidence: "HIGH" | "MEDIUM" | "LOW",
    samples: string[]         // redacted, max 3
  }>,
  breakdown: Record<string, {
    count: number,
    confidence: "HIGH" | "MEDIUM" | "LOW",
    severity_weight: number,
    confidence_factor: number,
    volume_multiplier: number,
    contribution: number
  }>,
  cooccurrence_bonus: number,
  raw_score: number,
  recommendations: string[],
  elapsed_ms: number
}
```

### Errors

| Status | Meaning |
|---:|---|
| 400 | Bad extension / empty file |
| 413 | File exceeds 10 MB |
| 422 | File could not be parsed |
| 500 | Unexpected internal error |

---

## Project Layout

```
.
├── backend/
│   ├── main.py                    # FastAPI entrypoint
│   ├── schemas.py                 # Pydantic models
│   ├── requirements.txt
│   └── services/
│       ├── extractor.py           # Text extraction
│       ├── detector.py            # 12 patterns with checksum validation
│       └── risk_engine.py         # Multi-factor scoring engine
├── src/
│   ├── App.tsx                    # Dashboard with score breakdown
│   ├── lib/
│   │   ├── types.ts
│   │   ├── extractor.ts
│   │   ├── detector.ts            # Browser-side detection
│   │   └── riskEngine.ts          # Client-side scoring
│   └── components/
│       ├── FileDropzone.tsx
│       ├── RiskScoreBadge.tsx     # Circular progress gauge
│       ├── FindingsTable.tsx
│       ├── RecommendationsList.tsx
│       └── ScoreBreakdown.tsx     # Detailed contribution bars
├── index.html
├── package.json
└── README.md
```

---

## Detection Patterns with Confidence Levels

| Pattern | Category | Confidence | Validation |
|---------|----------|------------|------------|
| Email Address | PII | MEDIUM | Regex only |
| Indian Phone | PII | MEDIUM | Regex only |
| PAN Card | PII | **HIGH** | Structure validation (AAAAB1234C) |
| Aadhaar | PII | **HIGH** | Verhoeff checksum |
| Passport | PII | MEDIUM | Regex only |
| Credit Card | PII | **HIGH** | Luhn checksum |
| API Key | Secret | LOW | Heuristic pattern |
| AWS Access Key | Secret | **HIGH** | Strict prefix pattern |
| AWS Secret Key | Secret | MEDIUM | Base64 pattern |
| JWT Token | Secret | **HIGH** | Base64url structure |
| Password | Secret | LOW | Context heuristic |
| DB Connection | Secret | MEDIUM | URI scheme pattern |

---

## License

Internal MVP — © 2026
