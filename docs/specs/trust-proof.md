# trust-proof — implementation spec

Local-first **security-questionnaire + evidence automation**. Ingests a
questionnaire and a corpus of *already-approved* evidence, maps each question to
explicit evidence, drafts an answer **only when it is grounded in a citation**,
marks everything else `UNKNOWN`, and exports a gap report plus a draft
questionnaire.

## Positioning

Security questionnaires stall enterprise deals for weeks and are painful to
answer by hand. `trust-proof` turns your existing approved docs into cited draft
answers in seconds — without inventing compliance claims. The value is that it
is **grounded and honest**: every drafted answer is *extractive*, tied to a
source file and line; anything unsupported is surfaced as a gap rather than
guessed. Nothing is uploaded.

## Hard safety rules (non-negotiable)

- **No hallucinated compliance claims.** Answers are extracted from cited
  evidence text; the tool never generates a claim the evidence does not state.
- **No auto-certification.** It drafts; a human approves. Output is explicitly
  labeled as a draft.
- **No external upload by default.** Everything runs locally and offline; there
  is no network path in the tool.
- **UNKNOWN over wrong.** If evidence does not clear the confidence threshold,
  the answer is `UNKNOWN` and the question is a gap.
- Secrets in evidence are redacted before they appear in any output.

## Inputs

- **Questionnaire** (`--questions <file>`): CSV, XLSX, or plain text.
  - CSV/XLSX: questions are taken from the first column (a header row is
    auto-detected and skipped when the first cell looks like a header).
  - Text: one question per non-empty line.
- **Evidence corpus** (`--evidence <dir>`): a directory of approved documents
  (`.md`, `.txt`, policy exports, SOC 2 excerpts, architecture/security docs).
  Walked read-only via `internal/walk`; each document is split into passages
  (paragraph blocks), each retaining its source file and starting line.

## Matching (deterministic, offline, explainable)

No LLM, no network. Retrieval is TF-IDF term overlap:

1. Tokenize questions and passages to lowercased alphanumeric terms; drop a
   small English stopword list.
2. Compute `idf(term)` over the passage corpus (document frequency across
   passages) so common words do not dominate.
3. Score a passage for a question as the sum of `idf(t)` for shared terms `t`,
   length-normalized to avoid long-passage bias.
4. **Coverage** = (Σ idf of matched question terms) / (Σ idf of all question
   terms) → drives confidence:
   - coverage ≥ 0.60 → **HIGH**
   - coverage ≥ 0.35 → **MEDIUM**
   - coverage ≥ 0.20 → **LOW**
   - otherwise → **UNKNOWN** (gap)

`--min-confidence {high|medium|low}` (default `medium`) sets the bar to draft an
answer; below it the question is a gap.

This is fully deterministic: same questionnaire + same evidence ⇒ same answers,
scores, and citations on any machine.

## Drafted answers (extractive, cited)

For an answered question, the draft answer is built **from the matched passage
text**, not generated:

> Based on `policies/access-control.md:12`: "All production access requires SSO
> with hardware MFA and is reviewed quarterly."

The result record per question:

- `Question`
- `Status`: `ANSWERED` | `UNKNOWN`
- `Confidence`: HIGH | MEDIUM | LOW (empty for UNKNOWN)
- `Answer`: extractive, cited text (empty for UNKNOWN)
- `Citations`: list of `file:line` sources with the (redacted) passage text
- `Coverage`: the numeric score, for auditability

## Outputs

- **Gap report** (default, terminal; also JSON): totals, coverage %, and the
  list of UNKNOWN questions. `--fail-on-gaps` exits `3` if any gap remains.
- **Draft questionnaire export**: `--format {csv|xlsx|md}` with `--out <file>`
  (defaults to stdout for text formats). Columns / sections:
  `Question | Status | Confidence | Answer | Citations`.
  - CSV via `encoding/csv`.
  - Markdown as a table with a summary header.
  - XLSX via `internal/xlsx` (stdlib-only writer).

## `internal/xlsx` (stdlib-only)

A minimal, dependency-free XLSX reader/writer, since no external modules can be
added:
- **Read**: unzip, parse `xl/worksheets/sheet1.xml`, resolve `xl/sharedStrings.xml`
  and inline strings, return `[][]string` (first sheet).
- **Write**: emit the minimal valid part set
  (`[Content_Types].xml`, `_rels/.rels`, `xl/workbook.xml`,
  `xl/_rels/workbook.xml.rels`, `xl/worksheets/sheet1.xml`) with inline strings.
- Tested by round-trip (write → read) and by parsing a hand-authored
  shared-strings sheet.

## CLI

`trust-proof` does **not** use `internal/cli` (that runner is for tree
scanners). Its flags:

```
--questions <file>        CSV / XLSX / text questionnaire (required)
--evidence <dir>          approved evidence corpus (required)
--format <fmt>            terminal | json | csv | xlsx | md   (default terminal)
--out <file>              output path for csv/xlsx/md         (default stdout)
--min-confidence <lvl>    high | medium | low                 (default medium)
--fail-on-gaps            exit 3 if any question is UNKNOWN
--version
```

Exit codes match the toolkit: `0` ok, `1` error, `3` gaps present (with
`--fail-on-gaps`).

## Fixtures (synthetic)

Under `internal/trustproof/testdata/`:
- `evidence/` — a few synthetic approved docs: `access-control.md`,
  `encryption.md`, `backup-policy.txt`, `soc2-excerpt.md` (all fabricated).
- `questions.csv` — questions, some clearly answerable from the evidence, some
  deliberately unsupported (to produce UNKNOWN gaps).
- `questions.txt` — same questions, text form, to test the text ingester.
- A generated `.xlsx` is produced in tests via `internal/xlsx` (not committed).

## Tests

- Answerable questions resolve to `ANSWERED` with a citation pointing at the
  right file; unsupported questions resolve to `UNKNOWN`.
- Determinism: same inputs ⇒ identical CSV / MD / JSON output.
- No hallucination: every answered question's answer text is a substring of some
  cited evidence passage (extractive property, asserted in a test).
- `--min-confidence high` demotes borderline answers to gaps.
- XLSX round-trips; secret-shaped text in evidence is redacted in output.
- Header-row auto-detection on CSV/XLSX.

## One-command demo

`make demo-trust` →
`go run ./cmd/trust-proof --questions internal/trustproof/testdata/questions.csv --evidence internal/trustproof/testdata/evidence`.
