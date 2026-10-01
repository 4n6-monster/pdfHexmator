# Synthetic PDF fixtures

These files are intentionally small, synthetic regression fixtures. They contain no real evidence or personal data.

- `normal.pdf` — single-revision classic xref PDF.
- `normal-duplicate.pdf` — exact byte-for-byte duplicate for SHA-256 grouping tests.
- `incremental.pdf` — one incremental update with a backward `/Prev` and a redefined Info object.
- `multiple-revisions.pdf` — two appended updates.
- `linearized.pdf` — synthetic Fast Web View structure with early `startxref 0`, forward `/Prev`, and matching `/L`.
- `signed-structure.pdf` — contains `/Type /Sig` and `/ByteRange` structures; it is **not** a cryptographically valid signature.
- `appended-data.pdf` — non-whitespace payload after the final `%%EOF`.
- `malformed.pdf` — intentionally incomplete PDF with no `%%EOF`.

The fixtures are designed for structural regression testing, not conformance certification.
