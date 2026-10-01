# Changelog

All notable changes to PDF Hexmator are documented here.

## [2.0.0] - 2026-10-01

### Added
- Renamed the primary executable script to `PDFHexmator.ps1`.
- Object-level revision diffing with per-definition SHA-256 hashes.
- Per-document revision diff CSV export when repeated object definitions are recovered.
- Optional external corroboration using qpdf, ExifTool, pdfsig, and Didier Stevens' pdfid.py.
- Forensic case manifest with tool hash, invocation details, source hashes, generated-artifact hashes, and `SHA256SUMS.txt`.
- Pester regression tests for Windows PowerShell 5.1 and PowerShell 7.
- Synthetic regression fixtures covering normal, linearized, incremental, signed-structure, malformed, appended-data, duplicate, and multi-revision PDFs.
- GitHub Actions workflow for automated Pester testing.
- Repository screenshots and release documentation.

### Changed
- Product branding standardized as **PDF Hexmator**.
- Bulk CSV/HTML summaries now include changed-object counts and external-validator status.
- README reorganized around quick-start, bulk workflow, forensic interpretation, validation, and testing.

### Retained
- Linearization-aware revision handling introduced in 1.x.
- Bulk analysis, duplicate SHA-256 grouping, detailed per-file reports, revision carving, metadata/signature/active-content triage, and per-document error isolation.
