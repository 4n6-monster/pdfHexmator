# PDF Hexmator

**PDF Hexmator** is a PowerShell-based forensic triage utility for examining PDF structure, revision history, metadata, signature-related structures, active content, and bulk document collections.

It is designed for **single-document analysis** and **high-volume folder triage** involving hundreds or thousands of PDFs. The tool emphasizes conservative interpretation: it reports observable structures and corroborating indicators rather than treating metadata or multiple `%%EOF` markers alone as proof that a document was improperly edited.

> **Version:** 2.0.0  
> **Script:** `PDFHexmator.ps1`  
> **PowerShell:** Windows PowerShell 5.1+ or PowerShell 7+  
> **Required dependencies:** None beyond PowerShell/.NET  
> **Optional corroboration:** qpdf, ExifTool, pdfsig, Didier Stevens' `pdfid.py`

![PDF Hexmator bulk dashboard](images/bulk-dashboard.png)

## Quick overview

PDF Hexmator examines PDFs for indicators including:

- PDF header/version and unusual data before the header
- classic xref tables and XRef streams
- `trailer`, `startxref`, and `%%EOF` relationships
- incremental updates and logical revision history
- backward and forward `/Prev` relationships
- PDF linearization / Fast Web View
- redefined indirect objects
- **object-level revision diffs with SHA-256 hashes**
- data appended after the final `%%EOF`
- Creator / Producer / CreationDate / ModDate metadata
- XMP metadata
- digital-signature structures and `/ByteRange`
- post-signature bytes
- `/DocMDP` and `/FieldMDP`
- JavaScript, OpenAction, Launch, embedded files, RichMedia, AcroForm, and XFA indicators
- MD5 and SHA-256 hashing
- exact SHA-256 duplicate grouping in bulk collections
- recoverable logical revision carving
- optional external corroboration with third-party PDF utilities
- case-level manifests and output hash inventories

## How to run

### Analyze one PDF

```powershell
powershell -ExecutionPolicy Bypass `
  -File .\PDFHexmator.ps1 `
  -Path 'C:\Evidence\document.pdf'
```

### Analyze a folder

```powershell
powershell -ExecutionPolicy Bypass `
  -File .\PDFHexmator.ps1 `
  -Path 'C:\Evidence\PDFs' `
  -OutputDirectory 'D:\PDF-Analysis'
```

### Recursively analyze a case folder

```powershell
powershell -ExecutionPolicy Bypass `
  -File .\PDFHexmator.ps1 `
  -Path 'C:\Evidence' `
  -Recurse `
  -OutputDirectory 'D:\PDF-Analysis'
```

### Full forensic triage run

```powershell
powershell -ExecutionPolicy Bypass `
  -File .\PDFHexmator.ps1 `
  -Path 'C:\Evidence\PDFs' `
  -Recurse `
  -DetailedReports `
  -ExtractRevisions `
  -ExternalValidation `
  -CaseName 'PDF Review - Case 2026-001' `
  -OutputDirectory 'D:\Analysis\PDF-Hexmator'
```

### Analyze multiple locations

```powershell
.\PDFHexmator.ps1 `
  -Path 'D:\Set1','E:\Set2','F:\Exports\document.pdf' `
  -Recurse `
  -OutputDirectory 'D:\PDF-Analysis'
```

Duplicate input paths are de-duplicated during target discovery.

## Parameters

| Parameter | Description |
|---|---|
| `-Path` | One or more PDF files, directories, or wildcard paths. |
| `-Recurse` | Includes PDFs in nested subdirectories. |
| `-OutputDirectory` | Destination for reports, manifests, and carved revisions. |
| `-DetailedReports` | Generates full per-document HTML/JSON reports in bulk mode. |
| `-ExtractRevisions` | Carves recoverable logical PDF revisions. |
| `-CaseName` | Friendly title for the consolidated report and case manifest. |
| `-ExternalValidation` | Attempts corroborating checks with supported third-party utilities. |
| `-ExternalToolsDirectory` | Optional directory containing external validation tools. |
| `-NoHtml` | Disables HTML output. |
| `-NoJson` | Disables JSON output. |
| `-NoCsv` | Disables consolidated CSV output in bulk mode. |
| `-NoManifest` | Disables the case manifest and `SHA256SUMS.txt`. |
| `-StopOnError` | Stops bulk processing on the first per-document error. |

By default, an error in one PDF is recorded and the bulk run continues.

## Output

A typical bulk run produces:

```text
PDF-Analysis\
│
├── PDF-Forensic-Bulk-Report.html
├── PDF-Forensic-Bulk-Summary.csv
├── PDF-Forensic-Bulk-Summary.json
├── PDFHexmator-Case-Manifest.json
├── PDFHexmator-Case-Manifest.csv
├── SHA256SUMS.txt
│
└── documents\
    ├── 000001_document-one\
    │   ├── document-one.pdf-forensics.html
    │   ├── document-one.pdf-forensics.json
    │   ├── document-one.revision-object-diff.csv
    │   └── revisions\
    └── ...
```

The `documents` tree is created when detailed reports and/or revision extraction are requested.

## Consolidated HTML report

The bulk HTML report is self-contained, searchable, and sortable. It summarizes:

- total/completed/error counts
- incremental-update indicators
- linearized PDFs
- signature structures
- active-content indicators
- duplicate sets
- logical revisions
- physical EOF markers
- backward/forward `/Prev` counts
- redefined objects
- **changed object definitions**
- optional external-validator status
- Producer/Creator metadata
- modification dates
- links to per-document reports

## Object-level revision diffing

Version 2.0.0 adds object-level comparison for repeated indirect object IDs.

When the same object/generation pair appears more than once, PDF Hexmator records each serialized object definition and calculates a SHA-256 hash. The report then compares adjacent definitions:

```text
Object 17 0
  Revision 1 -> Revision 2
  From SHA-256: 92DF...
  To SHA-256:   437A...
  Changed: True
```

This helps move the analysis from **“the file contains revisions”** toward **“these object definitions changed between revisions.”**

![PDF Hexmator detailed report](images/document-report.png)

> Object-level diffing compares serialized indirect-object definitions. It does not yet render a page-level visual diff or semantically decode every stream.

## Linearized PDFs / Fast Web View

Linearized PDFs require special handling because normal Fast Web View structure may include:

- more than one physical `%%EOF`
- an early `startxref 0`
- a `/Prev` entry pointing **forward** toward a later xref

A naive scanner can incorrectly describe this as revision history.

PDF Hexmator distinguishes:

- **physical EOF sections**, and
- **logical PDF revisions**.

Recognized linearization-only bootstrap structures are excluded from incremental-modification scoring and revision carving.

## External validation

Use `-ExternalValidation` to attempt corroborating analysis with locally installed utilities.

Supported integrations in v2.0.0:

| Tool | Purpose |
|---|---|
| qpdf | PDF syntax/xref/stream consistency check |
| ExifTool | Metadata corroboration |
| pdfsig | PDF signature reporting |
| Didier Stevens `pdfid.py` | Keyword/active-content corroboration |

Example:

```powershell
.\PDFHexmator.ps1 `
  -Path 'D:\Evidence' `
  -Recurse `
  -ExternalValidation
```

If tools are stored outside `PATH`:

```powershell
.\PDFHexmator.ps1 `
  -Path 'D:\Evidence' `
  -Recurse `
  -ExternalValidation `
  -ExternalToolsDirectory 'C:\ForensicTools\PDF'
```

Missing tools do not terminate the run. External results are treated as **corroborative**, not authoritative.

## Case manifest and hashing

Unless `-NoManifest` is used, PDF Hexmator generates:

- `PDFHexmator-Case-Manifest.json`
- `PDFHexmator-Case-Manifest.csv`
- `SHA256SUMS.txt`

The manifest records:

- PDF Hexmator version
- SHA-256 of the executing script
- case name
- start/completion timestamps
- command line
- PowerShell version
- host information
- run options
- source PDF hashes
- source assessments
- generated artifact hashes

This is intended to make a completed triage run easier to reproduce, audit, and preserve with case materials.

## Duplicate detection

Bulk mode groups byte-for-byte identical PDFs by complete-file SHA-256.

```text
DUP-0001 (6 files)
DUP-0002 (3 files)
DUP-0003 (2 files)
```

Visually identical files with different binary representations will not be grouped together.

## Digital signatures

PDF Hexmator looks for structures including:

```text
/Type /Sig
/ByteRange
/TransformMethod /DocMDP
/TransformMethod /FieldMDP
```

It can identify bytes that occur after a recovered signed byte range.

PDF Hexmator does **not** independently validate certificate trust, certificate chains, revocation, or cryptographic signature integrity. Use a signature-aware validator such as `pdfsig` or another trusted PDF application for that determination.

## Active content

The tool identifies lexical indicators associated with:

- JavaScript
- `/OpenAction`
- `/AA`
- `/Launch`
- embedded files
- RichMedia
- AcroForm
- XFA

These findings are triage leads. Their presence does not by itself establish malicious behavior.

## Assessment terminology

Examples include:

```text
LINEARIZED PDF - NO INCREMENTAL UPDATE ESTABLISHED
```

```text
LINEARIZED PDF - REVIEW FOR POST-LINEARIZATION CHANGES
```

```text
NO INCREMENTAL-UPDATE HISTORY IDENTIFIED BY THIS TRIAGE
```

```text
INDICATORS CONSISTENT WITH PDF MODIFICATION
```

```text
STRONG EVIDENCE OF INCREMENTAL MODIFICATION / MULTIPLE PDF REVISIONS
```

These are **structural triage assessments**. They are not opinions about motive, authenticity, fraud, or evidentiary weight.

## Forensic interpretation

### Multiple revisions do not automatically mean improper editing

Legitimate incremental updates may result from:

- digital signing
- annotations/comments
- form completion
- Bates numbering
- redaction workflows
- document-management systems
- ordinary editor saves

### No revision history does not prove a document was never edited

Prior history may be lost when a PDF is:

- fully rewritten
- optimized
- flattened
- linearized
- rasterized
- printed to PDF
- converted through another application
- sanitized

### Metadata is corroborative

Creator, Producer, CreationDate, ModDate, and XMP values can be absent, stale, overwritten, or manipulated. Treat metadata as context, not standalone proof.

## Read-only source handling

PDF Hexmator does not intentionally modify source PDFs. Input files are read for analysis; generated reports, hashes, manifests, and carved revisions are written to the output directory.

Normal forensic evidence-handling procedures should still be followed, including analysis from verified copies where appropriate.

## Performance

Bulk processing is sequential by design for compatibility with Windows PowerShell 5.1 and predictable memory use. One PDF is analyzed at a time rather than loading an entire collection into memory.

## Recommended workflow

1. Run PDF Hexmator across the full collection.
2. Review the consolidated HTML dashboard.
3. Filter the CSV for:
   - backward `/Prev`
   - multiple logical revisions
   - changed/redefined objects
   - high-severity findings
   - post-signature bytes
   - unusual Producer metadata
   - active content
4. De-prioritize exact duplicates where appropriate.
5. Open per-document detailed reports for files of interest.
6. Review object-level revision diffs.
7. Extract recoverable revisions.
8. Corroborate important findings with a second standards-aware tool.
9. Preserve the case manifest and `SHA256SUMS.txt` with the examination output.

## Testing

The repository contains synthetic regression fixtures covering:

- normal PDF
- exact duplicate
- incremental update
- multiple revisions
- linearized PDF
- signature structures
- appended data
- malformed PDF

Run the Pester suite:

```powershell
Install-Module Pester -Scope CurrentUser -Force -MinimumVersion 5.5.0
Invoke-Pester -Path .\tests\PDFHexmator.Tests.ps1 -Output Detailed
```

GitHub Actions runs the suite on both:

- Windows PowerShell 5.1
- PowerShell 7

The test PDFs are synthetic and contain no case evidence or personal data.

## Repository layout

```text
PDF-Hexmator/
│
├── PDFHexmator.ps1
├── README.md
├── CHANGELOG.md
├── RELEASE_NOTES_v2.0.0.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
│
├── images/
│   ├── bulk-dashboard.png
│   └── document-report.png
│
├── tests/
│   ├── PDFHexmator.Tests.ps1
│   └── fixtures/
│       └── *.pdf
│
└── .github/
    ├── release.yml
    └── workflows/
        └── pester.yml
```

## Limitations

PDF is a complex format. Current limitations include:

- compressed object streams may limit lexical object recovery
- malformed PDFs may produce incomplete results
- a full rewrite may remove revision history
- metadata can be inaccurate or intentionally manipulated
- signature structures are detected but not cryptographically validated internally
- object-level diffs do not yet equal page-level visual diffs
- embedded/content streams are not comprehensively decoded and semantically compared
- significant findings should be independently corroborated for evidentiary use

## Roadmap

Potential follow-on work:

- page-level rendered revision comparison
- content-stream decoding and semantic text differences
- additional xref/object-stream decoding
- resumable/checkpointed bulk scans
- opt-in PowerShell 7 parallel mode
- YARA-style PDF structural rules
- tighter forensic-suite integrations

## Acknowledgements

PDF Hexmator was informed by PDF structural-analysis concepts and prior community work, including:

- [PDF-Processing by jjrboucher](https://github.com/jjrboucher/PDF-Processing)
- PDF binary-template work by Didier Stevens, Christian Mehlmauer, Peter Wyatt, and the broader PDF analysis community

These references helped inform examination of PDF headers, objects, cross-reference structures, trailers, `startxref`, `%%EOF`, linearization, and incremental updates.

## License

PDF Hexmator is released under the [MIT License](LICENSE).

## Disclaimer

PDF Hexmator is an investigative and forensic triage utility. Results should be interpreted in context and independently validated before being used for evidentiary conclusions. Structural indicators may reflect legitimate PDF processing, and the absence of an indicator does not prove that a document has never been modified.
