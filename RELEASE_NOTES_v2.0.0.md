# PDF Hexmator 2.0.0

PDF Hexmator 2.0.0 is the first repository-grade release under the final project name.

## Highlights

- **Stable filename:** `PDFHexmator.ps1` — versioning is handled through releases and internal metadata rather than the filename.
- **Object-level revision diffs:** repeated indirect-object definitions are hashed and compared across logical revisions.
- **Forensic case manifest:** records the tool/script hash, command line, input hashes, output hashes, timestamps, and run options.
- **External corroboration:** optional checks using qpdf, ExifTool, pdfsig, and pdfid.py when available.
- **Automated testing:** Pester fixtures and GitHub Actions cover Windows PowerShell 5.1 and PowerShell 7.
- **Improved repository documentation:** README, changelog, license, contribution guidance, and screenshots.

## Recommended release assets

- `PDFHexmator.ps1`
- `PDF-Hexmator-v2.0.0.zip`
- `SHA256SUMS.txt`

## Verification

Before publishing a release, run:

```powershell
Invoke-Pester -Path .\tests\PDFHexmator.Tests.ps1 -Output Detailed
```

For a real evidence workflow, independently corroborate significant PDF findings with a standards-aware parser or another forensic utility.

## Release hashes

`PDFHexmator.ps1` SHA-256:

```text
E7B01443B86A7306A65451B976B0D3239F2CA0ED0D8ED9E115410909CA24047D
```
