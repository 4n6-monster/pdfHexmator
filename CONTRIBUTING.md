# Contributing

Contributions are welcome. PDF Hexmator is a forensic triage utility, so changes that affect interpretation should include regression coverage.

## Development expectations

1. Maintain compatibility with Windows PowerShell 5.1 and PowerShell 7 unless a change is explicitly scoped otherwise.
2. Add or update Pester tests for parser, assessment, or report changes.
3. Prefer conservative forensic wording. A structural indicator should not be described as proof of intent, authenticity, or wrongdoing.
4. Add synthetic fixtures rather than real case material.
5. Do not commit evidence, personal data, secrets, or proprietary PDFs.
6. Document user-visible changes in `CHANGELOG.md`.

## Running tests

```powershell
Install-Module Pester -Scope CurrentUser -Force -MinimumVersion 5.5.0
Invoke-Pester -Path .\tests\PDFHexmator.Tests.ps1 -Output Detailed
```
