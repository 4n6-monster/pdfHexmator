BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    $Script = Join-Path $ProjectRoot 'PDFHexmator.ps1'
    $Fixtures = Join-Path $PSScriptRoot 'fixtures'

    function Invoke-HexmatorTest {
        param([string]$FixtureName, [switch]$ExternalValidation)
        $out = Join-Path $TestDrive ([IO.Path]::GetFileNameWithoutExtension($FixtureName))
        $args = @(
            '-Path', (Join-Path $Fixtures $FixtureName),
            '-OutputDirectory', $out,
            '-NoManifest', '-NoHtml', '-NoJson'
        )
        if ($ExternalValidation) { $args += '-ExternalValidation' }
        return & $Script @args
    }
}

Describe 'PDF Hexmator v2.0.0 - single document structural triage' {
    It 'analyzes a normal PDF without establishing an incremental update' {
        $r = Invoke-HexmatorTest 'normal.pdf'
        $r.Tool.Version | Should -Be '2.0.0'
        $r.Structure.EofCount | Should -Be 1
        $r.Structure.LogicalRevisionCount | Should -Be 1
        $r.Assessment.Result | Should -Match 'NO INCREMENTAL-UPDATE|NO STRONG'
    }

    It 'detects an incremental update and changed object definition' {
        $r = Invoke-HexmatorTest 'incremental.pdf'
        $r.Structure.LogicalRevisionCount | Should -Be 2
        $r.Structure.BackwardPrevCount | Should -BeGreaterThan 0
        $r.ChangedObjectDefinitions | Should -BeGreaterThan 0
        @($r.RevisionDiffs | Where-Object Changed).Count | Should -BeGreaterThan 0
    }

    It 'recognizes multiple logical revisions' {
        $r = Invoke-HexmatorTest 'multiple-revisions.pdf'
        $r.Structure.LogicalRevisionCount | Should -Be 3
        $r.ChangedObjectDefinitions | Should -BeGreaterThan 1
    }

    It 'recognizes linearization without treating the bootstrap EOF as an edit' {
        $r = Invoke-HexmatorTest 'linearized.pdf'
        $r.Linearization.Detected | Should -BeTrue
        $r.Structure.LogicalRevisionCount | Should -Be 1
        $r.Assessment.Result | Should -Match '^LINEARIZED PDF'
    }

    It 'detects signature structures' {
        $r = Invoke-HexmatorTest 'signed-structure.pdf'
        $r.Signatures.ByteRangeCount | Should -BeGreaterThan 0
        $r.Signatures.SigTypeCount | Should -BeGreaterThan 0
    }

    It 'detects non-whitespace data after the final EOF' {
        $r = Invoke-HexmatorTest 'appended-data.pdf'
        @($r.Findings | Where-Object Code -eq 'DATA_AFTER_FINAL_EOF').Count | Should -Be 1
    }

    It 'reports malformed structure without requiring a valid EOF' {
        $r = Invoke-HexmatorTest 'malformed.pdf'
        @($r.Findings | Where-Object Code -eq 'NO_EOF').Count | Should -Be 1
    }

    It 'keeps external corroboration optional and non-fatal when tools are unavailable' {
        $r = Invoke-HexmatorTest 'normal.pdf' -ExternalValidation
        @($r.ExternalValidation).Count | Should -BeGreaterThan 3
    }
}

Describe 'PDF Hexmator v2.0.0 - bulk workflow' {
    It 'processes a folder, groups exact duplicates, and writes consolidated outputs and manifest' {
        $source = Join-Path $TestDrive 'bulk-input'
        New-Item -ItemType Directory -Path $source | Out-Null
        Copy-Item (Join-Path $Fixtures 'normal.pdf') (Join-Path $source 'a.pdf')
        Copy-Item (Join-Path $Fixtures 'normal-duplicate.pdf') (Join-Path $source 'b.pdf')
        Copy-Item (Join-Path $Fixtures 'incremental.pdf') (Join-Path $source 'c.pdf')

        $out = Join-Path $TestDrive 'bulk-output'
        $case = & $Script -Path $source -OutputDirectory $out -CaseName 'Pester Bulk Test'

        $case.Version | Should -Be '2.0.0'
        $case.Statistics.TotalDocuments | Should -Be 3
        $case.Statistics.DuplicateSets | Should -Be 1
        Test-Path (Join-Path $out 'PDF-Forensic-Bulk-Report.html') | Should -BeTrue
        Test-Path (Join-Path $out 'PDF-Forensic-Bulk-Summary.csv') | Should -BeTrue
        Test-Path (Join-Path $out 'PDF-Forensic-Bulk-Summary.json') | Should -BeTrue
        Test-Path (Join-Path $out 'PDFHexmator-Case-Manifest.json') | Should -BeTrue
        Test-Path (Join-Path $out 'SHA256SUMS.txt') | Should -BeTrue
    }
}
