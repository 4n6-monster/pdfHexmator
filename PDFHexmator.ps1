<#
.SYNOPSIS
    Bulk-capable PDF forensic triage for structural evidence of incremental updates,
    linearization, malformed structure, metadata history, signatures, appended data,
    duplicate files, and related indicators.

.DESCRIPTION
    PDFHexmator.ps1 can analyze:
      - one PDF
      - multiple explicitly named PDFs
      - one or more folders containing hundreds or thousands of PDFs
      - optionally, all PDF files in nested subdirectories

    Analysis is read-only. In bulk mode PDF Hexmator first calculates SHA-256 for every
    discovered PDF, groups byte-identical files, and performs deep PDF analysis only once
    per unique hash. Every original source path remains represented in the report beneath
    its hash group. A malformed or unsupported unique PDF is recorded as an error without
    stopping the remainder of the scan.

    Bulk output includes:
      - searchable/sortable self-contained HTML case report
      - CSV summary for spreadsheet/filtering workflows
      - JSON case summary
      - hash-first SHA-256 de-duplication before deep PDF analysis
      - nested identical-file groups in the consolidated report
      - complete source-file inventory mapped to each hash group
      - optional per-unique-document detailed HTML/JSON reports
      - optional carving of recoverable logical revisions
      - object-level revision diffing for redefined indirect objects
      - a forensic case manifest and SHA-256 output inventory
      - optional corroboration with qpdf, ExifTool, pdfsig, and pdfid.py

    The analyzer is linearization-aware. Normal Fast Web View bootstrap EOF/startxref
    structures are not automatically treated as incremental edits.

.PARAMETER Path
    One or more PDF files, directories, or wildcard paths.

.PARAMETER Recurse
    When a directory is supplied, include PDFs in all nested subdirectories.

.PARAMETER OutputDirectory
    Output directory. In bulk mode the default is PDF_Bulk_Forensics_<timestamp>.
    For a single PDF the historical per-file output naming is retained.

.PARAMETER DetailedReports
    In bulk mode, generate one full HTML/JSON report for each unique SHA-256 hash group.
    Byte-identical copies share the representative file's analysis and do not create redundant reports.

.PARAMETER ExtractRevisions
    Carve recoverable logical PDF revisions. Linearization-only bootstrap sections are
    excluded from revision carving.

.PARAMETER CaseName
    Friendly case/report title for the consolidated HTML report.

.PARAMETER NoHtml
    Disable HTML output.

.PARAMETER NoJson
    Disable JSON output.

.PARAMETER NoCsv
    Disable both the hash-group summary CSV and source-file inventory CSV in bulk mode.

.PARAMETER StopOnError
    Stop the bulk scan at the first hash or unique-document analysis error. By default,
    errors are logged in the master report and processing continues.

.PARAMETER ExternalValidation
    When enabled, attempt corroborating checks with installed external utilities such as
    qpdf, ExifTool, pdfsig, and Didier Stevens' pdfid.py. Missing tools are reported but
    do not stop analysis.

.PARAMETER ExternalToolsDirectory
    Optional directory containing external validation tools. PATH discovery is also used.

.PARAMETER NoManifest
    Disable generation of the forensic case manifest and SHA256SUMS.txt output inventory.

.EXAMPLE
    .\PDFHexmator.ps1 -Path 'C:\Evidence\document.pdf'

.EXAMPLE
    .\PDFHexmator.ps1 -Path 'C:\Evidence\PDFs' -OutputDirectory 'D:\Case123\PDF-Triage'

.EXAMPLE
    .\PDFHexmator.ps1 -Path 'C:\Evidence\PDFs' -Recurse -DetailedReports -CaseName 'Case 123 PDF Review'

.EXAMPLE
    .\PDFHexmator.ps1 -Path 'C:\Set1','D:\Set2','E:\loose.pdf' -Recurse -ExtractRevisions

.EXAMPLE
    .\PDFHexmator.ps1 -Path 'C:\Evidence' -Recurse -DetailedReports -ExtractRevisions -ExternalValidation -CaseName 'Case 2026-001'

.NOTES
    Version 2.1.1
    Designed for Windows PowerShell 5.1+ and PowerShell 7+.
    Files are processed sequentially so bulk scans do not hold every PDF in memory at once.
    v2.1 adds hash-first de-duplication so identical PDFs are hashed but deeply analyzed only once.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path,

    [Alias('IncludeSubdirectories')]
    [switch]$Recurse,

    [string]$OutputDirectory,

    [Alias('PerFileReports')]
    [switch]$DetailedReports,

    [switch]$ExtractRevisions,

    [string]$CaseName = 'PDF Hexmator Bulk Forensic Triage',

    [switch]$NoHtml,

    [switch]$NoJson,

    [switch]$NoCsv,

    [switch]$StopOnError,

    [switch]$ExternalValidation,

    [string]$ExternalToolsDirectory,

    [switch]$NoManifest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'


# ----------------------------
# Utility functions
# ----------------------------

function Convert-BytesToHex {
    param([byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant()
}

function Get-HashForBytes {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][ValidateSet('MD5','SHA256')][string]$Algorithm,
        [int]$Offset = 0,
        [int]$Count = -1
    )

    if ($Count -lt 0) { $Count = $Bytes.Length - $Offset }

    $alg = $null
    try {
        if ($Algorithm -eq 'MD5') {
            $alg = [System.Security.Cryptography.MD5]::Create()
        } else {
            $alg = [System.Security.Cryptography.SHA256]::Create()
        }
        $hash = $alg.ComputeHash($Bytes, $Offset, $Count)
        return Convert-BytesToHex -Bytes $hash
    }
    finally {
        if ($null -ne $alg) { $alg.Dispose() }
    }
}

function Get-AllRegexMatches {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [System.Text.RegularExpressions.RegexOptions]$Options = [System.Text.RegularExpressions.RegexOptions]::None
    )

    # IMPORTANT:
    # PowerShell enumerates IEnumerable results written to the pipeline. A .NET
    # MatchCollection with exactly one Match would therefore become a scalar
    # Match object at the caller, and `$result.Count` would fail under StrictMode.
    #
    # The unary comma writes the MatchCollection itself as one pipeline object,
    # preserving its native .Count and indexer behavior for 0, 1, or N matches.
    $collection = [System.Text.RegularExpressions.Regex]::Matches($Text, $Pattern, $Options)
    Write-Output -NoEnumerate $collection
}

function Test-PdfWhitespaceByte {
    param([byte]$Byte)
    return ($Byte -eq 0x00 -or $Byte -eq 0x09 -or $Byte -eq 0x0A -or
            $Byte -eq 0x0C -or $Byte -eq 0x0D -or $Byte -eq 0x20)
}

function Get-RevisionForOffset {
    param(
        [long]$Offset,
        [System.Collections.IList]$RevisionBoundaries
    )
    for ($i = 0; $i -lt $RevisionBoundaries.Count; $i++) {
        if ($Offset -lt [long]$RevisionBoundaries[$i].EndExclusive) {
            if ($RevisionBoundaries[$i].PSObject.Properties['Revision']) {
                return [int]$RevisionBoundaries[$i].Revision
            }
            return ($i + 1)
        }
    }

    if ($RevisionBoundaries.Count -gt 0 -and $RevisionBoundaries[$RevisionBoundaries.Count - 1].PSObject.Properties['Revision']) {
        return ([int]$RevisionBoundaries[$RevisionBoundaries.Count - 1].Revision + 1)
    }
    return ($RevisionBoundaries.Count + 1)
}

function Decode-PdfLiteralString {
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return $Value }

    # Strip surrounding parentheses when present.
    if ($Value.Length -ge 2 -and $Value[0] -eq '(' -and $Value[$Value.Length - 1] -eq ')') {
        $s = $Value.Substring(1, $Value.Length - 2)
    } else {
        $s = $Value
    }

    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $s.Length; $i++) {
        $ch = $s[$i]
        if ($ch -ne '\') {
            [void]$sb.Append($ch)
            continue
        }

        if ($i + 1 -ge $s.Length) {
            [void]$sb.Append('\')
            break
        }

        $i++
        $n = $s[$i]
        switch ($n) {
            'n' { [void]$sb.Append("`n"); continue }
            'r' { [void]$sb.Append("`r"); continue }
            't' { [void]$sb.Append("`t"); continue }
            'b' { [void]$sb.Append([char]8); continue }
            'f' { [void]$sb.Append([char]12); continue }
            '(' { [void]$sb.Append('('); continue }
            ')' { [void]$sb.Append(')'); continue }
            '\' { [void]$sb.Append('\'); continue }
            "`r" {
                if ($i + 1 -lt $s.Length -and $s[$i + 1] -eq "`n") { $i++ }
                continue
            }
            "`n" { continue }
            default {
                if ($n -match '[0-7]') {
                    $oct = [string]$n
                    for ($j = 0; $j -lt 2; $j++) {
                        if ($i + 1 -lt $s.Length -and $s[$i + 1] -match '[0-7]') {
                            $i++
                            $oct += [string]$s[$i]
                        } else {
                            break
                        }
                    }
                    try {
                        [void]$sb.Append([char][Convert]::ToInt32($oct, 8))
                    } catch {
                        [void]$sb.Append($oct)
                    }
                    continue
                }

                # Per PDF escaping rules, an unknown escaped char is treated as the char itself.
                [void]$sb.Append($n)
            }
        }
    }

    return $sb.ToString()
}

function Decode-PdfHexString {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $hex = ($Value -replace '[^0-9A-Fa-f]', '')
    if (($hex.Length % 2) -ne 0) { $hex += '0' }

    try {
        $b = New-Object byte[] ($hex.Length / 2)
        for ($i = 0; $i -lt $b.Length; $i++) {
            $b[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
        }

        if ($b.Length -ge 2 -and $b[0] -eq 0xFE -and $b[1] -eq 0xFF) {
            return [System.Text.Encoding]::BigEndianUnicode.GetString($b, 2, $b.Length - 2)
        }
        if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) {
            return [System.Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2)
        }

        return [System.Text.Encoding]::GetEncoding(1252).GetString($b)
    }
    catch {
        return $Value
    }
}

function Convert-PdfDate {
    param([string]$Raw)

    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }

    $s = $Raw.Trim()
    if ($s.StartsWith('D:')) { $s = $s.Substring(2) }

    # PDF date syntax:
    # YYYY [MM [DD [HH [mm [SS]]]]] [OHH'mm']
    #
    # Do NOT use PowerShell's automatic $Matches hashtable here. Windows
    # PowerShell uses case-insensitive dictionary keys, so named regex groups
    # such as "M" (month) and "m" (minute) collide and throw:
    # "Item has already been added."
    $datePattern = '^(?<Year>\d{4})(?<Month>\d{2})?(?<Day>\d{2})?(?<Hour>\d{2})?(?<Minute>\d{2})?(?<Second>\d{2})?(?<TimeZone>Z|[+\-]\d{2}''?\d{2}''?)?'
    $dateMatch = [System.Text.RegularExpressions.Regex]::Match(
        $s,
        $datePattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )

    if (-not $dateMatch.Success) {
        # Some producers write non-standard but parseable dates such as
        # "Tue Nov 11 13:10:21 2008". Preserve them as corroborative metadata.
        $fallback = [System.DateTimeOffset]::MinValue
        if ([System.DateTimeOffset]::TryParse(
            $s,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AllowWhiteSpaces,
            [ref]$fallback
        )) {
            return [pscustomobject]@{
                Parsed = $fallback.ToString('yyyy-MM-dd HH:mm:ss zzz')
                Offset = $fallback.Offset.ToString()
                Utc = $fallback.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss') + 'Z'
            }
        }
        return $null
    }

    try {
        $year = [int]$dateMatch.Groups['Year'].Value
        $month = if ($dateMatch.Groups['Month'].Success) { [int]$dateMatch.Groups['Month'].Value } else { 1 }
        $day = if ($dateMatch.Groups['Day'].Success) { [int]$dateMatch.Groups['Day'].Value } else { 1 }
        $hour = if ($dateMatch.Groups['Hour'].Success) { [int]$dateMatch.Groups['Hour'].Value } else { 0 }
        $minute = if ($dateMatch.Groups['Minute'].Success) { [int]$dateMatch.Groups['Minute'].Value } else { 0 }
        $second = if ($dateMatch.Groups['Second'].Success) { [int]$dateMatch.Groups['Second'].Value } else { 0 }

        $dt = [System.DateTime]::new(
            $year,
            $month,
            $day,
            $hour,
            $minute,
            $second,
            [System.DateTimeKind]::Unspecified
        )

        $tz = if ($dateMatch.Groups['TimeZone'].Success) {
            $dateMatch.Groups['TimeZone'].Value
        } else {
            $null
        }

        if ([string]::IsNullOrWhiteSpace($tz)) {
            return [pscustomobject]@{
                Parsed = $dt.ToString('yyyy-MM-dd HH:mm:ss')
                Offset = $null
                Utc = $null
            }
        }

        if ($tz -eq 'Z') {
            $dto = [System.DateTimeOffset]::new($dt, [System.TimeSpan]::Zero)
        }
        else {
            $clean = $tz -replace "'", ''

            # Expected normalized form is +HHmm or -HHmm.
            if ($clean -notmatch '^[+\-]\d{4}$') {
                return [pscustomobject]@{
                    Parsed = $dt.ToString('yyyy-MM-dd HH:mm:ss')
                    Offset = $tz
                    Utc = $null
                }
            }

            $sign = if ($clean[0] -eq '-') { -1 } else { 1 }
            $tzHour = [int]$clean.Substring(1, 2)
            $tzMinute = [int]$clean.Substring(3, 2)

            # DateTimeOffset supports offsets from -14:00 through +14:00.
            if ($tzHour -gt 14 -or $tzMinute -gt 59 -or ($tzHour -eq 14 -and $tzMinute -ne 0)) {
                return [pscustomobject]@{
                    Parsed = $dt.ToString('yyyy-MM-dd HH:mm:ss')
                    Offset = $tz
                    Utc = $null
                }
            }

            $offsetMinutes = $sign * (($tzHour * 60) + $tzMinute)
            $offset = [System.TimeSpan]::FromMinutes($offsetMinutes)
            $dto = [System.DateTimeOffset]::new($dt, $offset)
        }

        return [pscustomobject]@{
            Parsed = $dto.ToString('yyyy-MM-dd HH:mm:ss zzz')
            Offset = $dto.Offset.ToString()
            Utc = $dto.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss') + 'Z'
        }
    }
    catch {
        # Metadata is corroborative. A malformed date should not terminate the
        # entire forensic triage run; preserve execution and report it as
        # unparseable instead.
        return $null
    }
}

function Get-PdfMetadataOccurrences {
    param(
        [string]$Text,
        [System.Collections.IList]$RevisionBoundaries
    )

    $results = New-Object System.Collections.Generic.List[object]
    $keys = @('Title','Author','Subject','Keywords','Creator','Producer','CreationDate','ModDate','Trapped')

    foreach ($key in $keys) {
        # Literal string (supports common escaped chars but is intentionally conservative).
        $literalPattern = '/' + [Regex]::Escape($key) + '\s*(?<val>\((?:\\.|[^\\)])*\))'
        foreach ($m in (Get-AllRegexMatches -Text $Text -Pattern $literalPattern -Options ([System.Text.RegularExpressions.RegexOptions]::Singleline))) {
            $decoded = Decode-PdfLiteralString -Value $m.Groups['val'].Value
            $parsedDate = $null
            if ($key -eq 'CreationDate' -or $key -eq 'ModDate') {
                $parsedDate = Convert-PdfDate -Raw $decoded
            }

            $results.Add([pscustomobject]@{
                Source = 'InfoDictionary'
                Key = $key
                Value = $decoded
                Raw = $m.Groups['val'].Value
                Offset = [long]$m.Index
                Revision = Get-RevisionForOffset -Offset $m.Index -RevisionBoundaries $RevisionBoundaries
                ParsedDate = $parsedDate
            })
        }

        # Hex string.
        $hexPattern = '/' + [Regex]::Escape($key) + '\s*<(?<val>[0-9A-Fa-f\s]+)>'
        foreach ($m in (Get-AllRegexMatches -Text $Text -Pattern $hexPattern -Options ([System.Text.RegularExpressions.RegexOptions]::Singleline))) {
            $decoded = Decode-PdfHexString -Value $m.Groups['val'].Value
            $parsedDate = $null
            if ($key -eq 'CreationDate' -or $key -eq 'ModDate') {
                $parsedDate = Convert-PdfDate -Raw $decoded
            }

            $results.Add([pscustomobject]@{
                Source = 'InfoDictionary'
                Key = $key
                Value = $decoded
                Raw = '<' + $m.Groups['val'].Value + '>'
                Offset = [long]$m.Index
                Revision = Get-RevisionForOffset -Offset $m.Index -RevisionBoundaries $RevisionBoundaries
                ParsedDate = $parsedDate
            })
        }
    }

    # Common XMP values. XMP can be packetized in streams; lexical recovery is best effort.
    $xmpMap = @{
        'CreateDate'   = '(?is)<xmp:CreateDate\b[^>]*>(?<val>.*?)</xmp:CreateDate>'
        'ModifyDate'   = '(?is)<xmp:ModifyDate\b[^>]*>(?<val>.*?)</xmp:ModifyDate>'
        'MetadataDate' = '(?is)<xmp:MetadataDate\b[^>]*>(?<val>.*?)</xmp:MetadataDate>'
        'CreatorTool'  = '(?is)<xmp:CreatorTool\b[^>]*>(?<val>.*?)</xmp:CreatorTool>'
        'Producer'     = '(?is)<pdf:Producer\b[^>]*>(?<val>.*?)</pdf:Producer>'
        'PDFVersion'   = '(?is)<pdf:PDFVersion\b[^>]*>(?<val>.*?)</pdf:PDFVersion>'
    }

    foreach ($entry in $xmpMap.GetEnumerator()) {
        foreach ($m in (Get-AllRegexMatches -Text $Text -Pattern $entry.Value -Options ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase))) {
            $decoded = [System.Net.WebUtility]::HtmlDecode(($m.Groups['val'].Value -replace '<[^>]+>', '').Trim())
            $parsedDate = $null
            if ($entry.Key -match 'Date$') {
                try {
                    $dto = [DateTimeOffset]::Parse($decoded, [Globalization.CultureInfo]::InvariantCulture)
                    $parsedDate = [pscustomobject]@{
                        Parsed = $dto.ToString('yyyy-MM-dd HH:mm:ss zzz')
                        Offset = $dto.Offset.ToString()
                        Utc = $dto.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss') + 'Z'
                    }
                } catch {
                    $parsedDate = $null
                }
            }

            $results.Add([pscustomobject]@{
                Source = 'XMP'
                Key = $entry.Key
                Value = $decoded
                Raw = $m.Groups['val'].Value
                Offset = [long]$m.Index
                Revision = Get-RevisionForOffset -Offset $m.Index -RevisionBoundaries $RevisionBoundaries
                ParsedDate = $parsedDate
            })
        }
    }

    return $results.ToArray()
}

function Add-Finding {
    param(
        [System.Collections.Generic.List[object]]$List,
        [ValidateSet('HIGH','MEDIUM','LOW','INFO')][string]$Severity,
        [string]$Code,
        [string]$Title,
        [string]$Detail
    )

    $List.Add([pscustomobject]@{
        Severity = $Severity
        Code = $Code
        Title = $Title
        Detail = $Detail
    })
}

function HtmlEncode {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-HtmlTable {
    param(
        [string[]]$Headers,
        [object[]]$Rows
    )

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="table-wrap"><table><thead><tr>')
    foreach ($h in $Headers) {
        [void]$sb.Append('<th>' + (HtmlEncode $h) + '</th>')
    }
    [void]$sb.Append('</tr></thead><tbody>')

    foreach ($row in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($h in $Headers) {
            $value = $row.$h
            [void]$sb.Append('<td>' + (HtmlEncode $value) + '</td>')
        }
        [void]$sb.Append('</tr>')
    }

    if ($Rows.Count -eq 0) {
        [void]$sb.Append('<tr><td colspan="' + $Headers.Count + '"><em>None</em></td></tr>')
    }

    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function Get-SafePropertySum {
    <#
    .SYNOPSIS
        StrictMode-safe numeric property summation.

    .DESCRIPTION
        Windows PowerShell 5.1 can return a Measure-Object result without a
        materialized Sum property when the filtered input is empty. Under
        Set-StrictMode, directly reading .Sum can then throw
        PropertyNotFoundStrict.

        This helper performs the aggregation explicitly and therefore returns
        0 for empty input and a stable Int64 sum for one or more objects.
    #>
    param(
        [AllowNull()]
        [object[]]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Property
    )

    [long]$sum = 0

    foreach ($item in @($InputObject)) {
        if ($null -eq $item) { continue }

        $propertyInfo = $item.PSObject.Properties[$Property]
        if ($null -eq $propertyInfo -or $null -eq $propertyInfo.Value) {
            continue
        }

        try {
            $sum += [long]$propertyInfo.Value
        }
        catch {
            continue
        }
    }

    return $sum
}

function Get-SafeFileName {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [int]$MaxLength = 100
    )

    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $safe = $Name
    foreach ($ch in $invalid) {
        $safe = $safe.Replace([string]$ch, '_')
    }
    $safe = $safe -replace '[\x00-\x1F]', '_'
    $safe = $safe.Trim().TrimEnd([char]'.')
    if ([string]::IsNullOrWhiteSpace($safe)) { $safe = 'document' }
    if ($safe.Length -gt $MaxLength) {
        $safe = $safe.Substring(0, $MaxLength)
    }
    return $safe
}

function Resolve-PdfTargets {
    param(
        [Parameter(Mandatory = $true)][string[]]$InputPath,
        [bool]$Recurse = $false,
        [string]$ExcludeRoot
    )

    $files = New-Object System.Collections.Generic.List[object]
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $excludeFull = $null
    if (-not [string]::IsNullOrWhiteSpace($ExcludeRoot)) {
        try {
            $excludeFull = [System.IO.Path]::GetFullPath($ExcludeRoot).TrimEnd([char[]]@([char]'\',[char]'/'))
        } catch {
            $excludeFull = $null
        }
    }

    foreach ($input in $InputPath) {
        if ([string]::IsNullOrWhiteSpace($input)) { continue }

        $items = @()
        if (Test-Path -LiteralPath $input) {
            $items = @(Get-Item -LiteralPath $input -Force)
        }
        elseif ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($input)) {
            $items = @(Get-Item -Path $input -Force -ErrorAction SilentlyContinue)
        }
        else {
            Write-Warning ("Input path not found: {0}" -f $input)
            continue
        }

        foreach ($item in $items) {
            if ($item.PSIsContainer) {
                $children = if ($Recurse) {
                    @(Get-ChildItem -LiteralPath $item.FullName -File -Recurse -Force -ErrorAction SilentlyContinue)
                } else {
                    @(Get-ChildItem -LiteralPath $item.FullName -File -Force -ErrorAction SilentlyContinue)
                }

                foreach ($child in $children) {
                    if ($child.Extension -ine '.pdf') { continue }

                    $full = [System.IO.Path]::GetFullPath($child.FullName)

                    # Do not ingest the active output tree.
                    if ($excludeFull -and $full.StartsWith($excludeFull + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
                        continue
                    }

                    if ($seen.Add($full)) {
                        $files.Add($child)
                    }
                }
            }
            else {
                if ($item.Extension -ine '.pdf') {
                    Write-Warning ("Skipping non-PDF file: {0}" -f $item.FullName)
                    continue
                }

                $full = [System.IO.Path]::GetFullPath($item.FullName)
                if ($excludeFull -and $full.StartsWith($excludeFull + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
                    continue
                }

                if ($seen.Add($full)) {
                    $files.Add($item)
                }
            }
        }
    }

    return @($files | Sort-Object FullName)
}

function Get-LatestMetadataValue {
    param(
        [object]$Report,
        [string[]]$Keys
    )

    if ($null -eq $Report -or $null -eq $Report.MetadataOccurrences) { return $null }

    $matches = @(
        $Report.MetadataOccurrences |
            Where-Object { $_.Key -in $Keys -and -not [string]::IsNullOrWhiteSpace([string]$_.Value) } |
            Sort-Object Offset
    )

    if ($matches.Count -eq 0) { return $null }
    $m = $matches[$matches.Count - 1]

    if ($m.ParsedDate -and $m.ParsedDate.Parsed) {
        return [string]$m.ParsedDate.Parsed
    }
    return [string]$m.Value
}

function Get-FeatureCount {
    param(
        [object]$Report,
        [string]$FeatureName
    )
    $row = @($Report.Features | Where-Object { $_.Feature -eq $FeatureName } | Select-Object -First 1)
    if ($row.Count -eq 0) { return 0 }
    return [int]$row[0].Count
}

function Convert-AnalysisToBulkSummary {
    param(
        [Parameter(Mandatory = $true)][object]$Report,
        [Parameter(Mandatory = $true)][int]$Index,
        [string]$DetailHtmlRelative,
        [string]$DetailJsonRelative
    )

    $high = @($Report.Findings | Where-Object { $_.Severity -eq 'HIGH' }).Count
    $medium = @($Report.Findings | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
    $low = @($Report.Findings | Where-Object { $_.Severity -eq 'LOW' }).Count
    $info = @($Report.Findings | Where-Object { $_.Severity -eq 'INFO' }).Count

    $activeNames = @('JavaScript','OpenAction','AdditionalActions','LaunchAction','EmbeddedFile','RichMedia')
    $activeTotal = 0
    foreach ($n in $activeNames) {
        $activeTotal += Get-FeatureCount -Report $Report -FeatureName $n
    }

    return [pscustomobject]@{
        Index = $Index
        Status = 'Complete'
        FileName = [string]$Report.File.Name
        FullPath = [string]$Report.File.Path
        Directory = [System.IO.Path]::GetDirectoryName([string]$Report.File.Path)
        SizeBytes = [long]$Report.File.SizeBytes
        SHA256 = [string]$Report.File.SHA256
        MD5 = [string]$Report.File.MD5
        PdfVersion = [string]$Report.Structure.PdfVersion
        Assessment = [string]$Report.Assessment.Result
        AssessmentDetail = [string]$Report.Assessment.Detail
        Linearized = [bool]$Report.Linearization.Detected
        LinearizationLengthMatch = [bool]$Report.Linearization.DeclaredLengthMatchesCurrent
        LogicalRevisions = [int]$Report.Structure.LogicalRevisionCount
        PhysicalEofMarkers = [int]$Report.Structure.EofCount
        StartXrefCount = [int]$Report.Structure.StartXrefCount
        ForwardPrev = [int]$Report.Structure.ForwardPrevCount
        BackwardPrev = [int]$Report.Structure.BackwardPrevCount
        RedefinedObjects = @($Report.RepeatedObjects).Count
        ChangedObjectDefinitions = [int]$Report.ChangedObjectDefinitions
        SignatureByteRanges = [int]$Report.Signatures.ByteRangeCount
        ExternalToolsAvailable = @($Report.ExternalValidation | Where-Object { $_.Available }).Count
        ExternalToolFailures = @($Report.ExternalValidation | Where-Object { $_.Available -and -not $_.Success }).Count
        ActiveContentIndicators = $activeTotal
        HighFindings = $high
        MediumFindings = $medium
        LowFindings = $low
        InfoFindings = $info
        Producer = Get-LatestMetadataValue -Report $Report -Keys @('Producer')
        Creator = Get-LatestMetadataValue -Report $Report -Keys @('Creator','CreatorTool')
        CreationDate = Get-LatestMetadataValue -Report $Report -Keys @('CreationDate','CreateDate')
        ModificationDate = Get-LatestMetadataValue -Report $Report -Keys @('ModDate','ModifyDate','MetadataDate')
        FileSystemLastWriteTime = [string]$Report.File.FileSystemLastWriteTime
        DuplicateGroup = ''
        DuplicateCount = 1
        DetailHtml = $DetailHtmlRelative
        DetailJson = $DetailJsonRelative
        Error = ''
    }
}

function New-BulkErrorSummary {
    param(
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$File,
        [Parameter(Mandatory = $true)][int]$Index,
        [Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    return [pscustomobject]@{
        Index = $Index
        Status = 'Error'
        FileName = $File.Name
        FullPath = $File.FullName
        Directory = $File.DirectoryName
        SizeBytes = [long]$File.Length
        SHA256 = ''
        MD5 = ''
        PdfVersion = ''
        Assessment = 'ANALYSIS ERROR'
        AssessmentDetail = $ErrorRecord.Exception.Message
        Linearized = $false
        LinearizationLengthMatch = $false
        LogicalRevisions = 0
        PhysicalEofMarkers = 0
        StartXrefCount = 0
        ForwardPrev = 0
        BackwardPrev = 0
        RedefinedObjects = 0
        ChangedObjectDefinitions = 0
        SignatureByteRanges = 0
        ExternalToolsAvailable = 0
        ExternalToolFailures = 0
        ActiveContentIndicators = 0
        HighFindings = 0
        MediumFindings = 0
        LowFindings = 0
        InfoFindings = 0
        Producer = ''
        Creator = ''
        CreationDate = ''
        ModificationDate = ''
        FileSystemLastWriteTime = $File.LastWriteTime.ToString('o')
        DuplicateGroup = ''
        DuplicateCount = 1
        DetailHtml = ''
        DetailJson = ''
        Error = $ErrorRecord.Exception.Message
    }
}

function Set-DuplicateGroups {
    param([object[]]$Documents)

    $dupId = 0
    $groups = @(
        $Documents |
            Where-Object { $_.Status -eq 'Complete' -and -not [string]::IsNullOrWhiteSpace($_.SHA256) } |
            Group-Object SHA256 |
            Where-Object { $_.Count -gt 1 } |
            Sort-Object Count -Descending
    )

    foreach ($group in $groups) {
        $dupId++
        $label = 'DUP-{0:D4}' -f $dupId
        foreach ($doc in $group.Group) {
            $doc.DuplicateGroup = $label
            $doc.DuplicateCount = $group.Count
        }
    }

    return $groups.Count
}

function Get-PdfHashInventory {
    param(
        [Parameter(Mandatory = $true)][object[]]$Files
    )

    $records = New-Object System.Collections.Generic.List[object]
    $total = $Files.Count

    for ($i = 0; $i -lt $total; $i++) {
        $file = $Files[$i]
        $index = $i + 1
        $pct = if ($total -gt 0) { [int](($index / [double]$total) * 100) } else { 100 }

        Write-Progress -Activity 'PDF Hexmator - Phase 1 of 2: SHA-256 inventory' `
            -Status ("[{0:N0}/{1:N0}] {2}" -f $index, $total, $file.Name) `
            -PercentComplete $pct

        $hash = $null
        $status = 'Hashed'
        $errorText = ''
        try {
            $hash = Get-FileSha256 -LiteralPath $file.FullName
            if ([string]::IsNullOrWhiteSpace($hash)) {
                throw 'SHA-256 calculation returned no value.'
            }
        }
        catch {
            $status = 'HashError'
            $errorText = $_.Exception.Message
        }

        $records.Add([pscustomobject]@{
            Index = $index
            Status = $status
            FileName = $file.Name
            FullPath = $file.FullName
            Directory = $file.DirectoryName
            SizeBytes = [long]$file.Length
            FileSystemLastWriteTime = $file.LastWriteTime.ToString('o')
            SHA256 = $hash
            HashGroup = ''
            GroupSize = 0
            RepresentativeFullPath = ''
            IsRepresentative = $false
            Assessment = ''
            Error = $errorText
        })
    }

    Write-Progress -Activity 'PDF Hexmator - Phase 1 of 2: SHA-256 inventory' -Completed
    return $records.ToArray()
}

function New-PdfHashGroups {
    param(
        [Parameter(Mandatory = $true)][object[]]$Inventory
    )

    $valid = @($Inventory | Where-Object { $_.Status -eq 'Hashed' -and -not [string]::IsNullOrWhiteSpace($_.SHA256) })
    $rawGroups = @(
        $valid |
            Group-Object SHA256 |
            Sort-Object @{ Expression = { ($_.Group | Measure-Object -Property Index -Minimum).Minimum }; Ascending = $true }
    )

    $groups = New-Object System.Collections.Generic.List[object]
    $groupIndex = 0

    foreach ($raw in $rawGroups) {
        $groupIndex++
        $groupId = 'HASH-{0:D6}' -f $groupIndex
        $members = @($raw.Group | Sort-Object Index)
        $representative = $members[0]

        foreach ($member in $members) {
            $member.HashGroup = $groupId
            $member.GroupSize = $members.Count
            $member.RepresentativeFullPath = $representative.FullPath
            $member.IsRepresentative = ($member.FullPath -eq $representative.FullPath)
        }

        $groups.Add([pscustomobject]@{
            GroupIndex = $groupIndex
            HashGroup = $groupId
            SHA256 = [string]$raw.Name
            FileCount = $members.Count
            DuplicateCopies = [Math]::Max(0, $members.Count - 1)
            IsDuplicateSet = ($members.Count -gt 1)
            Representative = $representative
            Files = $members
        })
    }

    return $groups.ToArray()
}

function Convert-AnalysisToHashGroupSummary {
    param(
        [Parameter(Mandatory = $true)][object]$HashGroup,
        [Parameter(Mandatory = $true)][object]$Report,
        [string]$DetailHtmlRelative,
        [string]$DetailJsonRelative
    )

    $base = Convert-AnalysisToBulkSummary `
        -Report $Report `
        -Index ([int]$HashGroup.GroupIndex) `
        -DetailHtmlRelative $DetailHtmlRelative `
        -DetailJsonRelative $DetailJsonRelative

    $memberPaths = @($HashGroup.Files | ForEach-Object { $_.FullPath })

    return [pscustomobject]@{
        Index = [int]$HashGroup.GroupIndex
        HashGroup = [string]$HashGroup.HashGroup
        Status = [string]$base.Status
        SHA256 = [string]$HashGroup.SHA256
        FileCount = [int]$HashGroup.FileCount
        DuplicateCopies = [int]$HashGroup.DuplicateCopies
        IsDuplicateSet = [bool]$HashGroup.IsDuplicateSet
        RepresentativeFileName = [string]$HashGroup.Representative.FileName
        RepresentativeFullPath = [string]$HashGroup.Representative.FullPath
        RepresentativeDirectory = [string]$HashGroup.Representative.Directory
        FileName = [string]$HashGroup.Representative.FileName
        FullPath = [string]$HashGroup.Representative.FullPath
        Directory = [string]$HashGroup.Representative.Directory
        SizeBytes = [long]$base.SizeBytes
        MD5 = [string]$base.MD5
        PdfVersion = [string]$base.PdfVersion
        Assessment = [string]$base.Assessment
        AssessmentDetail = [string]$base.AssessmentDetail
        Linearized = [bool]$base.Linearized
        LinearizationLengthMatch = [bool]$base.LinearizationLengthMatch
        LogicalRevisions = [int]$base.LogicalRevisions
        PhysicalEofMarkers = [int]$base.PhysicalEofMarkers
        StartXrefCount = [int]$base.StartXrefCount
        ForwardPrev = [int]$base.ForwardPrev
        BackwardPrev = [int]$base.BackwardPrev
        RedefinedObjects = [int]$base.RedefinedObjects
        ChangedObjectDefinitions = [int]$base.ChangedObjectDefinitions
        SignatureByteRanges = [int]$base.SignatureByteRanges
        ExternalToolsAvailable = [int]$base.ExternalToolsAvailable
        ExternalToolFailures = [int]$base.ExternalToolFailures
        ActiveContentIndicators = [int]$base.ActiveContentIndicators
        HighFindings = [int]$base.HighFindings
        MediumFindings = [int]$base.MediumFindings
        LowFindings = [int]$base.LowFindings
        InfoFindings = [int]$base.InfoFindings
        Producer = [string]$base.Producer
        Creator = [string]$base.Creator
        CreationDate = [string]$base.CreationDate
        ModificationDate = [string]$base.ModificationDate
        FileSystemLastWriteTime = [string]$HashGroup.Representative.FileSystemLastWriteTime
        MemberPaths = ($memberPaths -join ' | ')
        Files = @($HashGroup.Files)
        DetailHtml = $DetailHtmlRelative
        DetailJson = $DetailJsonRelative
        Error = ''
    }
}

function New-HashGroupErrorSummary {
    param(
        [Parameter(Mandatory = $true)][object]$HashGroup,
        [Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $memberPaths = @($HashGroup.Files | ForEach-Object { $_.FullPath })
    return [pscustomobject]@{
        Index = [int]$HashGroup.GroupIndex
        HashGroup = [string]$HashGroup.HashGroup
        Status = 'Error'
        SHA256 = [string]$HashGroup.SHA256
        FileCount = [int]$HashGroup.FileCount
        DuplicateCopies = [int]$HashGroup.DuplicateCopies
        IsDuplicateSet = [bool]$HashGroup.IsDuplicateSet
        RepresentativeFileName = [string]$HashGroup.Representative.FileName
        RepresentativeFullPath = [string]$HashGroup.Representative.FullPath
        RepresentativeDirectory = [string]$HashGroup.Representative.Directory
        FileName = [string]$HashGroup.Representative.FileName
        FullPath = [string]$HashGroup.Representative.FullPath
        Directory = [string]$HashGroup.Representative.Directory
        SizeBytes = [long]$HashGroup.Representative.SizeBytes
        MD5 = ''
        PdfVersion = ''
        Assessment = 'ANALYSIS ERROR'
        AssessmentDetail = $ErrorRecord.Exception.Message
        Linearized = $false
        LinearizationLengthMatch = $false
        LogicalRevisions = 0
        PhysicalEofMarkers = 0
        StartXrefCount = 0
        ForwardPrev = 0
        BackwardPrev = 0
        RedefinedObjects = 0
        ChangedObjectDefinitions = 0
        SignatureByteRanges = 0
        ExternalToolsAvailable = 0
        ExternalToolFailures = 0
        ActiveContentIndicators = 0
        HighFindings = 0
        MediumFindings = 0
        LowFindings = 0
        InfoFindings = 0
        Producer = ''
        Creator = ''
        CreationDate = ''
        ModificationDate = ''
        FileSystemLastWriteTime = [string]$HashGroup.Representative.FileSystemLastWriteTime
        MemberPaths = ($memberPaths -join ' | ')
        Files = @($HashGroup.Files)
        DetailHtml = ''
        DetailJson = ''
        Error = $ErrorRecord.Exception.Message
    }
}

function New-BulkHtmlReport {
    param(
        [Parameter(Mandatory = $true)][object]$CaseReport,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $groups = @($CaseReport.HashGroups)
    $hashErrors = @($CaseReport.HashErrors)
    $stats = $CaseReport.Statistics
    $rows = New-Object System.Text.StringBuilder

    foreach ($g in $groups) {
        $assessmentClass = 'normal'
        if ($g.Status -eq 'Error') { $assessmentClass = 'error' }
        elseif ($g.Assessment -like 'STRONG EVIDENCE*') { $assessmentClass = 'high' }
        elseif ($g.Assessment -like 'INDICATORS*' -or $g.Assessment -like '*REVIEW*') { $assessmentClass = 'review' }
        elseif ($g.Linearized) { $assessmentClass = 'linearized' }

        $detailLink = ''
        if (-not [string]::IsNullOrWhiteSpace($g.DetailHtml)) {
            $href = [System.Uri]::EscapeUriString(($g.DetailHtml -replace '\\','/'))
            $detailLink = '<a class="detail-link" href="' + (HtmlEncode $href) + '">View analysis</a>'
        }

        $memberHtml = New-Object System.Text.StringBuilder
        [void]$memberHtml.Append('<details class="members"><summary>')
        if ($g.FileCount -gt 1) {
            [void]$memberHtml.Append((HtmlEncode ("{0} identical PDFs - {1} duplicate cop{2}" -f $g.FileCount, $g.DuplicateCopies, $(if ($g.DuplicateCopies -eq 1) {'y'} else {'ies'}))))
        }
        else {
            [void]$memberHtml.Append('1 source PDF')
        }
        [void]$memberHtml.Append('</summary><div class="member-list">')
        foreach ($m in @($g.Files)) {
            $role = if ($m.IsRepresentative) { '<span class="rep">ANALYZED</span>' } else { '<span class="dup">IDENTICAL</span>' }
            [void]$memberHtml.Append('<div class="member">' + $role + '<code>' + (HtmlEncode $m.FullPath) + '</code></div>')
        }
        [void]$memberHtml.Append('</div></details>')

        $sizeMB = [Math]::Round(([double]$g.SizeBytes / 1MB), 2)
        $prevText = "{0}/{1}" -f $g.BackwardPrev, $g.ForwardPrev
        $findText = "{0}/{1}" -f $g.HighFindings, $g.MediumFindings
        $shortHash = if ($g.SHA256.Length -gt 16) { $g.SHA256.Substring(0,16) + '…' } else { $g.SHA256 }

        [void]$rows.Append(
            '<tr class="' + $assessmentClass + '"' +
            ' data-status="' + (HtmlEncode $g.Status) + '"' +
            ' data-assessment="' + (HtmlEncode $assessmentClass) + '"' +
            ' data-linearized="' + ($(if ($g.Linearized) {'1'} else {'0'})) + '"' +
            ' data-duplicate="' + ($(if ($g.FileCount -gt 1) {'1'} else {'0'})) + '"' +
            ' data-high="' + $g.HighFindings + '">' +
            '<td class="num">' + $g.Index + '</td>' +
            '<td><strong>' + (HtmlEncode $g.HashGroup) + '</strong><div class="hash" title="' + (HtmlEncode $g.SHA256) + '">' + (HtmlEncode $shortHash) + '</div></td>' +
            '<td class="file"><strong>' + (HtmlEncode $g.RepresentativeFileName) + '</strong><div class="path">' + (HtmlEncode $g.RepresentativeDirectory) + '</div>' + $memberHtml.ToString() + '</td>' +
            '<td class="num" data-sort="' + $g.FileCount + '">' + $g.FileCount + '</td>' +
            '<td class="num" data-sort="' + $g.SizeBytes + '">' + $sizeMB + '</td>' +
            '<td><span class="badge ' + $assessmentClass + '">' + (HtmlEncode $g.Assessment) + '</span></td>' +
            '<td>' + (HtmlEncode $g.PdfVersion) + '</td>' +
            '<td class="center">' + ($(if ($g.Linearized) {'Yes'} else {'No'})) + '</td>' +
            '<td class="num">' + $g.LogicalRevisions + '</td>' +
            '<td class="num">' + $g.PhysicalEofMarkers + '</td>' +
            '<td class="center" title="Backward / Forward">' + $prevText + '</td>' +
            '<td class="num">' + $g.ChangedObjectDefinitions + '</td>' +
            '<td class="num">' + $g.SignatureByteRanges + '</td>' +
            '<td class="num">' + $g.ActiveContentIndicators + '</td>' +
            '<td class="center" title="High / Medium">' + $findText + '</td>' +
            '<td>' + (HtmlEncode $g.Producer) + '</td>' +
            '<td>' + (HtmlEncode $g.ModificationDate) + '</td>' +
            '<td>' + $detailLink + '</td>' +
            '</tr>'
        )
    }

    $css = @'
:root{--bg:#eef2f5;--panel:#fff;--text:#16202a;--muted:#65727f;--line:#d9e1e7;--navy:#14283b;--high:#982323;--highbg:#fff0f0;--review:#946000;--reviewbg:#fff8e5;--ok:#176944;--okbg:#edf8f2;--linear:#3d5680;--linearbg:#eef3fb;--err:#7c2733;--errbg:#fdecef}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.4 "Segoe UI",Arial,sans-serif}header{background:var(--navy);color:#fff;padding:24px 30px}header h1{margin:0 0 5px;font-size:24px}header .sub{opacity:.82}main{max-width:1950px;margin:0 auto;padding:20px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px;margin-bottom:18px}.card{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:15px;box-shadow:0 1px 2px rgba(0,0,0,.04)}.metric .value{font-size:26px;font-weight:700;line-height:1.1}.metric .label{color:var(--muted);margin-top:5px}.toolbar{display:flex;flex-wrap:wrap;gap:9px;align-items:center;margin-bottom:12px}.toolbar input,.toolbar select{border:1px solid #c9d3db;border-radius:6px;padding:8px 10px;background:#fff}.toolbar input{min-width:330px;flex:1}.table-wrap{background:#fff;border:1px solid var(--line);border-radius:9px;overflow:auto;max-height:72vh}table{border-collapse:separate;border-spacing:0;width:100%;min-width:1750px}th,td{padding:8px 9px;border-bottom:1px solid #e6ebef;vertical-align:top}th{position:sticky;top:0;z-index:2;background:#eaf0f4;color:#31475b;text-align:left;cursor:pointer;white-space:nowrap}td.num{text-align:right;font-variant-numeric:tabular-nums}td.center{text-align:center}td.file{min-width:340px}.path,.hash{color:var(--muted);font-size:11px;margin-top:2px}.hash{font-family:Consolas,monospace}.badge{display:inline-block;padding:3px 6px;border-radius:5px;font-size:11px;font-weight:700;max-width:270px}.badge.high{background:var(--highbg);color:var(--high)}.badge.review{background:var(--reviewbg);color:var(--review)}.badge.linearized{background:var(--linearbg);color:var(--linear)}.badge.normal{background:var(--okbg);color:var(--ok)}.badge.error{background:var(--errbg);color:var(--err)}tr.high td:first-child{border-left:4px solid var(--high)}tr.review td:first-child{border-left:4px solid var(--review)}tr.error td:first-child{border-left:4px solid var(--err)}.detail-link{font-weight:600;color:#185d91;text-decoration:none}.detail-link:hover{text-decoration:underline}.members{margin-top:7px}.members summary{cursor:pointer;color:#315a78;font-size:12px;font-weight:600}.member-list{margin-top:6px;padding:6px 8px;background:#f7f9fb;border:1px solid #e3e9ee;border-radius:5px;max-height:190px;overflow:auto}.member{display:flex;gap:7px;align-items:flex-start;padding:3px 0}.member code{font-size:11px;word-break:break-all}.rep,.dup{font-size:9px;font-weight:700;border-radius:4px;padding:2px 4px;white-space:nowrap}.rep{background:#e7f6ed;color:#14633d}.dup{background:#eef2f7;color:#596b7a}.section-title{margin:22px 0 9px;font-size:17px}.note{color:var(--muted)}.kv{display:grid;grid-template-columns:230px 1fr;gap:7px 14px}.k{font-weight:600;color:#50606e}.error-list{font-family:Consolas,monospace;font-size:12px}footer{padding:20px 0;color:var(--muted)}.hidden{display:none!important}@media print{.toolbar{display:none}.table-wrap{max-height:none;overflow:visible}th{position:static}body{background:#fff}.card{box-shadow:none}.members[open] .member-list{max-height:none}}
'@

    $js = @'
(function(){
 const q=document.getElementById("q"),status=document.getElementById("status"),classf=document.getElementById("classf"),dup=document.getElementById("dup"),rows=[...document.querySelectorAll("#docs tbody tr")],shown=document.getElementById("shown");
 function apply(){const needle=q.value.toLowerCase().trim(),st=status.value,cl=classf.value,dp=dup.value;let count=0;rows.forEach(r=>{const okQ=!needle||r.innerText.toLowerCase().includes(needle),okS=!st||r.dataset.status===st,okC=!cl||r.dataset.assessment===cl,okD=!dp||(dp==="yes"&&r.dataset.duplicate==="1")||(dp==="no"&&r.dataset.duplicate==="0"),show=okQ&&okS&&okC&&okD;r.classList.toggle("hidden",!show);if(show)count++;});shown.textContent=count.toLocaleString();}
 [q,status,classf,dup].forEach(x=>x.addEventListener("input",apply));
 document.querySelectorAll("#docs th").forEach((th,idx)=>{let asc=true;th.addEventListener("click",()=>{const sorted=rows.slice().sort((a,b)=>{const ac=a.children[idx],bc=b.children[idx],av=ac.dataset.sort!==undefined?Number(ac.dataset.sort):ac.innerText.trim().toLowerCase(),bv=bc.dataset.sort!==undefined?Number(bc.dataset.sort):bc.innerText.trim().toLowerCase();if(typeof av==="number"&&typeof bv==="number")return asc?av-bv:bv-av;return asc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));});const tb=document.querySelector("#docs tbody");sorted.forEach(r=>tb.appendChild(r));asc=!asc;});});apply();
})();
'@

    $title = if ([string]::IsNullOrWhiteSpace($CaseReport.CaseName)) { 'PDF Hexmator Bulk Forensic Triage' } else { $CaseReport.CaseName }
    $html = New-Object System.Text.StringBuilder
    [void]$html.Append('<!doctype html><html><head><meta charset="utf-8"><title>' + (HtmlEncode $title) + '</title><style>' + $css + '</style></head><body>')
    [void]$html.Append('<header><h1>' + (HtmlEncode $title) + '</h1><div class="sub">Hash-first PDF forensic triage · Each unique SHA-256 analyzed once · Generated ' + (HtmlEncode $CaseReport.Generated) + '</div></header><main>')

    [void]$html.Append('<div class="cards">')
    $metrics = @(
        [pscustomobject]@{Label='PDFs discovered';Value=$stats.TotalDocuments},
        [pscustomobject]@{Label='Unique SHA-256';Value=$stats.UniqueHashes},
        [pscustomobject]@{Label='Deep analyses';Value=$stats.DeepAnalysesPerformed},
        [pscustomobject]@{Label='Analyses avoided';Value=$stats.DeepAnalysesSaved},
        [pscustomobject]@{Label='Duplicate sets';Value=$stats.DuplicateSets},
        [pscustomobject]@{Label='Hash errors';Value=$stats.HashErrors},
        [pscustomobject]@{Label='Incremental evidence';Value=$stats.UniqueIncrementalEvidence},
        [pscustomobject]@{Label='Linearized';Value=$stats.UniqueLinearized}
    )
    foreach($m in $metrics){[void]$html.Append('<div class="card metric"><div class="value">'+(HtmlEncode $m.Value)+'</div><div class="label">'+(HtmlEncode $m.Label)+'</div></div>')}
    [void]$html.Append('</div>')

    [void]$html.Append('<div class="card"><div class="kv">')
    [void]$html.Append('<div class="k">Input</div><div>'+(HtmlEncode ($CaseReport.InputPaths -join '; '))+'</div>')
    [void]$html.Append('<div class="k">Hash-first de-duplication</div><div>Enabled — SHA-256 inventory completed before PDF parsing</div>')
    [void]$html.Append('<div class="k">Recursive</div><div>'+(HtmlEncode $CaseReport.Recurse)+'</div>')
    [void]$html.Append('<div class="k">Detailed reports</div><div>'+(HtmlEncode $CaseReport.DetailedReports)+' (one report per unique hash)</div>')
    [void]$html.Append('<div class="k">Extract revisions</div><div>'+(HtmlEncode $CaseReport.ExtractRevisions)+' (representative unique files only)</div>')
    [void]$html.Append('<div class="k">PowerShell</div><div>'+(HtmlEncode $CaseReport.PowerShell)+'</div>')
    [void]$html.Append('</div></div>')

    [void]$html.Append('<h2 class="section-title">Unique PDF hash groups</h2>')
    [void]$html.Append('<div class="toolbar"><input id="q" type="search" placeholder="Search any member path, hash, assessment, producer..."><select id="status"><option value="">All statuses</option><option>Complete</option><option>Error</option></select><select id="classf"><option value="">All assessments</option><option value="high">Strong incremental evidence</option><option value="review">Review / indicators</option><option value="linearized">Linearized</option><option value="normal">Other / no strong history</option><option value="error">Errors</option></select><select id="dup"><option value="">All hash groups</option><option value="yes">Duplicate sets only</option><option value="no">Unique-only files</option></select><span class="note">Showing <strong id="shown">'+$groups.Count+'</strong> of '+$groups.Count+' unique hash groups</span></div>')
    [void]$html.Append('<div class="table-wrap"><table id="docs"><thead><tr><th>#</th><th>Hash group</th><th>Representative / identical files</th><th>Files</th><th>MB</th><th>Assessment</th><th>PDF</th><th>Linearized</th><th>Logical Rev.</th><th>EOF</th><th>Prev B/F</th><th>Changed Obj.</th><th>Signatures</th><th>Active</th><th>H/M</th><th>Producer</th><th>Modification Date</th><th>Detail</th></tr></thead><tbody>')
    [void]$html.Append($rows.ToString())
    [void]$html.Append('</tbody></table></div>')

    if ($hashErrors.Count -gt 0) {
        [void]$html.Append('<h2 class="section-title">Hashing errors</h2><div class="card error-list">')
        foreach($e in $hashErrors){[void]$html.Append('<div><strong>'+(HtmlEncode $e.FileName)+'</strong> — '+(HtmlEncode $e.FullPath)+' — '+(HtmlEncode $e.Error)+'</div>')}
        [void]$html.Append('</div>')
    }

    [void]$html.Append('<h2 class="section-title">Interpretation notes</h2><div class="card"><ul>')
    [void]$html.Append('<li>Every discovered PDF is hashed first. Byte-identical files share one SHA-256 group and only the representative file receives deep structural analysis.</li>')
    [void]$html.Append('<li>Nested member paths preserve the location of every identical source PDF without duplicating forensic findings.</li>')
    [void]$html.Append('<li>Incremental-update structures establish multiple physical saved states; they do not establish malicious or improper editing.</li>')
    [void]$html.Append('<li>Recognized linearization-only EOF/startxref structures are excluded from logical revision scoring.</li>')
    [void]$html.Append('<li>Metadata is corroborative only. Signature structures are detected but cryptographic trust is not independently established.</li>')
    [void]$html.Append('</ul></div>')
    [void]$html.Append('<footer>Generated by PDF Hexmator v2.1.1</footer><script>'+$js+'</script></main></body></html>')
    [System.IO.File]::WriteAllText($OutputPath,$html.ToString(),[System.Text.UTF8Encoding]::new($false))
}


function Get-CommandLineText {
    try {
        return [Environment]::CommandLine
    }
    catch {
        return ($MyInvocation.Line -as [string])
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) { return $null }
    try {
        return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToUpperInvariant()
    }
    catch {
        $b = [System.IO.File]::ReadAllBytes($LiteralPath)
        return Get-HashForBytes -Bytes $b -Algorithm SHA256
    }
}

function Resolve-ExternalTool {
    param(
        [Parameter(Mandatory = $true)][string[]]$Names,
        [string]$ToolsDirectory
    )

    if (-not [string]::IsNullOrWhiteSpace($ToolsDirectory) -and (Test-Path -LiteralPath $ToolsDirectory -PathType Container)) {
        foreach ($name in $Names) {
            $candidate = Join-Path $ToolsDirectory $name
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return (Get-Item -LiteralPath $candidate).FullName
            }
        }
    }

    foreach ($name in $Names) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

function Invoke-ExternalProcessCapture {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [int]$MaxChars = 24000
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Executable
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    # Windows PowerShell 5.1 / .NET Framework does not expose ProcessStartInfo.ArgumentList.
    if ($psi.PSObject.Properties['ArgumentList']) {
        foreach ($arg in $Arguments) { [void]$psi.ArgumentList.Add($arg) }
    }
    else {
        $quoted = @($Arguments | ForEach-Object {
            if ($_ -match '[\s"]') { '"' + ($_ -replace '"','\"') + '"' } else { $_ }
        })
        $psi.Arguments = ($quoted -join ' ')
    }

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    try {
        [void]$proc.Start()
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()
        $combined = (($stdout + [Environment]::NewLine + $stderr).Trim())
        if ($combined.Length -gt $MaxChars) {
            $combined = $combined.Substring(0, $MaxChars) + "`n[output truncated]"
        }
        return [pscustomobject]@{
            ExitCode = $proc.ExitCode
            Output = $combined
        }
    }
    catch {
        return [pscustomobject]@{
            ExitCode = -1
            Output = $_.Exception.Message
        }
    }
    finally {
        $proc.Dispose()
    }
}

function Invoke-PdfExternalValidation {
    param(
        [Parameter(Mandatory = $true)][string]$PdfPath,
        [string]$ToolsDirectory
    )

    $results = New-Object System.Collections.Generic.List[object]

    $toolDefs = @(
        [pscustomobject]@{ Name='qpdf'; Candidates=@('qpdf.exe','qpdf'); Args=@('--check',$PdfPath) },
        [pscustomobject]@{ Name='exiftool'; Candidates=@('exiftool.exe','exiftool'); Args=@('-s','-FileType','-PDFVersion','-Producer','-Creator','-CreateDate','-ModifyDate','-Linearized',$PdfPath) },
        [pscustomobject]@{ Name='pdfsig'; Candidates=@('pdfsig.exe','pdfsig'); Args=@($PdfPath) }
    )

    foreach ($def in $toolDefs) {
        $exe = Resolve-ExternalTool -Names $def.Candidates -ToolsDirectory $ToolsDirectory
        if ($exe) {
            $run = Invoke-ExternalProcessCapture -Executable $exe -Arguments $def.Args
            $results.Add([pscustomobject]@{
                Tool = $def.Name
                Available = $true
                Path = $exe
                ExitCode = $run.ExitCode
                Success = ($run.ExitCode -eq 0)
                Output = $run.Output
            })
        }
        else {
            $results.Add([pscustomobject]@{
                Tool = $def.Name
                Available = $false
                Path = $null
                ExitCode = $null
                Success = $false
                Output = 'Tool not found.'
            })
        }
    }

    $pdfId = Resolve-ExternalTool -Names @('pdfid.py','pdfid') -ToolsDirectory $ToolsDirectory
    if ($pdfId) {
        $python = Resolve-ExternalTool -Names @('python.exe','python3.exe','python3','python','py.exe','py') -ToolsDirectory $null
        if ($pdfId.ToLowerInvariant().EndsWith('.py') -and $python) {
            $run = Invoke-ExternalProcessCapture -Executable $python -Arguments @($pdfId,$PdfPath)
            $results.Add([pscustomobject]@{ Tool='pdfid.py'; Available=$true; Path=$pdfId; ExitCode=$run.ExitCode; Success=($run.ExitCode -eq 0); Output=$run.Output })
        }
        elseif (-not $pdfId.ToLowerInvariant().EndsWith('.py')) {
            $run = Invoke-ExternalProcessCapture -Executable $pdfId -Arguments @($PdfPath)
            $results.Add([pscustomobject]@{ Tool='pdfid.py'; Available=$true; Path=$pdfId; ExitCode=$run.ExitCode; Success=($run.ExitCode -eq 0); Output=$run.Output })
        }
        else {
            $results.Add([pscustomobject]@{ Tool='pdfid.py'; Available=$true; Path=$pdfId; ExitCode=$null; Success=$false; Output='pdfid.py found but no Python interpreter was located.' })
        }
    }
    else {
        $results.Add([pscustomobject]@{ Tool='pdfid.py'; Available=$false; Path=$null; ExitCode=$null; Success=$false; Output='Tool not found.' })
    }

    return $results.ToArray()
}

function Get-GeneratedArtifactInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string[]]$ExcludeNames = @('PDFHexmator-Case-Manifest.json','PDFHexmator-Case-Manifest.csv','SHA256SUMS.txt')
    )
    $items = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return @() }

    foreach ($f in @(Get-ChildItem -LiteralPath $Root -File -Recurse -Force -ErrorAction SilentlyContinue | Sort-Object FullName)) {
        if ($f.Name -in $ExcludeNames) { continue }
        $relative = $f.FullName.Substring($Root.TrimEnd([char[]]@([char]'\',[char]'/')).Length).TrimStart([char[]]@([char]'\',[char]'/'))
        $items.Add([pscustomobject]@{
            RelativePath = $relative
            SizeBytes = [long]$f.Length
            SHA256 = Get-FileSha256 -LiteralPath $f.FullName
        })
    }
    return $items.ToArray()
}

function Write-CaseManifest {
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$CaseName,
        [Parameter(Mandatory = $true)][object[]]$Documents,
        [Parameter(Mandatory = $true)][string[]]$InputPaths,
        [bool]$Recurse,
        [bool]$DetailedReports,
        [bool]$ExtractRevisions,
        [bool]$ExternalValidation,
        [bool]$HashFirstDeduplication = $false,
        [string]$Started,
        [string]$Completed
    )

    $scriptHash = if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) { Get-FileSha256 -LiteralPath $PSCommandPath } else { $null }
    $artifacts = @(Get-GeneratedArtifactInventory -Root $OutputRoot)

    $sourceRows = @($Documents | ForEach-Object {
        $hashGroup = if ($_.PSObject.Properties['HashGroup']) { [string]$_.HashGroup } else { '' }
        $groupSize = if ($_.PSObject.Properties['GroupSize']) { [int]$_.GroupSize } else { 1 }
        $representative = if ($_.PSObject.Properties['RepresentativeFullPath']) { [string]$_.RepresentativeFullPath } else { [string]$_.FullPath }
        $isRepresentative = if ($_.PSObject.Properties['IsRepresentative']) { [bool]$_.IsRepresentative } else { $true }
        $status = if ($_.PSObject.Properties['Status']) { [string]$_.Status } else { 'Complete' }
        $assessment = if ($_.PSObject.Properties['Assessment']) { [string]$_.Assessment } else { '' }
        [pscustomobject]@{
            FileName = $_.FileName
            FullPath = $_.FullPath
            SizeBytes = $_.SizeBytes
            SHA256 = $_.SHA256
            HashGroup = $hashGroup
            GroupSize = $groupSize
            RepresentativeFullPath = $representative
            IsRepresentative = $isRepresentative
            Status = $status
            Assessment = $assessment
        }
    })

    $manifest = [ordered]@{
        Tool = 'PDF Hexmator'
        Script = 'PDFHexmator.ps1'
        Version = '2.1.1'
        ScriptSHA256 = $scriptHash
        CaseName = $CaseName
        Started = $Started
        Completed = $Completed
        CommandLine = Get-CommandLineText
        PowerShell = $PSVersionTable.PSVersion.ToString()
        Host = [ordered]@{
            ComputerName = $env:COMPUTERNAME
            UserName = $env:USERNAME
            OS = [Environment]::OSVersion.VersionString
        }
        Options = [ordered]@{
            InputPaths = @($InputPaths)
            Recurse = $Recurse
            HashFirstDeduplication = $HashFirstDeduplication
            DetailedReports = $DetailedReports
            ExtractRevisions = $ExtractRevisions
            ExternalValidation = $ExternalValidation
        }
        Sources = $sourceRows
        GeneratedArtifacts = $artifacts
    }

    $jsonPath = Join-Path $OutputRoot 'PDFHexmator-Case-Manifest.json'
    $csvPath = Join-Path $OutputRoot 'PDFHexmator-Case-Manifest.csv'
    $sumPath = Join-Path $OutputRoot 'SHA256SUMS.txt'

    [pscustomobject]$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    $sourceRows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    $sumLines = New-Object System.Collections.Generic.List[string]
    if ($scriptHash) { $sumLines.Add(('{0}  {1}' -f $scriptHash, 'PDFHexmator.ps1')) }
    foreach ($a in $artifacts) { $sumLines.Add(('{0}  {1}' -f $a.SHA256, ($a.RelativePath -replace '\\','/'))) }
    $manifestHash = Get-FileSha256 -LiteralPath $jsonPath
    $manifestCsvHash = Get-FileSha256 -LiteralPath $csvPath
    $sumLines.Add(('{0}  {1}' -f $manifestHash, 'PDFHexmator-Case-Manifest.json'))
    $sumLines.Add(('{0}  {1}' -f $manifestCsvHash, 'PDFHexmator-Case-Manifest.csv'))
    $sumLines | Set-Content -LiteralPath $sumPath -Encoding ASCII

    return [pscustomobject]@{ Json=$jsonPath; Csv=$csvPath; Sha256Sums=$sumPath; ArtifactCount=$artifacts.Count }
}

function Invoke-PdfFileAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ResolvedPath,
        [Parameter(Mandatory = $true)][string]$DocumentOutputDirectory,
        [bool]$ExtractRevisions = $false,
        [bool]$WriteJson = $true,
        [bool]$WriteHtml = $true,
        [bool]$Quiet = $false,
        [bool]$RunExternalValidation = $false,
        [string]$ExternalToolsDirectory
    )

    $resolved = [System.IO.Path]::GetFullPath($ResolvedPath)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Input path is not a file: $resolved"
    }

    $file = Get-Item -LiteralPath $resolved
    if ($file.Length -eq 0) {
        throw "Input file is empty."
    }

    $OutputDirectory = [System.IO.Path]::GetFullPath($DocumentOutputDirectory)
    [void](New-Item -ItemType Directory -Path $OutputDirectory -Force)

    $NoJson = -not $WriteJson
    $NoHtml = -not $WriteHtml

    $bytes = [System.IO.File]::ReadAllBytes($resolved)

    # ISO-8859-1 gives a 1:1 byte-to-character mapping, preserving byte offsets for ASCII PDF tokens.
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $text = $latin1.GetString($bytes)

    # ----------------------------
    # Structural token discovery
    # ----------------------------

    $headerMatches = Get-AllRegexMatches -Text $text -Pattern '%PDF-(?<version>\d\.\d)[^\r\n]*'
    $objMatches = Get-AllRegexMatches -Text $text -Pattern '(?m)(?<![A-Za-z0-9])(?<obj>\d+)\s+(?<gen>\d+)\s+obj\b'
    $endObjMatches = Get-AllRegexMatches -Text $text -Pattern '(?m)(?<![A-Za-z])endobj\b'
    $streamMatches = Get-AllRegexMatches -Text $text -Pattern '(?m)(?<![A-Za-z])stream(?:\r\n|\r|\n)'
    $endStreamMatches = Get-AllRegexMatches -Text $text -Pattern '(?m)(?<![A-Za-z])endstream\b'
    $xrefMatches = Get-AllRegexMatches -Text $text -Pattern '(?m)(?<!start)(?<![A-Za-z])xref\b'
    $trailerMatches = Get-AllRegexMatches -Text $text -Pattern '(?m)(?<![A-Za-z])trailer\b'
    $startXrefMatches = Get-AllRegexMatches -Text $text -Pattern '(?ms)(?<![A-Za-z])startxref[\x00\x09\x0A\x0C\x0D\x20]+(?<offset>\d+)'
    $eofMatches = Get-AllRegexMatches -Text $text -Pattern '%%EOF'
    $prevMatches = Get-AllRegexMatches -Text $text -Pattern '/Prev\s+(?<offset>\d+)'
    $xrefStmMatches = Get-AllRegexMatches -Text $text -Pattern '/XRefStm\s+(?<offset>\d+)'
    $xrefStreamMarkers = Get-AllRegexMatches -Text $text -Pattern '/Type\s*/XRef\b'

    # ----------------------------
    # Linearization (Fast Web View) detection
    # ----------------------------
    #
    # IMPORTANT FORENSIC DISTINCTION:
    # A standards-conforming linearized PDF normally contains an early first-page
    # xref/trailer, a dummy "startxref 0", an early %%EOF, and a /Prev entry that
    # points FORWARD to the main xref near the end of the file. Those structures
    # must not be mistaken for chronological incremental-update history.
    #
    # The linearization dictionary is required near the beginning of the file and
    # includes /Linearized plus /L (the file length at the time it was linearized).
    $linearScanLength = [Math]::Min(65536, $bytes.Length)
    $linearHeadText = $latin1.GetString($bytes, 0, $linearScanLength)
    $linearizationMatch = [System.Text.RegularExpressions.Regex]::Match(
        $linearHeadText,
        '(?s)\d+\s+\d+\s+obj\s*<<(?<dict>.*?/Linearized\s+(?<version>\d+(?:\.\d+)?).*?)>>',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )

    $isLinearized = $linearizationMatch.Success
    $linearizationVersion = $null
    $linearizationDeclaredLength = $null
    $linearizationDeclaredLengthMatchesCurrent = $false
    $linearizationDictionaryOffset = -1

    if ($isLinearized) {
        $linearizationDictionaryOffset = [long]$linearizationMatch.Index
        $linearizationVersion = $linearizationMatch.Groups['version'].Value
        $linDict = $linearizationMatch.Groups['dict'].Value
        $linLengthMatch = [System.Text.RegularExpressions.Regex]::Match($linDict, '/L\s+(?<length>\d+)')
        if ($linLengthMatch.Success) {
            $linearizationDeclaredLength = [long]$linLengthMatch.Groups['length'].Value
            $linearizationDeclaredLengthMatchesCurrent = ($linearizationDeclaredLength -eq $bytes.Length)
        }
    }

    # Physical EOF boundaries are structural markers. For a non-linearized PDF they
    # are often revision boundaries; for a linearized PDF the early EOF is part of
    # the Fast Web View layout and is NOT a recoverable prior document revision.
    $physicalEofBoundaries = New-Object System.Collections.Generic.List[object]
    $previousPhysicalEnd = 0
    for ($i = 0; $i -lt $eofMatches.Count; $i++) {
        $end = [long]($eofMatches[$i].Index + $eofMatches[$i].Length)
        while ($end -lt $bytes.Length -and (Test-PdfWhitespaceByte -Byte $bytes[$end])) {
            $end++
        }

        $physicalEofBoundaries.Add([pscustomobject]@{
            PhysicalSection = $i + 1
            EofOffset = [long]$eofMatches[$i].Index
            EndExclusive = $end
            SizeBytes = $end
            DeltaBytes = ($end - $previousPhysicalEnd)
            SHA256 = Get-HashForBytes -Bytes $bytes -Algorithm SHA256 -Offset 0 -Count ([int]$end)
        })
        $previousPhysicalEnd = $end
    }

    # Build logical revision boundaries. A normal linearized PDF consumes its early
    # EOF as part of the initial file layout. /L identifies the complete linearized
    # file length; any complete EOF-delimited material appended after that length is
    # potentially an incremental update.
    $revisionBoundaries = New-Object System.Collections.Generic.List[object]
    $baseBoundaryIndex = -1

    if ($isLinearized -and $physicalEofBoundaries.Count -gt 0) {
        if ($null -ne $linearizationDeclaredLength -and $linearizationDeclaredLength -gt 0) {
            $bestDiff = [long]::MaxValue
            for ($i = 0; $i -lt $physicalEofBoundaries.Count; $i++) {
                $diff = [Math]::Abs([long]$physicalEofBoundaries[$i].EndExclusive - [long]$linearizationDeclaredLength)
                if ($diff -lt $bestDiff) {
                    $bestDiff = $diff
                    $baseBoundaryIndex = $i
                }
            }

            # /L should be exact, but tolerate only trailing-EOL-sized differences.
            if ($bestDiff -gt 16) {
                $baseBoundaryIndex = -1
            }
        }

        # Conservative fallback for recognized linearization: the second physical
        # EOF is normally the end of the complete base linearized document.
        if ($baseBoundaryIndex -lt 0 -and $physicalEofBoundaries.Count -ge 2) {
            $baseBoundaryIndex = 1
        }
    }

    if (-not $isLinearized) {
        $baseBoundaryIndex = 0
    }

    if ($baseBoundaryIndex -ge 0) {
        $logicalRevision = 1
        $previousLogicalEnd = 0
        for ($i = $baseBoundaryIndex; $i -lt $physicalEofBoundaries.Count; $i++) {
            $pb = $physicalEofBoundaries[$i]
            $revisionBoundaries.Add([pscustomobject]@{
                Revision = $logicalRevision
                EofOffset = [long]$pb.EofOffset
                EndExclusive = [long]$pb.EndExclusive
                SizeBytes = [long]$pb.SizeBytes
                DeltaBytes = ([long]$pb.EndExclusive - $previousLogicalEnd)
                SHA256 = $pb.SHA256
                PhysicalSection = $pb.PhysicalSection
            })
            $previousLogicalEnd = [long]$pb.EndExclusive
            $logicalRevision++
        }
    }


    # ----------------------------
    # File/hash/header checks
    # ----------------------------

    $sha256 = Get-HashForBytes -Bytes $bytes -Algorithm SHA256
    $md5 = Get-HashForBytes -Bytes $bytes -Algorithm MD5

    $headerOffset = if ($headerMatches.Count -gt 0) { [long]$headerMatches[0].Index } else { -1 }
    $pdfVersion = if ($headerMatches.Count -gt 0) { $headerMatches[0].Groups['version'].Value } else { $null }

    $nonWhitespaceBeforeHeader = 0
    if ($headerOffset -gt 0) {
        for ($i = 0; $i -lt $headerOffset; $i++) {
            if (-not (Test-PdfWhitespaceByte -Byte $bytes[$i])) {
                $nonWhitespaceBeforeHeader++
            }
        }
    }

    $trailingNonWhitespace = 0
    $trailingStart = $bytes.Length
    if ($eofMatches.Count -gt 0) {
        $trailingStart = [long]($eofMatches[$eofMatches.Count - 1].Index + $eofMatches[$eofMatches.Count - 1].Length)
        for ($i = $trailingStart; $i -lt $bytes.Length; $i++) {
            if (-not (Test-PdfWhitespaceByte -Byte $bytes[$i])) {
                $trailingNonWhitespace++
            }
        }
    }

    # ----------------------------
    # startxref and /Prev validation
    # ----------------------------

    $startXrefChecks = New-Object System.Collections.Generic.List[object]
    foreach ($m in $startXrefMatches) {
        $target = [long]$m.Groups['offset'].Value
        $valid = $false
        $targetType = 'OutOfRange'
        $preview = ''

        if ($isLinearized -and $target -eq 0) {
            # Linearized PDFs use a dummy startxref 0 after the first-page trailer.
            $valid = $true
            $targetType = 'LinearizedDummyStartXref'
            $preview = ''
        }
        elseif ($target -ge 0 -and $target -lt $bytes.Length) {
            $previewLen = [Math]::Min(2048, $bytes.Length - [int]$target)
            $preview = $latin1.GetString($bytes, [int]$target, [int]$previewLen)

            if ($preview -match '^\s*xref\b') {
                $valid = $true
                $targetType = 'ClassicXRef'
            }
            elseif ($preview -match '^\s*\d+\s+\d+\s+obj\b') {
                if ($preview -match '/Type\s*/XRef\b') {
                    $valid = $true
                    $targetType = 'XRefStream'
                } else {
                    $targetType = 'IndirectObject_NotConfirmedXRefStream'
                }
            }
            else {
                $targetType = 'UnexpectedData'
            }
        }

        $startXrefChecks.Add([pscustomobject]@{
            StartXrefOffset = [long]$m.Index
            TargetOffset = $target
            TargetType = $targetType
            ValidTarget = $valid
            Revision = Get-RevisionForOffset -Offset $m.Index -RevisionBoundaries $revisionBoundaries
        })
    }

    $prevChecks = New-Object System.Collections.Generic.List[object]
    foreach ($m in $prevMatches) {
        $target = [long]$m.Groups['offset'].Value
        $valid = $false
        $targetType = 'OutOfRange'

        if ($target -ge 0 -and $target -lt $bytes.Length) {
            $previewLen = [Math]::Min(2048, $bytes.Length - [int]$target)
            $preview = $latin1.GetString($bytes, [int]$target, [int]$previewLen)
            if ($preview -match '^\s*xref\b') {
                $valid = $true
                $targetType = 'ClassicXRef'
            }
            elseif ($preview -match '^\s*\d+\s+\d+\s+obj\b' -and $preview -match '/Type\s*/XRef\b') {
                $valid = $true
                $targetType = 'XRefStream'
            }
            else {
                $targetType = 'UnexpectedData'
            }
        }

        $direction = if ($target -gt [long]$m.Index) { 'Forward' } elseif ($target -lt [long]$m.Index) { 'Backward' } else { 'Self' }

        $prevChecks.Add([pscustomobject]@{
            PrevKeyOffset = [long]$m.Index
            TargetOffset = $target
            Direction = $direction
            TargetType = $targetType
            ValidTarget = $valid
            Revision = Get-RevisionForOffset -Offset $m.Index -RevisionBoundaries $revisionBoundaries
        })
    }

    # ----------------------------
    # Repeated object IDs
    # ----------------------------

    $objectOccurrences = New-Object System.Collections.Generic.List[object]
    foreach ($m in $objMatches) {
        $objectOccurrences.Add([pscustomobject]@{
            Object = [int]$m.Groups['obj'].Value
            Generation = [int]$m.Groups['gen'].Value
            Offset = [long]$m.Index
            Revision = Get-RevisionForOffset -Offset $m.Index -RevisionBoundaries $revisionBoundaries
        })
    }

    $repeatedObjects = New-Object System.Collections.Generic.List[object]
    $groups = @($objectOccurrences | Group-Object { "$($_.Object):$($_.Generation)" })
    foreach ($g in $groups) {
        if ($g.Count -gt 1) {
            $parts = $g.Name.Split(':')
            $offsets = @($g.Group | Sort-Object Offset | ForEach-Object { $_.Offset })
            $revs = @($g.Group | Sort-Object Offset | ForEach-Object { $_.Revision } | Select-Object -Unique)
            $repeatedObjects.Add([pscustomobject]@{
                Object = [int]$parts[0]
                Generation = [int]$parts[1]
                Occurrences = $g.Count
                Revisions = ($revs -join ', ')
                Offsets = ($offsets -join ', ')
            })
        }
    }

    # ----------------------------
    # Object-level revision diffing
    # ----------------------------

    $objectDefinitions = New-Object System.Collections.Generic.List[object]
    foreach ($m in $objMatches) {
        $start = [long]$m.Index
        $endMatch = $null
        foreach ($e in $endObjMatches) {
            if ([long]$e.Index -gt $start) { $endMatch = $e; break }
        }
        if ($null -eq $endMatch) { continue }

        $endExclusive = [long]$endMatch.Index + [long]$endMatch.Length
        $length = $endExclusive - $start
        if ($length -le 0 -or $length -gt [int]::MaxValue) { continue }

        $raw = New-Object byte[] ([int]$length)
        [Array]::Copy($bytes, [int]$start, $raw, 0, [int]$length)
        $objectDefinitions.Add([pscustomobject]@{
            Object = [int]$m.Groups['obj'].Value
            Generation = [int]$m.Groups['gen'].Value
            Offset = $start
            EndOffset = $endExclusive
            Length = $length
            Revision = Get-RevisionForOffset -Offset $start -RevisionBoundaries $revisionBoundaries
            SHA256 = Get-HashForBytes -Bytes $raw -Algorithm SHA256
        })
    }

    $revisionDiffs = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($objectDefinitions | Group-Object { "$($_.Object):$($_.Generation)" })) {
        if ($g.Count -lt 2) { continue }
        $orderedDefs = @($g.Group | Sort-Object Offset)
        for ($di = 1; $di -lt $orderedDefs.Count; $di++) {
            $before = $orderedDefs[$di - 1]
            $after = $orderedDefs[$di]
            $revisionDiffs.Add([pscustomobject]@{
                Object = $after.Object
                Generation = $after.Generation
                FromRevision = $before.Revision
                ToRevision = $after.Revision
                FromOffset = $before.Offset
                ToOffset = $after.Offset
                FromLength = $before.Length
                ToLength = $after.Length
                FromSHA256 = $before.SHA256
                ToSHA256 = $after.SHA256
                Changed = ($before.SHA256 -ne $after.SHA256)
            })
        }
    }
    $changedObjectDiffs = @($revisionDiffs | Where-Object { $_.Changed })

    # ----------------------------
    # Metadata
    # ----------------------------

    $metadataOccurrences = Get-PdfMetadataOccurrences -Text $text -RevisionBoundaries $revisionBoundaries

    $metadataSummary = New-Object System.Collections.Generic.List[object]
    foreach ($grp in @($metadataOccurrences | Group-Object Key)) {
        $unique = @($grp.Group | Select-Object -ExpandProperty Value | Where-Object { $_ -ne '' } | Select-Object -Unique)
        $revPairs = @($grp.Group | Sort-Object Offset | ForEach-Object { "R$($_.Revision): $($_.Value)" })
        $metadataSummary.Add([pscustomobject]@{
            Key = $grp.Name
            UniqueValues = $unique.Count
            Values = ($unique -join ' | ')
            RevisionHistory = ($revPairs -join ' || ')
        })
    }

    # Date consistency (best effort).
    $creationDates = @($metadataOccurrences | Where-Object { $_.Key -in @('CreationDate','CreateDate') -and $null -ne $_.ParsedDate })
    $modDates = @($metadataOccurrences | Where-Object { $_.Key -in @('ModDate','ModifyDate','MetadataDate') -and $null -ne $_.ParsedDate })

    # ----------------------------
    # Signature indicators
    # ----------------------------

    $sigTypeMatches = Get-AllRegexMatches -Text $text -Pattern '/Type\s*/Sig\b'
    $byteRangeMatches = Get-AllRegexMatches -Text $text -Pattern '/ByteRange\s*\[\s*(?<a>\d+)\s+(?<b>\d+)\s+(?<c>\d+)\s+(?<d>\d+)\s*\]'
    $docMdpMatches = Get-AllRegexMatches -Text $text -Pattern '/TransformMethod\s*/DocMDP\b'
    $fieldMdpMatches = Get-AllRegexMatches -Text $text -Pattern '/TransformMethod\s*/FieldMDP\b'

    $signatureRanges = New-Object System.Collections.Generic.List[object]
    foreach ($m in $byteRangeMatches) {
        $a = [long]$m.Groups['a'].Value
        $b = [long]$m.Groups['b'].Value
        $c = [long]$m.Groups['c'].Value
        $d = [long]$m.Groups['d'].Value

        $firstEnd = $a + $b
        $secondEnd = $c + $d
        $rangeValid = ($a -eq 0 -and $b -ge 0 -and $c -ge $firstEnd -and $d -ge 0 -and $secondEnd -le $bytes.Length)
        $bytesAfterSignedRange = if ($secondEnd -le $bytes.Length) { $bytes.Length - $secondEnd } else { -1 }

        $signatureRanges.Add([pscustomobject]@{
            Offset = [long]$m.Index
            Range = "[$a $b $c $d]"
            RangeValid = $rangeValid
            SignedEndOffset = $secondEnd
            BytesAfterSignedRange = $bytesAfterSignedRange
            Revision = Get-RevisionForOffset -Offset $m.Index -RevisionBoundaries $revisionBoundaries
        })
    }

    # ----------------------------
    # Other PDF feature indicators
    # ----------------------------

    $featurePatterns = [ordered]@{
        'Linearized'        = '/Linearized\b'
        'Encrypted'         = '/Encrypt\b'
        'JavaScript'        = '/JavaScript\b|/JS\b'
        'OpenAction'        = '/OpenAction\b'
        'AdditionalActions' = '/AA\b'
        'LaunchAction'      = '/Launch\b'
        'EmbeddedFile'      = '/EmbeddedFile\b'
        'RichMedia'         = '/RichMedia\b'
        'AcroForm'          = '/AcroForm\b'
        'XFA'               = '/XFA\b'
        'ObjStm'            = '/Type\s*/ObjStm\b'
        'XRefStream'        = '/Type\s*/XRef\b'
    }

    $features = New-Object System.Collections.Generic.List[object]
    foreach ($kv in $featurePatterns.GetEnumerator()) {
        $matches = Get-AllRegexMatches -Text $text -Pattern $kv.Value
        $features.Add([pscustomobject]@{
            Feature = $kv.Key
            Count = $matches.Count
        })
    }

    # ----------------------------
    # Optional external corroboration
    # ----------------------------
    $externalValidationResults = @()
    if ($RunExternalValidation) {
        $externalValidationResults = @(Invoke-PdfExternalValidation -PdfPath $resolved -ToolsDirectory $ExternalToolsDirectory)
    }

    # ----------------------------
    # Findings / assessment
    # ----------------------------

    $findings = New-Object System.Collections.Generic.List[object]
    $validPrev = @($prevChecks | Where-Object { $_.ValidTarget })
    $forwardPrev = @($prevChecks | Where-Object { $_.ValidTarget -and $_.Direction -eq 'Forward' })
    $backwardPrev = @($prevChecks | Where-Object { $_.ValidTarget -and $_.Direction -eq 'Backward' })
    $dummyLinearizedStartXref = @($startXrefChecks | Where-Object { $_.TargetType -eq 'LinearizedDummyStartXref' })
    $linearizationPatternConfirmed = (
        $isLinearized -and
        $dummyLinearizedStartXref.Count -gt 0 -and
        $forwardPrev.Count -gt 0
    )
    $logicalRevisionCount = $revisionBoundaries.Count
    $incrementalRevisionCount = [Math]::Max(0, $logicalRevisionCount - 1)

    if ($changedObjectDiffs.Count -gt 0) {
        Add-Finding -List $findings -Severity HIGH -Code 'OBJECT_DEFINITION_CHANGES' -Title 'Redefined object content changed between revisions' -Detail ("Recovered {0} changed object-definition transition(s). Review RevisionDiffs for object numbers, revision numbers, offsets, lengths, and hashes." -f $changedObjectDiffs.Count)
    }

    if ($RunExternalValidation) {
        foreach ($ext in $externalValidationResults) {
            if ($ext.Available -and -not $ext.Success) {
                Add-Finding -List $findings -Severity LOW -Code ('EXTERNAL_' + $ext.Tool.ToUpperInvariant() + '_NONZERO') -Title ("External validator {0} returned a non-zero result" -f $ext.Tool) -Detail ("Exit code: {0}. Review ExternalValidation output; external-tool results are corroborative and do not replace structural analysis." -f $ext.ExitCode)
            }
        }
    }

    if ($headerMatches.Count -eq 0) {
        Add-Finding -List $findings -Severity HIGH -Code 'NO_PDF_HEADER' -Title 'PDF header not found' -Detail 'No %PDF-x.y header was located. The file may be malformed, embedded, encrypted in an outer format, or not actually a PDF.'
    }
    elseif ($headerMatches.Count -gt 1) {
        Add-Finding -List $findings -Severity MEDIUM -Code 'MULTIPLE_PDF_HEADERS' -Title 'Multiple PDF headers found' -Detail ("Found {0} %PDF- headers. This can occur with concatenated/embedded PDFs, malformed files, or polyglot-like content." -f $headerMatches.Count)
    }

    if ($headerOffset -gt 0 -and $nonWhitespaceBeforeHeader -gt 0) {
        Add-Finding -List $findings -Severity MEDIUM -Code 'DATA_BEFORE_HEADER' -Title 'Non-whitespace data exists before the PDF header' -Detail ("{0} non-whitespace byte(s) precede the first PDF header at offset {1}. Review for wrapper/polyglot content." -f $nonWhitespaceBeforeHeader, $headerOffset)
    }

    if ($isLinearized) {
        $lengthState = if ($null -eq $linearizationDeclaredLength) {
            'The /L file-length value was not recovered.'
        } elseif ($linearizationDeclaredLengthMatchesCurrent) {
            ('The linearization /L value ({0}) matches the current file length.' -f $linearizationDeclaredLength)
        } elseif ($linearizationDeclaredLength -lt $bytes.Length) {
            ('The linearization /L value ({0}) is smaller than the current file length ({1}), which can occur when data was appended after linearization.' -f $linearizationDeclaredLength, $bytes.Length)
        } else {
            ('The linearization /L value ({0}) is larger than the current file length ({1}); review for truncation or malformed linearization data.' -f $linearizationDeclaredLength, $bytes.Length)
        }

        Add-Finding -List $findings -Severity INFO -Code 'LINEARIZED_PDF' -Title 'Linearized (Fast Web View) PDF detected' -Detail ("Detected /Linearized {0} near the beginning of the PDF. {1}" -f $linearizationVersion, $lengthState)
    }

    if ($linearizationPatternConfirmed) {
        Add-Finding -List $findings -Severity INFO -Code 'LINEARIZED_XREF_LAYOUT' -Title 'Early EOF/startxref and forward /Prev are consistent with linearization' -Detail ("Detected {0} dummy startxref 0 entr{1} and {2} validated forward /Prev entr{3}. In a linearized PDF this is expected layout, not by itself evidence of a prior saved revision." -f $dummyLinearizedStartXref.Count, $(if ($dummyLinearizedStartXref.Count -eq 1) {'y'} else {'ies'}), $forwardPrev.Count, $(if ($forwardPrev.Count -eq 1) {'y'} else {'ies'}))
    }

    if ($logicalRevisionCount -gt 1) {
        Add-Finding -List $findings -Severity HIGH -Code 'MULTIPLE_LOGICAL_REVISIONS' -Title 'Additional EOF-delimited revision(s) detected beyond the base document' -Detail ("Recovered {0} logical revision(s), including {1} revision(s) after the base PDF structure. Linearization-only bootstrap markers were excluded." -f $logicalRevisionCount, $incrementalRevisionCount)
    }
    elseif (-not $isLinearized -and $eofMatches.Count -gt 1) {
        Add-Finding -List $findings -Severity HIGH -Code 'MULTIPLE_EOF' -Title 'Multiple PDF revision terminators detected' -Detail ("Found {0} %%EOF markers in a non-linearized PDF. This is a strong indicator of incremental saves/revisions, although the revisions may be benign." -f $eofMatches.Count)
    }

    if (-not $isLinearized -and $startXrefMatches.Count -gt 1) {
        Add-Finding -List $findings -Severity HIGH -Code 'MULTIPLE_STARTXREF' -Title 'Multiple startxref sections detected' -Detail ("Found {0} startxref sections in a non-linearized PDF, consistent with multiple revisions/incremental updates." -f $startXrefMatches.Count)
    }

    if ($backwardPrev.Count -gt 0) {
        Add-Finding -List $findings -Severity HIGH -Code 'PREV_CHAIN' -Title 'Backward /Prev revision chain detected' -Detail ("Found {0} validated backward /Prev entr{1}. A backward /Prev link is consistent with an incremental update pointing to an earlier cross-reference section." -f $backwardPrev.Count, $(if ($backwardPrev.Count -eq 1) {'y'} else {'ies'}))
    }

    if ($repeatedObjects.Count -gt 0) {
        Add-Finding -List $findings -Severity HIGH -Code 'REDEFINED_OBJECTS' -Title 'Indirect objects are redefined later in the file' -Detail ("Found {0} object ID(s) with multiple physical definitions. In an incremental PDF, later definitions can supersede earlier versions of the same object." -f $repeatedObjects.Count)
    }

    $badStartXref = @($startXrefChecks | Where-Object { -not $_.ValidTarget })
    if ($badStartXref.Count -gt 0) {
        Add-Finding -List $findings -Severity MEDIUM -Code 'BAD_STARTXREF' -Title 'One or more startxref offsets did not resolve cleanly' -Detail ("{0} of {1} startxref target(s) did not point to a recognizable classic xref table or /Type /XRef stream. The file may be malformed, intentionally unusual, or outside this lexical parser's coverage." -f $badStartXref.Count, $startXrefChecks.Count)
    }

    $badPrev = @($prevChecks | Where-Object { -not $_.ValidTarget })
    if ($badPrev.Count -gt 0) {
        Add-Finding -List $findings -Severity MEDIUM -Code 'BAD_PREV' -Title 'One or more /Prev offsets did not resolve cleanly' -Detail ("{0} /Prev target(s) did not point to a recognizable xref structure." -f $badPrev.Count)
    }

    if ($objMatches.Count -ne $endObjMatches.Count) {
        Add-Finding -List $findings -Severity MEDIUM -Code 'OBJ_MISMATCH' -Title 'obj/endobj count mismatch' -Detail ("Found {0} object declarations and {1} endobj markers." -f $objMatches.Count, $endObjMatches.Count)
    }

    if ($streamMatches.Count -ne $endStreamMatches.Count) {
        Add-Finding -List $findings -Severity MEDIUM -Code 'STREAM_MISMATCH' -Title 'stream/endstream count mismatch' -Detail ("Found {0} stream markers and {1} endstream markers." -f $streamMatches.Count, $endStreamMatches.Count)
    }

    if ($xrefMatches.Count -gt 0 -and $xrefMatches.Count -ne $trailerMatches.Count) {
        Add-Finding -List $findings -Severity MEDIUM -Code 'XREF_TRAILER_MISMATCH' -Title 'Classic xref/trailer count mismatch' -Detail ("Found {0} classic xref token(s) and {1} trailer token(s). Hybrid-reference PDFs and xref streams can legitimately differ, so review the xref stream indicators before treating this as malformed." -f $xrefMatches.Count, $trailerMatches.Count)
    }

    if ($eofMatches.Count -gt 0 -and $startXrefMatches.Count -ne $eofMatches.Count) {
        Add-Finding -List $findings -Severity MEDIUM -Code 'STARTXREF_EOF_MISMATCH' -Title 'startxref/%%EOF count mismatch' -Detail ("Found {0} startxref section(s) and {1} %%EOF marker(s). A mismatch can indicate malformed structure, stray marker bytes, truncation, or unusual/hybrid construction." -f $startXrefMatches.Count, $eofMatches.Count)
    }

    if ($xrefStmMatches.Count -gt 0) {
        Add-Finding -List $findings -Severity INFO -Code 'HYBRID_XREF' -Title '/XRefStm references detected' -Detail ("Found {0} /XRefStm entr{1}, indicating hybrid-reference behavior may be present." -f $xrefStmMatches.Count, $(if ($xrefStmMatches.Count -eq 1) {'y'} else {'ies'}))
    }

    if ($eofMatches.Count -eq 0) {
        Add-Finding -List $findings -Severity HIGH -Code 'NO_EOF' -Title 'No %%EOF marker detected' -Detail 'A conforming PDF should end with an EOF marker. Missing EOF may indicate truncation, corruption, or non-standard structure.'
    }
    elseif ($trailingNonWhitespace -gt 0) {
        Add-Finding -List $findings -Severity HIGH -Code 'DATA_AFTER_FINAL_EOF' -Title 'Non-whitespace data exists after the final %%EOF' -Detail ("Found {0} non-whitespace byte(s) after the final EOF marker. Review for appended payloads, concatenated data, or malformed output." -f $trailingNonWhitespace)
    }

    $multiProducer = @($metadataOccurrences | Where-Object { $_.Key -in @('Producer','Creator','CreatorTool') } | Select-Object -ExpandProperty Value | Where-Object { $_ } | Select-Object -Unique)
    if ($multiProducer.Count -gt 1) {
        Add-Finding -List $findings -Severity LOW -Code 'MULTIPLE_CREATOR_TOOLS' -Title 'Multiple creator/producer values recovered' -Detail ("Recovered {0} distinct Creator/Producer/CreatorTool value(s). Different tools can reflect a processing/editing history, but metadata is not reliable proof by itself." -f $multiProducer.Count)
    }

    if ($creationDates.Count -gt 0 -and $modDates.Count -gt 0) {
        # Compare the latest parseable timestamps when UTC is available; otherwise retain as informational.
        $creationUtc = @()
        foreach ($x in $creationDates) {
            if ($x.ParsedDate.Utc) {
                try { $creationUtc += [datetime]::Parse($x.ParsedDate.Utc.TrimEnd('Z'), [Globalization.CultureInfo]::InvariantCulture) } catch {}
            }
        }
        $modUtc = @()
        foreach ($x in $modDates) {
            if ($x.ParsedDate.Utc) {
                try { $modUtc += [datetime]::Parse($x.ParsedDate.Utc.TrimEnd('Z'), [Globalization.CultureInfo]::InvariantCulture) } catch {}
            }
        }

        if ($creationUtc.Count -gt 0 -and $modUtc.Count -gt 0) {
            $earliestCreation = ($creationUtc | Sort-Object | Select-Object -First 1)
            $latestModification = ($modUtc | Sort-Object | Select-Object -Last 1)

            if ($latestModification -gt $earliestCreation) {
                Add-Finding -List $findings -Severity INFO -Code 'METADATA_MOD_AFTER_CREATE' -Title 'Modification metadata post-dates creation metadata' -Detail ("Latest parseable modification time ({0:u}) is after earliest parseable creation time ({1:u}). This is consistent with a later save, but metadata alone is not proof." -f $latestModification, $earliestCreation)
            }
            elseif ($latestModification -lt $earliestCreation) {
                Add-Finding -List $findings -Severity MEDIUM -Code 'METADATA_TIME_ANOMALY' -Title 'Modification metadata predates creation metadata' -Detail ("Latest parseable modification time ({0:u}) is before earliest parseable creation time ({1:u}). This may reflect stale/forged metadata, timezone issues, or document-processing artifacts." -f $latestModification, $earliestCreation)
            }
        }
    }

    $postSignature = @($signatureRanges | Where-Object { $_.RangeValid -and $_.BytesAfterSignedRange -gt 0 })
    if ($postSignature.Count -gt 0) {
        Add-Finding -List $findings -Severity HIGH -Code 'POST_SIGNATURE_BYTES' -Title 'Bytes exist after a signed ByteRange' -Detail ("At least {0} signature ByteRange(s) end before the physical end of the PDF. This is consistent with data being appended after that signature revision. Cryptographic validation is still required." -f $postSignature.Count)
    }

    if ($sigTypeMatches.Count -gt 0 -or $byteRangeMatches.Count -gt 0) {
        Add-Finding -List $findings -Severity INFO -Code 'SIGNATURE_PRESENT' -Title 'Digital-signature structures detected' -Detail ("Detected {0} /Type /Sig marker(s) and {1} /ByteRange array(s). This script does not validate certificate trust or signature integrity." -f $sigTypeMatches.Count, $byteRangeMatches.Count)
    }

    $activeCounts = @($features | Where-Object { $_.Feature -in @('JavaScript','OpenAction','AdditionalActions','LaunchAction','EmbeddedFile','RichMedia') -and $_.Count -gt 0 })
    if ($activeCounts.Count -gt 0) {
        $desc = ($activeCounts | ForEach-Object { "$($_.Feature)=$($_.Count)" }) -join ', '
        Add-Finding -List $findings -Severity MEDIUM -Code 'ACTIVE_CONTENT' -Title 'Active or embedded-content indicators detected' -Detail ("Lexical indicators: {0}. These do not by themselves prove malicious behavior, but should be reviewed." -f $desc)
    }

    # Overall assessment deliberately avoids claiming more than the structures support.
    $repeatedAcrossLogicalRevisions = @(
        $repeatedObjects | Where-Object {
            $_.Revisions -match ','
        }
    )

    $strongIncrementalEvidence = (
        $logicalRevisionCount -gt 1 -and
        (
            $backwardPrev.Count -gt 0 -or
            $repeatedAcrossLogicalRevisions.Count -gt 0 -or
            $incrementalRevisionCount -gt 0
        )
    )

    if ($isLinearized -and $logicalRevisionCount -eq 1 -and $linearizationPatternConfirmed) {
        if ($linearizationDeclaredLengthMatchesCurrent) {
            $assessment = 'LINEARIZED PDF - NO INCREMENTAL UPDATE ESTABLISHED'
            $assessmentDetail = 'The file has a standards-consistent Fast Web View layout: /Linearized is present, the declared /L matches the current file size, the early startxref value is the expected dummy 0, and the early /Prev points forward to the main cross-reference section. The two physical %%EOF markers are therefore part of the linearized layout and do not establish that the PDF was edited after linearization.'
        }
        else {
            $assessment = 'LINEARIZED PDF - REVIEW FOR POST-LINEARIZATION CHANGES'
            $assessmentDetail = 'The file has a linearized Fast Web View layout. Its early %%EOF/startxref 0/forward /Prev structures are expected and are not themselves evidence of editing. However, the declared linearization length does not cleanly match the current file length, so appended data or structural changes should be reviewed.'
        }
    }
    elseif ($strongIncrementalEvidence) {
        $assessment = 'STRONG EVIDENCE OF INCREMENTAL MODIFICATION / MULTIPLE PDF REVISIONS'
        $assessmentDetail = 'After excluding linearization-only bootstrap structures, the file contains more than one logical PDF revision and corroborating incremental-update structure. This establishes multiple physical saved states but does not establish whether the changes were improper or malicious.'
    }
    elseif ($backwardPrev.Count -gt 0 -or $repeatedAcrossLogicalRevisions.Count -gt 0) {
        $assessment = 'INDICATORS CONSISTENT WITH PDF MODIFICATION'
        $assessmentDetail = 'One or more structures are consistent with incremental editing or post-processing after accounting for linearization. Review the logical revisions and changed objects.'
    }
    elseif ($isLinearized) {
        $assessment = 'LINEARIZED PDF - NO STRONG INCREMENTAL-UPDATE HISTORY IDENTIFIED'
        $assessmentDetail = 'The PDF is linearized. Linearization-specific xref/EOF structures were excluded from modification scoring. No strong additional incremental-update history was recovered by this triage.'
    }
    else {
        $assessment = 'NO INCREMENTAL-UPDATE HISTORY IDENTIFIED BY THIS TRIAGE'
        $assessmentDetail = 'No strong incremental-update structures were recovered. This does NOT prove the document was never edited: a full rewrite, optimization, linearization, print-to-PDF, rasterization, sanitization, or metadata manipulation can remove prior revision evidence.'
    }

    # ----------------------------
    # Revision carving
    # ----------------------------

    $carved = New-Object System.Collections.Generic.List[object]
    if ($ExtractRevisions -and $revisionBoundaries.Count -gt 1) {
        $revisionDir = Join-Path $OutputDirectory 'revisions'
        [void](New-Item -ItemType Directory -Path $revisionDir -Force)

        foreach ($rev in $revisionBoundaries) {
            $name = '{0}.revision-{1:D2}.pdf' -f $file.BaseName, $rev.Revision
            $outPath = Join-Path $revisionDir $name

            $length = [int]$rev.EndExclusive
            $slice = New-Object byte[] $length
            [Array]::Copy($bytes, 0, $slice, 0, $length)
            [System.IO.File]::WriteAllBytes($outPath, $slice)

            $carved.Add([pscustomobject]@{
                Revision = $rev.Revision
                Path = $outPath
                SizeBytes = $length
                SHA256 = $rev.SHA256
            })
        }
    }

    $revisionDiffCsvPath = $null
    if ($revisionDiffs.Count -gt 0 -and ($WriteHtml -or $WriteJson -or $ExtractRevisions)) {
        $revisionDiffCsvPath = Join-Path $OutputDirectory ($file.BaseName + '.revision-object-diff.csv')
        $revisionDiffs.ToArray() | Export-Csv -LiteralPath $revisionDiffCsvPath -NoTypeInformation -Encoding UTF8
    }

    # ----------------------------
    # Build report object
    # ----------------------------

    $report = [ordered]@{
        Tool = [ordered]@{
            Name = 'PDF Hexmator'
            Version = '2.1.1'
            Generated = (Get-Date).ToString('o')
            PowerShell = $PSVersionTable.PSVersion.ToString()
        }
        File = [ordered]@{
            Path = $resolved
            Name = $file.Name
            SizeBytes = $file.Length
            FileSystemCreationTime = $file.CreationTime.ToString('o')
            FileSystemLastWriteTime = $file.LastWriteTime.ToString('o')
            MD5 = $md5
            SHA256 = $sha256
        }
        Assessment = [ordered]@{
            Result = $assessment
            Detail = $assessmentDetail
        }
        Structure = [ordered]@{
            PdfHeaderCount = $headerMatches.Count
            PdfHeaderOffset = $headerOffset
            PdfVersion = $pdfVersion
            NonWhitespaceBytesBeforeHeader = $nonWhitespaceBeforeHeader
            ObjectCount = $objMatches.Count
            EndObjectCount = $endObjMatches.Count
            StreamCount = $streamMatches.Count
            EndStreamCount = $endStreamMatches.Count
            ClassicXrefTokenCount = $xrefMatches.Count
            XrefStreamMarkerCount = $xrefStreamMarkers.Count
            TrailerTokenCount = $trailerMatches.Count
            StartXrefCount = $startXrefMatches.Count
            PrevCount = $prevMatches.Count
            ValidPrevCount = $validPrev.Count
            ForwardPrevCount = $forwardPrev.Count
            BackwardPrevCount = $backwardPrev.Count
            XRefStmCount = $xrefStmMatches.Count
            EofCount = $eofMatches.Count
            LogicalRevisionCount = $logicalRevisionCount
            NonWhitespaceBytesAfterFinalEof = $trailingNonWhitespace
        }
        Linearization = [ordered]@{
            Detected = $isLinearized
            PatternConfirmed = $linearizationPatternConfirmed
            Version = $linearizationVersion
            DictionaryOffset = $linearizationDictionaryOffset
            DeclaredLength = $linearizationDeclaredLength
            CurrentLength = $bytes.Length
            DeclaredLengthMatchesCurrent = $linearizationDeclaredLengthMatchesCurrent
            PhysicalEofCount = $physicalEofBoundaries.Count
            LogicalRevisionCount = $logicalRevisionCount
        }
        PhysicalEofSections = $physicalEofBoundaries.ToArray()
        Revisions = $revisionBoundaries.ToArray()
        StartXrefChecks = $startXrefChecks.ToArray()
        PrevChecks = $prevChecks.ToArray()
        RepeatedObjects = $repeatedObjects.ToArray()
        ObjectDefinitions = $objectDefinitions.ToArray()
        RevisionDiffs = $revisionDiffs.ToArray()
        ChangedObjectDefinitions = $changedObjectDiffs.Count
        RevisionDiffCsv = $revisionDiffCsvPath
        ExternalValidation = @($externalValidationResults)
        MetadataSummary = $metadataSummary.ToArray()
        MetadataOccurrences = [object[]]@($metadataOccurrences)
        Signatures = [ordered]@{
            SigTypeCount = $sigTypeMatches.Count
            ByteRangeCount = $byteRangeMatches.Count
            DocMDPCount = $docMdpMatches.Count
            FieldMDPCount = $fieldMdpMatches.Count
            ByteRanges = $signatureRanges.ToArray()
        }
        Features = $features.ToArray()
        Findings = $findings.ToArray()
        CarvedRevisions = $carved.ToArray()
        Limitations = @(
            'Incremental-update evidence proves multiple physical PDF revisions, not malicious intent.',
            'A full rewrite/optimization can remove earlier revision history.',
            'Metadata can be stale, absent, or intentionally altered.',
            'Compressed object streams can limit lexical object inspection.',
            'Digital signatures require cryptographic validation with a signature-aware tool.'
        )
    }

    # ----------------------------
    # JSON output
    # ----------------------------

    $jsonPath = Join-Path $OutputDirectory ($file.BaseName + '.pdf-forensics.json')
    if (-not $NoJson) {
        $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    }

    # ----------------------------
    # HTML output
    # ----------------------------

    $htmlPath = Join-Path $OutputDirectory ($file.BaseName + '.pdf-forensics.html')
    if (-not $NoHtml) {
        $findingRows = @($findings | ForEach-Object {
            [pscustomobject]@{
                Severity = $_.Severity
                Finding = $_.Title
                Detail = $_.Detail
            }
        })

        $revisionRows = @($revisionBoundaries | ForEach-Object {
            [pscustomobject]@{
                Revision = $_.Revision
                Physical_Section = $_.PhysicalSection
                EOF_Offset = $_.EofOffset
                Size_Bytes = $_.SizeBytes
                Delta_Bytes = $_.DeltaBytes
                SHA256 = $_.SHA256
            }
        })

        $physicalRows = @($physicalEofBoundaries | ForEach-Object {
            [pscustomobject]@{
                Physical_Section = $_.PhysicalSection
                EOF_Offset = $_.EofOffset
                End_Exclusive = $_.EndExclusive
                Size_Bytes = $_.SizeBytes
                SHA256 = $_.SHA256
            }
        })

        $startRows = @($startXrefChecks | ForEach-Object {
            [pscustomobject]@{
                Revision = $_.Revision
                StartXref_Offset = $_.StartXrefOffset
                Target_Offset = $_.TargetOffset
                Target_Type = $_.TargetType
                Valid = $_.ValidTarget
            }
        })

        $repeatRows = @($repeatedObjects | ForEach-Object {
            [pscustomobject]@{
                Object = $_.Object
                Generation = $_.Generation
                Occurrences = $_.Occurrences
                Revisions = $_.Revisions
                Offsets = $_.Offsets
            }
        })

        $diffRows = @($revisionDiffs | ForEach-Object {
            [pscustomobject]@{
                Object = $_.Object
                Generation = $_.Generation
                From_Revision = $_.FromRevision
                To_Revision = $_.ToRevision
                From_Offset = $_.FromOffset
                To_Offset = $_.ToOffset
                Changed = $_.Changed
                From_SHA256 = $_.FromSHA256
                To_SHA256 = $_.ToSHA256
            }
        })

        $externalRows = @($externalValidationResults | ForEach-Object {
            [pscustomobject]@{
                Tool = $_.Tool
                Available = $_.Available
                ExitCode = $_.ExitCode
                Success = $_.Success
                Output = $_.Output
            }
        })

        $metadataRows = @($metadataSummary | ForEach-Object {
            [pscustomobject]@{
                Key = $_.Key
                Unique_Values = $_.UniqueValues
                Values = $_.Values
                Revision_History = $_.RevisionHistory
            }
        })

        $sigRows = @($signatureRanges | ForEach-Object {
            [pscustomobject]@{
                Revision = $_.Revision
                ByteRange = $_.Range
                Range_Valid = $_.RangeValid
                Signed_End = $_.SignedEndOffset
                Bytes_After = $_.BytesAfterSignedRange
            }
        })

        $featureRows = @($features | Where-Object { $_.Count -gt 0 } | ForEach-Object {
            [pscustomobject]@{
                Feature = $_.Feature
                Count = $_.Count
            }
        })

        $sevClass = switch ($assessment) {
            { $_ -like 'STRONG*' } { 'bad'; break }
            { $_ -like 'INDICATORS*' } { 'warn'; break }
            default { 'ok' }
        }

        $css = @'
    :root{
      --bg:#f4f6f8;--panel:#fff;--text:#18202a;--muted:#5d6977;--line:#dce2e8;
      --accent:#1f4f7a;--high:#9e1b1b;--med:#a15c00;--low:#355c7d;--ok:#176b43;
    }
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",Arial,sans-serif}
    header{background:#152536;color:#fff;padding:24px 32px}
    header h1{margin:0 0 6px;font-size:24px}
    header .sub{opacity:.8}
    main{max-width:1500px;margin:0 auto;padding:24px}
    .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;margin:0 0 18px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
    .assessment{border-left:6px solid var(--accent)}
    .assessment.bad{border-left-color:var(--high)}
    .assessment.warn{border-left-color:var(--med)}
    .assessment.ok{border-left-color:var(--ok)}
    h2{margin:0 0 12px;font-size:18px;color:#22364a}
    h3{margin:18px 0 8px;font-size:15px}
    .kv{display:grid;grid-template-columns:220px 1fr;gap:7px 16px}
    .k{color:var(--muted);font-weight:600}
    .v{word-break:break-word}
    .table-wrap{overflow:auto;border:1px solid var(--line);border-radius:7px}
    table{border-collapse:collapse;width:100%;min-width:720px}
    th,td{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
    th{background:#edf2f6;color:#30465a;position:sticky;top:0}
    tr:last-child td{border-bottom:0}
    code{font-family:Consolas,monospace;font-size:12px}
    .note{color:var(--muted)}
    footer{color:var(--muted);padding:4px 0 24px}
    @media print{body{background:#fff}.card{box-shadow:none;break-inside:avoid}header{background:#fff;color:#000;border-bottom:2px solid #000}}
'@

        $html = New-Object System.Text.StringBuilder
        [void]$html.Append('<!doctype html><html><head><meta charset="utf-8"><title>PDF Forensic Triage - ' + (HtmlEncode $file.Name) + '</title><style>' + $css + '</style></head><body>')
        [void]$html.Append('<header><h1>PDF Forensic Triage</h1><div class="sub">' + (HtmlEncode $file.Name) + '</div></header><main>')

        [void]$html.Append('<section class="card assessment ' + $sevClass + '"><h2>Assessment</h2><strong>' + (HtmlEncode $assessment) + '</strong><p>' + (HtmlEncode $assessmentDetail) + '</p></section>')

        [void]$html.Append('<section class="card"><h2>File</h2><div class="kv">')
        $pairs = [ordered]@{
            'Path' = $resolved
            'Size' = ("{0:N0} bytes" -f $file.Length)
            'PDF version' = $pdfVersion
            'MD5' = $md5
            'SHA-256' = $sha256
            'Filesystem created' = $file.CreationTime.ToString('o')
            'Filesystem modified' = $file.LastWriteTime.ToString('o')
        }
        foreach ($p in $pairs.GetEnumerator()) {
            [void]$html.Append('<div class="k">' + (HtmlEncode $p.Key) + '</div><div class="v"><code>' + (HtmlEncode $p.Value) + '</code></div>')
        }
        [void]$html.Append('</div></section>')

        [void]$html.Append('<section class="card"><h2>Structural summary</h2><div class="kv">')
        $spairs = [ordered]@{
            'PDF headers' = $headerMatches.Count
            'Header offset' = $headerOffset
            'Objects / endobj' = "$($objMatches.Count) / $($endObjMatches.Count)"
            'Streams / endstream' = "$($streamMatches.Count) / $($endStreamMatches.Count)"
            'Classic xref tokens' = $xrefMatches.Count
            'XRef stream markers' = $xrefStreamMarkers.Count
            'trailers' = $trailerMatches.Count
            'startxref' = $startXrefMatches.Count
            'Linearized / Fast Web View' = $isLinearized
            'Linearization version' = $linearizationVersion
            'Linearization /L' = $linearizationDeclaredLength
            '/L matches current size' = $linearizationDeclaredLengthMatchesCurrent
            '/Prev (raw / forward / backward)' = "$($prevMatches.Count) / $($forwardPrev.Count) / $($backwardPrev.Count)"
            'Physical %%EOF markers' = $eofMatches.Count
            'Logical revisions' = $logicalRevisionCount
            'Repeated object IDs' = $repeatedObjects.Count
            'Bytes before header (non-whitespace)' = $nonWhitespaceBeforeHeader
            'Bytes after final EOF (non-whitespace)' = $trailingNonWhitespace
        }
        foreach ($p in $spairs.GetEnumerator()) {
            [void]$html.Append('<div class="k">' + (HtmlEncode $p.Key) + '</div><div class="v">' + (HtmlEncode $p.Value) + '</div>')
        }
        [void]$html.Append('</div></section>')

        [void]$html.Append('<section class="card"><h2>Findings</h2>' + (New-HtmlTable -Headers @('Severity','Finding','Detail') -Rows $findingRows) + '</section>')
        [void]$html.Append('<section class="card"><h2>Logical revisions</h2><p class="note">Linearization-only bootstrap EOF markers are excluded. A SHA-256 is calculated over each logical file revision prefix.</p>' + (New-HtmlTable -Headers @('Revision','Physical_Section','EOF_Offset','Size_Bytes','Delta_Bytes','SHA256') -Rows $revisionRows) + '</section>')
        [void]$html.Append('<section class="card"><h2>Physical EOF sections</h2><p class="note">Raw %%EOF locations. In a linearized PDF, more than one physical EOF can be normal and does not necessarily represent an edit.</p>' + (New-HtmlTable -Headers @('Physical_Section','EOF_Offset','End_Exclusive','Size_Bytes','SHA256') -Rows $physicalRows) + '</section>')
        [void]$html.Append('<section class="card"><h2>startxref validation</h2>' + (New-HtmlTable -Headers @('Revision','StartXref_Offset','Target_Offset','Target_Type','Valid') -Rows $startRows) + '</section>')
        [void]$html.Append('<section class="card"><h2>Repeated indirect objects</h2><p class="note">Repeated object/generation IDs can show which objects were superseded in later incremental revisions.</p>' + (New-HtmlTable -Headers @('Object','Generation','Occurrences','Revisions','Offsets') -Rows $repeatRows) + '</section>')
        [void]$html.Append('<section class="card"><h2>Object-level revision diff</h2><p class="note">Compares raw indirect-object definitions when the same object/generation ID appears more than once. Changed hashes indicate different serialized object definitions.</p>' + (New-HtmlTable -Headers @('Object','Generation','From_Revision','To_Revision','From_Offset','To_Offset','Changed','From_SHA256','To_SHA256') -Rows $diffRows) + '</section>')
        [void]$html.Append('<section class="card"><h2>External validation</h2><p class="note">Optional corroboration from locally installed third-party utilities. These results are not authoritative by themselves.</p>' + (New-HtmlTable -Headers @('Tool','Available','ExitCode','Success','Output') -Rows $externalRows) + '</section>')
        [void]$html.Append('<section class="card"><h2>Metadata history</h2><p class="note">Metadata is corroborative only; it can be stale or altered.</p>' + (New-HtmlTable -Headers @('Key','Unique_Values','Values','Revision_History') -Rows $metadataRows) + '</section>')
        [void]$html.Append('<section class="card"><h2>Digital signature indicators</h2>' + (New-HtmlTable -Headers @('Revision','ByteRange','Range_Valid','Signed_End','Bytes_After') -Rows $sigRows) + '</section>')
        [void]$html.Append('<section class="card"><h2>Other PDF features</h2>' + (New-HtmlTable -Headers @('Feature','Count') -Rows $featureRows) + '</section>')

        [void]$html.Append('<section class="card"><h2>Interpretation limits</h2><ul>')
        foreach ($lim in $report.Limitations) {
            [void]$html.Append('<li>' + (HtmlEncode $lim) + '</li>')
        }
        [void]$html.Append('</ul></section>')

        [void]$html.Append('<footer>Generated ' + (HtmlEncode (Get-Date).ToString('o')) + ' by PDF Hexmator v2.1.1</footer>')
        [void]$html.Append('</main></body></html>')

        [System.IO.File]::WriteAllText($htmlPath, $html.ToString(), ([System.Text.UTF8Encoding]::new($false)))
    }

    if (-not $Quiet) {
        # ----------------------------
        # Console summary
        # ----------------------------

        Write-Host ''
        Write-Host 'PDF HEXMATOR - PDF FORENSIC TRIAGE' -ForegroundColor Cyan
        Write-Host ('=' * 72)
        Write-Host ("File       : {0}" -f $resolved)
        Write-Host ("Size       : {0:N0} bytes" -f $file.Length)
        Write-Host ("SHA-256    : {0}" -f $sha256)
        Write-Host ("PDF version: {0}" -f $(if ($pdfVersion) { $pdfVersion } else { 'Not identified' }))
        Write-Host ("PowerShell : {0}" -f $PSVersionTable.PSVersion.ToString())
        Write-Host ''
        Write-Host 'Assessment :' -NoNewline
        if ($strongIncrementalEvidence) {
            Write-Host (" {0}" -f $assessment) -ForegroundColor Yellow
        } elseif ($assessment -like 'INDICATORS*') {
            Write-Host (" {0}" -f $assessment) -ForegroundColor Yellow
        } else {
            Write-Host (" {0}" -f $assessment) -ForegroundColor Green
        }
        Write-Host ("  {0}" -f $assessmentDetail)
        Write-Host ''
        Write-Host ("Linearized : {0}" -f $isLinearized)
        if ($isLinearized) {
            Write-Host ("  /L       : {0} (current size: {1}; match: {2})" -f $linearizationDeclaredLength, $bytes.Length, $linearizationDeclaredLengthMatchesCurrent)
        }
        Write-Host ("Revisions  : {0} logical / {1} physical %%EOF marker(s)" -f $logicalRevisionCount, $eofMatches.Count)
        Write-Host ("startxref  : {0}" -f $startXrefMatches.Count)
        Write-Host ("/Prev      : {0} raw / {1} forward / {2} backward" -f $prevMatches.Count, $forwardPrev.Count, $backwardPrev.Count)
        Write-Host ("Redefined  : {0} object ID(s)" -f $repeatedObjects.Count)
        Write-Host ("Signatures : {0} ByteRange(s)" -f $byteRangeMatches.Count)
        Write-Host ''

        if ($findings.Count -gt 0) {
            Write-Host 'Findings:' -ForegroundColor Cyan
            foreach ($f in $findings) {
                $color = switch ($f.Severity) {
                    'HIGH' { 'Red' }
                    'MEDIUM' { 'Yellow' }
                    'LOW' { 'DarkCyan' }
                    default { 'Gray' }
                }
                Write-Host ("[{0}] {1}: {2}" -f $f.Severity, $f.Title, $f.Detail) -ForegroundColor $color
            }
        } else {
            Write-Host 'No reportable structural findings were generated.' -ForegroundColor Green
        }

        Write-Host ''
        Write-Host ("Output dir : {0}" -f $OutputDirectory)
        if (-not $NoJson) { Write-Host ("JSON       : {0}" -f $jsonPath) }
        if (-not $NoHtml) { Write-Host ("HTML       : {0}" -f $htmlPath) }
        if ($ExtractRevisions) {
            if ($carved.Count -gt 0) {
                Write-Host ("Carved     : {0} logical revision file(s)" -f $carved.Count)
            } else {
                Write-Host 'Carved     : 0 (no prior logical revision was recoverable)'
            }
        }
        Write-Host ''


    }

    # Return report object to the pipeline for automation.
    [pscustomobject]$report
}

# ----------------------------
# Main orchestration
# ----------------------------

$runStarted = Get-Date
$timestamp = $runStarted.ToString('yyyyMMdd_HHmmss')

# Determine whether an input directory was explicitly supplied.
$inputIncludedDirectory = $false
foreach ($p in $Path) {
    if (Test-Path -LiteralPath $p -PathType Container) {
        $inputIncludedDirectory = $true
        break
    }
}

# Choose an output location before discovery so the active output tree can be excluded.
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    if ($Path.Count -eq 1 -and (Test-Path -LiteralPath $Path[0] -PathType Leaf)) {
        $singleInput = Get-Item -LiteralPath $Path[0]
        $OutputDirectory = Join-Path $singleInput.DirectoryName ($singleInput.BaseName + '_pdf_forensics_' + $timestamp)
    }
    elseif ($Path.Count -eq 1 -and (Test-Path -LiteralPath $Path[0] -PathType Container)) {
        $root = (Get-Item -LiteralPath $Path[0]).FullName
        $OutputDirectory = Join-Path $root ('PDF_Bulk_Forensics_' + $timestamp)
    }
    else {
        $OutputDirectory = Join-Path (Get-Location).Path ('PDF_Bulk_Forensics_' + $timestamp)
    }
}

$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$pdfFiles = @(Resolve-PdfTargets -InputPath $Path -Recurse ([bool]$Recurse) -ExcludeRoot $OutputDirectory)

if ($pdfFiles.Count -eq 0) {
    throw 'No PDF files were found in the supplied path(s).'
}

$bulkMode = ($pdfFiles.Count -gt 1 -or $inputIncludedDirectory -or $Path.Count -gt 1)
[void](New-Item -ItemType Directory -Path $OutputDirectory -Force)

# Preserve the original single-document experience.
if (-not $bulkMode) {
    $single = $pdfFiles[0]
    $report = Invoke-PdfFileAnalysis `
        -ResolvedPath $single.FullName `
        -DocumentOutputDirectory $OutputDirectory `
        -ExtractRevisions ([bool]$ExtractRevisions) `
        -WriteJson (-not [bool]$NoJson) `
        -WriteHtml (-not [bool]$NoHtml) `
        -Quiet $false `
        -RunExternalValidation ([bool]$ExternalValidation) `
        -ExternalToolsDirectory $ExternalToolsDirectory

    if (-not $NoManifest) {
        $singleSummary = Convert-AnalysisToBulkSummary -Report $report -Index 1 -DetailHtmlRelative '' -DetailJsonRelative ''
        $manifestResult = Write-CaseManifest `
            -OutputRoot $OutputDirectory `
            -CaseName $CaseName `
            -Documents @($singleSummary) `
            -InputPaths @($Path) `
            -Recurse ([bool]$Recurse) `
            -DetailedReports $true `
            -ExtractRevisions ([bool]$ExtractRevisions) `
            -ExternalValidation ([bool]$ExternalValidation) `
            -Started $runStarted.ToString('o') `
            -Completed (Get-Date).ToString('o')
        if (-not $NoHtml -or -not $NoJson) {
            Write-Host ("Manifest   : {0}" -f $manifestResult.Json)
        }
    }

    $report
    return
}

Write-Host ''
Write-Host 'PDF HEXMATOR - BULK FORENSIC TRIAGE' -ForegroundColor Cyan
Write-Host ('=' * 78)
Write-Host ("PDFs discovered : {0:N0}" -f $pdfFiles.Count)
Write-Host ("Recursive       : {0}" -f [bool]$Recurse)
Write-Host ("Output          : {0}" -f $OutputDirectory)
Write-Host ("Details         : {0}" -f [bool]$DetailedReports)
Write-Host ("Revisions       : {0}" -f [bool]$ExtractRevisions)
Write-Host ("External        : {0}" -f [bool]$ExternalValidation)
Write-Host ("Manifest        : {0}" -f (-not [bool]$NoManifest))
Write-Host ("PowerShell      : {0}" -f $PSVersionTable.PSVersion.ToString())
Write-Host ''

# PHASE 1: Hash every discovered PDF before any deep PDF parsing.
Write-Host 'Phase 1/2 - Calculating SHA-256 for every PDF...' -ForegroundColor Cyan
$hashInventory = @(Get-PdfHashInventory -Files $pdfFiles)
$hashErrors = @($hashInventory | Where-Object { $_.Status -eq 'HashError' })
$hashGroups = @(New-PdfHashGroups -Inventory $hashInventory)
$hashedFiles = @($hashInventory | Where-Object { $_.Status -eq 'Hashed' }).Count
$uniqueHashCount = $hashGroups.Count
$duplicateSets = @($hashGroups | Where-Object { $_.FileCount -gt 1 }).Count
$deepAnalysesSaved = [Math]::Max(0, $hashedFiles - $uniqueHashCount)
$duplicateFiles = [int](Get-SafePropertySum `
    -InputObject @($hashGroups | Where-Object { $_.FileCount -gt 1 }) `
    -Property 'FileCount')

Write-Host ("  Hashed successfully : {0:N0}" -f $hashedFiles)
Write-Host ("  Unique SHA-256      : {0:N0}" -f $uniqueHashCount)
Write-Host ("  Duplicate sets      : {0:N0}" -f $duplicateSets)
Write-Host ("  Deep analyses saved : {0:N0}" -f $deepAnalysesSaved)
Write-Host ("  Hash errors         : {0:N0}" -f $hashErrors.Count)
Write-Host ''

if ($StopOnError -and $hashErrors.Count -gt 0) {
    throw ("SHA-256 hashing failed for {0} PDF(s). First error: {1} - {2}" -f $hashErrors.Count,$hashErrors[0].FullPath,$hashErrors[0].Error)
}

$documentsDir = Join-Path $OutputDirectory 'documents'
if ($DetailedReports -or $ExtractRevisions) { [void](New-Item -ItemType Directory -Path $documentsDir -Force) }

# PHASE 2: Analyze only one representative file for each unique SHA-256.
Write-Host 'Phase 2/2 - Deep analysis of unique SHA-256 representatives...' -ForegroundColor Cyan
$groupSummaries = New-Object System.Collections.Generic.List[object]
$totalUnique = $hashGroups.Count

for ($i = 0; $i -lt $totalUnique; $i++) {
    $group = $hashGroups[$i]
    $file = Get-Item -LiteralPath $group.Representative.FullPath
    $index = $i + 1
    $pct = if ($totalUnique -gt 0) { [int](($index / [double]$totalUnique) * 100) } else { 100 }

    Write-Progress -Activity 'PDF Hexmator - Phase 2 of 2: unique PDF analysis' `
        -Status ("[{0:N0}/{1:N0}] {2} ({3} source file{4})" -f $index,$totalUnique,$file.Name,$group.FileCount,$(if($group.FileCount -eq 1){''}else{'s'})) `
        -PercentComplete $pct

    $safeBase = Get-SafeFileName -Name $file.BaseName -MaxLength 76
    $docFolderName = '{0}_{1}' -f $group.HashGroup,$safeBase
    $docOut = if ($DetailedReports -or $ExtractRevisions) { Join-Path $documentsDir $docFolderName } else { $OutputDirectory }
    $writeDetailHtml = ([bool]$DetailedReports -and -not [bool]$NoHtml)
    $writeDetailJson = ([bool]$DetailedReports -and -not [bool]$NoJson)
    $detailHtmlRel = if ($writeDetailHtml) { 'documents/{0}/{1}.pdf-forensics.html' -f $docFolderName,$file.BaseName } else { '' }
    $detailJsonRel = if ($writeDetailJson) { 'documents/{0}/{1}.pdf-forensics.json' -f $docFolderName,$file.BaseName } else { '' }

    try {
        $report = Invoke-PdfFileAnalysis `
            -ResolvedPath $file.FullName `
            -DocumentOutputDirectory $docOut `
            -ExtractRevisions ([bool]$ExtractRevisions) `
            -WriteJson $writeDetailJson `
            -WriteHtml $writeDetailHtml `
            -Quiet $true `
            -RunExternalValidation ([bool]$ExternalValidation) `
            -ExternalToolsDirectory $ExternalToolsDirectory

        # Defensive verification: the representative deep-analysis hash must equal the phase-one hash.
        if ([string]$report.File.SHA256 -ne [string]$group.SHA256) {
            throw ("Representative file changed between hashing and analysis. Expected SHA-256 {0}; analyzed {1}." -f $group.SHA256,$report.File.SHA256)
        }

        $summary = Convert-AnalysisToHashGroupSummary -HashGroup $group -Report $report -DetailHtmlRelative $detailHtmlRel -DetailJsonRelative $detailJsonRel
        $groupSummaries.Add($summary)
        foreach ($member in @($group.Files)) {
            $member.Status = 'Complete'
            $member.Assessment = $summary.Assessment
        }

        $statusColor = if ($summary.HighFindings -gt 0) { 'Yellow' } else { 'DarkGray' }
        Write-Host ("[{0,6:N0}/{1:N0}] {2} x{3} -> {4}" -f $index,$totalUnique,$group.HashGroup,$group.FileCount,$summary.Assessment) -ForegroundColor $statusColor
    }
    catch {
        $errSummary = New-HashGroupErrorSummary -HashGroup $group -ErrorRecord $_
        $groupSummaries.Add($errSummary)
        foreach ($member in @($group.Files)) {
            $member.Status = 'Error'
            $member.Assessment = 'ANALYSIS ERROR'
            $member.Error = $_.Exception.Message
        }
        Write-Host ("[{0,6:N0}/{1:N0}] ERROR {2} ({3} file(s)): {4}" -f $index,$totalUnique,$group.HashGroup,$group.FileCount,$_.Exception.Message) -ForegroundColor Red
        if ($StopOnError) {
            Write-Progress -Activity 'PDF Hexmator - Phase 2 of 2: unique PDF analysis' -Completed
            throw
        }
    }

    if (($index % 100) -eq 0) { [GC]::Collect(); [GC]::WaitForPendingFinalizers() }
}
Write-Progress -Activity 'PDF Hexmator - Phase 2 of 2: unique PDF analysis' -Completed

$groupSummaryArray = $groupSummaries.ToArray()
$completedUnique = @($groupSummaryArray | Where-Object { $_.Status -eq 'Complete' }).Count
$analysisErrorGroups = @($groupSummaryArray | Where-Object { $_.Status -eq 'Error' }).Count
$completedSourceFiles = Get-SafePropertySum `
    -InputObject @($groupSummaryArray | Where-Object { $_.Status -eq 'Complete' }) `
    -Property 'FileCount'
$analysisErrorSourceFiles = Get-SafePropertySum `
    -InputObject @($groupSummaryArray | Where-Object { $_.Status -eq 'Error' }) `
    -Property 'FileCount'

$uniqueIncrementalEvidence = @($groupSummaryArray | Where-Object { $_.Assessment -like 'STRONG EVIDENCE*' -or $_.Assessment -like 'INDICATORS CONSISTENT*' }).Count
$sourceIncrementalEvidence = Get-SafePropertySum `
    -InputObject @($groupSummaryArray | Where-Object { $_.Assessment -like 'STRONG EVIDENCE*' -or $_.Assessment -like 'INDICATORS CONSISTENT*' }) `
    -Property 'FileCount'
$uniqueLinearized = @($groupSummaryArray | Where-Object { $_.Linearized }).Count
$sourceLinearized = Get-SafePropertySum `
    -InputObject @($groupSummaryArray | Where-Object { $_.Linearized }) `
    -Property 'FileCount'
$uniqueSigned = @($groupSummaryArray | Where-Object { $_.SignatureByteRanges -gt 0 }).Count
$uniqueActive = @($groupSummaryArray | Where-Object { $_.ActiveContentIndicators -gt 0 }).Count
$highFindingGroups = @($groupSummaryArray | Where-Object { $_.HighFindings -gt 0 }).Count
$totalBytes = Get-SafePropertySum `
    -InputObject @($hashInventory) `
    -Property 'SizeBytes'

$caseReport = [ordered]@{
    Tool = 'PDF Hexmator'
    Version = '2.1.1'
    CaseName = $CaseName
    Generated = (Get-Date).ToString('o')
    Started = $runStarted.ToString('o')
    PowerShell = $PSVersionTable.PSVersion.ToString()
    InputPaths = @($Path)
    OutputDirectory = $OutputDirectory
    Recurse = [bool]$Recurse
    HashFirstDeduplication = $true
    DetailedReports = [bool]$DetailedReports
    ExtractRevisions = [bool]$ExtractRevisions
    ExternalValidation = [bool]$ExternalValidation
    ExternalToolsDirectory = $ExternalToolsDirectory
    ManifestEnabled = (-not [bool]$NoManifest)
    Statistics = [ordered]@{
        TotalDocuments = $pdfFiles.Count
        HashedSuccessfully = $hashedFiles
        HashErrors = $hashErrors.Count
        UniqueHashes = $uniqueHashCount
        DeepAnalysesPerformed = $totalUnique
        DeepAnalysesSucceeded = $completedUnique
        DeepAnalysisErrorGroups = $analysisErrorGroups
        DeepAnalysisErrorSourceFiles = [int]$analysisErrorSourceFiles
        DeepAnalysesSaved = $deepAnalysesSaved
        CompletedSourceFiles = [int]$completedSourceFiles
        TotalBytes = [long]$totalBytes
        DuplicateSets = $duplicateSets
        DuplicateFiles = [int]$duplicateFiles
        RedundantCopies = $deepAnalysesSaved
        UniqueIncrementalEvidence = $uniqueIncrementalEvidence
        SourceDocumentsWithIncrementalEvidence = [int]$sourceIncrementalEvidence
        UniqueLinearized = $uniqueLinearized
        SourceDocumentsLinearized = [int]$sourceLinearized
        UniqueSigned = $uniqueSigned
        UniqueActiveContent = $uniqueActive
        UniqueHashesWithHighFindings = $highFindingGroups
        UniqueHashesWithChangedObjects = @($groupSummaryArray | Where-Object { $_.ChangedObjectDefinitions -gt 0 }).Count
        ExternalValidatorFailures = @($groupSummaryArray | Where-Object { $_.ExternalToolFailures -gt 0 }).Count
    }
    HashGroups = $groupSummaryArray
    HashErrors = $hashErrors
    Interpretation = @(
        'Every discovered PDF is SHA-256 hashed before deep analysis. Byte-identical PDFs are analyzed once per unique hash.',
        'Each hash group retains all original source paths; findings belong to the byte-identical group rather than being duplicated for every copy.',
        'Incremental-update evidence establishes multiple physical saved states but does not establish malicious or improper editing.',
        'Recognized linearization-only EOF/startxref structures are excluded from logical revision scoring.',
        'A complete rewrite or optimization can remove prior revision evidence.',
        'Metadata is corroborative and can be altered or stale.',
        'Signature structures are detected but cryptographic certificate/signature validity is not verified.'
    )
}

$csvPath = Join-Path $OutputDirectory 'PDF-Forensic-Bulk-Summary.csv'
$fileInventoryCsvPath = Join-Path $OutputDirectory 'PDF-Forensic-File-Inventory.csv'
$jsonPath = Join-Path $OutputDirectory 'PDF-Forensic-Bulk-Summary.json'
$htmlPath = Join-Path $OutputDirectory 'PDF-Forensic-Bulk-Report.html'

if (-not $NoCsv) {
    $groupSummaryArray |
        Select-Object Index,HashGroup,Status,SHA256,FileCount,DuplicateCopies,RepresentativeFileName,RepresentativeFullPath,SizeBytes,MD5,PdfVersion,
            Assessment,Linearized,LinearizationLengthMatch,LogicalRevisions,PhysicalEofMarkers,StartXrefCount,ForwardPrev,BackwardPrev,
            RedefinedObjects,ChangedObjectDefinitions,SignatureByteRanges,ExternalToolsAvailable,ExternalToolFailures,ActiveContentIndicators,
            HighFindings,MediumFindings,LowFindings,Producer,Creator,CreationDate,ModificationDate,MemberPaths,DetailHtml,DetailJson,Error |
        Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    $hashInventory |
        Select-Object Index,Status,FileName,FullPath,Directory,SizeBytes,SHA256,HashGroup,GroupSize,RepresentativeFullPath,IsRepresentative,
            Assessment,FileSystemLastWriteTime,Error |
        Export-Csv -LiteralPath $fileInventoryCsvPath -NoTypeInformation -Encoding UTF8
}

if (-not $NoJson) { [pscustomobject]$caseReport | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding UTF8 }
if (-not $NoHtml) { New-BulkHtmlReport -CaseReport ([pscustomobject]$caseReport) -OutputPath $htmlPath }

$manifestResult = $null
if (-not $NoManifest) {
    $manifestResult = Write-CaseManifest `
        -OutputRoot $OutputDirectory `
        -CaseName $CaseName `
        -Documents $hashInventory `
        -InputPaths @($Path) `
        -Recurse ([bool]$Recurse) `
        -DetailedReports ([bool]$DetailedReports) `
        -ExtractRevisions ([bool]$ExtractRevisions) `
        -ExternalValidation ([bool]$ExternalValidation) `
        -HashFirstDeduplication $true `
        -Started $runStarted.ToString('o') `
        -Completed (Get-Date).ToString('o')
}

$elapsed = (Get-Date) - $runStarted

Write-Host ''
Write-Host ('=' * 78)
Write-Host 'BULK TRIAGE COMPLETE' -ForegroundColor Cyan
Write-Host ("PDFs discovered        : {0:N0}" -f $pdfFiles.Count)
Write-Host ("SHA-256 hashed         : {0:N0}" -f $hashedFiles)
Write-Host ("Unique SHA-256         : {0:N0}" -f $uniqueHashCount)
Write-Host ("Deep analyses run      : {0:N0}" -f $totalUnique)
Write-Host ("Deep analyses saved    : {0:N0}" -f $deepAnalysesSaved)
Write-Host ("Duplicate sets/files   : {0:N0} / {1:N0}" -f $duplicateSets,$duplicateFiles)
Write-Host ("Hash errors            : {0:N0}" -f $hashErrors.Count)
Write-Host ("Analysis error groups  : {0:N0}" -f $analysisErrorGroups)
Write-Host ("Incremental evidence   : {0:N0} unique hash group(s)" -f $uniqueIncrementalEvidence)
Write-Host ("Linearized PDFs        : {0:N0} unique hash group(s)" -f $uniqueLinearized)
Write-Host ("Elapsed                : {0}" -f $elapsed.ToString('hh\:mm\:ss'))
Write-Host ("Output                 : {0}" -f $OutputDirectory)
if (-not $NoHtml) { Write-Host ("HTML                   : {0}" -f $htmlPath) }
if (-not $NoCsv)  {
    Write-Host ("Hash-group CSV         : {0}" -f $csvPath)
    Write-Host ("File inventory CSV     : {0}" -f $fileInventoryCsvPath)
}
if (-not $NoJson) { Write-Host ("JSON                   : {0}" -f $jsonPath) }
if ($manifestResult) { Write-Host ("Manifest               : {0}" -f $manifestResult.Json) }
Write-Host ''

[pscustomobject]$caseReport
