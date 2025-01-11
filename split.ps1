################################################################################
# Configuration
################################################################################

# Input file containing all Sigma rules (big combined file)
$InputFile = ".\Combined.yml"

# Base directory for output (short path, outside OneDrive)
$OutputBaseDir = "C:\Users\amr.ashraf\rules"

# Global counter for unique IDs (across all tactics)
$GlobalID = 2000

################################################################################
# Helper: Aggressive sanitization for filenames/directories
# Allows letters, digits, space, underscore, dash, dot, parentheses
################################################################################
function AggressiveSanitize {
    param([string] $Name)

    if (-not $Name) { return "" }

    # Keep only these characters: a-z, A-Z, 0-9, space, underscore, dot, dash, (), everything else -> underscore
    $Name = $Name -replace '[^a-zA-Z0-9 _.\-\(\)]', '_'
    return $Name.Trim()
}

################################################################################
# Read & Split
################################################################################

# Read the entire file as one string, then split by the YAML separator
$FileContent = Get-Content -Path $InputFile -Raw
$Rules       = $FileContent -split "`n---`n"

################################################################################
# Process Each Rule
################################################################################

foreach ($Rule in $Rules) {
    # Only process if it has at least a title
    if ($Rule -notmatch "title:.*") {
        continue
    }

    # Extract needed fields (fallback to "unknown" if missing)
    $Title = if ($Rule -match 'title:\s*(.+)') { $Matches[1].Trim() } else { "NoTitle" }
    $TacticTag = if ($Rule -match 'tags:\s*-?\s*attack\.([a-z_]+)') { $Matches[1].Trim() } else { "unknown" }
    $Level  = if ($Rule -match 'level:\s*(.+)') { $Matches[1].Trim() } else { "unknown" }
    $Status = if ($Rule -match 'status:\s*(.+)') { $Matches[1].Trim() } else { "unknown" }

    # Remove the entire "id:" line
    $Rule = $Rule -replace 'id:\s*.+`n', ''

    ############################################################################
    # Parse the entire 'tags:' block (multi-line) to store in summary
    ############################################################################
    $lines       = $Rule -split "`r?`n"
    $tagsBlock   = New-Object System.Collections.Generic.List[string]
    $collectTags = $false

    foreach ($line in $lines) {
        if ($line -match '^\s*tags:\s*') {
            $collectTags = $true
            $tagsBlock.Add($line)
            continue
        }
        if ($collectTags) {
            # Stop collecting if we hit a top-level key (non-indented or doesn't look like part of tags)
            if ($line -match '^[^ \t-]') {
                break
            }
            $tagsBlock.Add($line)
        }
    }

    # Flatten tags into a single line for CSV
    # For example, each tags line becomes trimmed and joined by "; "
    $tagsOneLine = ($tagsBlock | ForEach-Object { $_.Trim() }) -join "; "

    # Escape any double-quotes in the tags so CSV doesn't break
    $tagsOneLine = $tagsOneLine -replace '"', '""'

    ############################################################################
    # Prepare Output Directories & Filenames
    ############################################################################

    # Sanitize tactic for directory creation
    $SafeTacticTag = AggressiveSanitize($TacticTag)
    $TacticDir     = Join-Path -Path $OutputBaseDir -ChildPath $SafeTacticTag

    # Ensure the tactic directory exists
    if (-not (Test-Path -Path $TacticDir)) {
        New-Item -ItemType Directory -Path $TacticDir | Out-Null
    }

    # Pull the global ID (increment for each rule so it's unique across all folders)
    $ID = $GlobalID
    $GlobalID++

    # Tactic code: up to first 3 chars (uppercase)
    $ShortTactic = $SafeTacticTag.ToUpper()
    if ($ShortTactic.Length -gt 3) {
        $ShortTactic = $ShortTactic.Substring(0,3)
    }

    # Build the final filename
    # Example: "DEF-2000-CredentialDump (critical).yml"
    $SafeTitle = AggressiveSanitize($Title)
    $SafeLevel = AggressiveSanitize($Level)
    $FileName  = "{0}-{1}-{2} ({3})" -f $ShortTactic, $ID, $SafeTitle, $SafeLevel
    $SafeFileName = AggressiveSanitize($FileName) + ".yml"
    $OutputFile   = Join-Path -Path $TacticDir -ChildPath $SafeFileName

    ############################################################################
    # Write the Rule to Its Own .yml File
    ############################################################################
    $Rule | Out-File -FilePath $OutputFile -Encoding UTF8

    ############################################################################
    # Append Summary in CSV Format to "Summary.csv"
    # The "RuleName" is the final file name, not the Title
    ############################################################################
    $SummaryFile = Join-Path $TacticDir "Summary.csv"

    # If Summary.csv doesn't exist yet, write a header row
    if (-not (Test-Path $SummaryFile)) {
        Add-Content $SummaryFile -Value 'FileName,Status,Tags'
    }

    # Escape double quotes in $SafeFileName and $Status
    $safeFileNameCSV = $SafeFileName -replace '"', '""'
    $safeStatusCSV   = $Status       -replace '"', '""'

    # Prepare a single CSV line: "FileName","Status","FlattenedTags"
    $csvLine = '"{0}","{1}","{2}"' -f $safeFileNameCSV, $safeStatusCSV, $tagsOneLine
    Add-Content -Path $SummaryFile -Value $csvLine
}

Write-Host "`nAll rules split with globally unique IDs. Summaries in each tactic folder's Summary.csv."