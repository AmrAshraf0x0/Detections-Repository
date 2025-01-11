[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$RootFolder
)

# Resolve full path (remove . or ..) for clarity
$RootFolder = (Resolve-Path $RootFolder).ProviderPath

# Recursively gather all .yml files
$AllYmlFiles = Get-ChildItem -Path $RootFolder -Filter '*.yml' -File -Recurse

if (-not $AllYmlFiles) {
    Write-Host "No .yml files found under $RootFolder"
    return
}

# Prepare a list for the summary of all files
$SummaryList = New-Object System.Collections.Generic.List[PSObject]

foreach ($YmlFile in $AllYmlFiles) {

    ############################################################################
    # 1) Read file contents as a single string to capture 'status:' easily
    ############################################################################
    $ContentStr = Get-Content -Path $YmlFile.FullName -Raw

    # Default 'status' to "unknown" if not matched
    $Status = "unknown"
    if ($ContentStr -match '(?im)^\s*status:\s*(.+)$') {
        $Status = $Matches[1].Trim()
    }

    ############################################################################
    # 2) Read file line by line to parse the 'tags:' block
    #    but skip the literal 'tags:' line itself
    ############################################################################
    $Lines     = Get-Content -Path $YmlFile.FullName
    $Collect   = $false
    $tagsBlock = New-Object System.Collections.Generic.List[string]

    foreach ($Line in $Lines) {
        if ($Line -match '^\s*tags:\s*$') {
            # Found "tags:" line, start collecting
            $Collect = $true
            continue
        }
        if ($Collect) {
            # If a new top-level key (no dash or indentation), stop collecting
            if ($Line -match '^[^ \t-]') {
                break
            }
            # Remove leading dash and extra whitespace
            $trimLine = $Line -replace '^\s*-\s*',''
            $trimLine = $trimLine.Trim()
            if ($trimLine) {
                $tagsBlock.Add($trimLine)
            }
        }
    }

    # Flatten tags into a single string
    $Tags = $tagsBlock -join "; "

    ############################################################################
    # 3) Create an object with the short file name, status, and tags
    ############################################################################
    $obj = [PSCustomObject]@{
        FileName = $YmlFile.Name
        Status   = $Status
        Tags     = $Tags
    }

    $SummaryList.Add($obj)
}

################################################################################
# 4) Write one combined CSV in the root folder
################################################################################
$OutputCsv = Join-Path $RootFolder "AllRulesSummary.csv"

# Export: columns FileName, Status, Tags
$SummaryList |
    Select-Object FileName, Status, Tags |
    Export-Csv -Path $OutputCsv -NoTypeInformation

Write-Host "`nAll .yml files processed. Combined summary written to:"
Write-Host $OutputCsv
