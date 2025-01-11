# Get the current directory
$CurrentDirectory = Get-Location

# Loop through each file matching the naming scheme in the current directory
Get-ChildItem -Path $CurrentDirectory -Filter "EXE-E-*.yml" | ForEach-Object {
    # Read the content of the YAML file
    $Content = Get-Content $_.FullName

    # Extract the title and level values
    $Title = ($Content | Select-String -Pattern "^title:\s*(.+)$").Matches.Groups[1].Value.Trim()
    $Level = ($Content | Select-String -Pattern "^level:\s*(.+)$").Matches.Groups[1].Value.Trim()

    # Construct the new file name
    $BaseName = $_.BaseName -replace "(EXE-E-\d+).*", '$1'
    $NewFileName = "{0}-{1} [{2}].yml" -f $BaseName, $Title, $Level

    # Rename the file
    Rename-Item -Path $_.FullName -NewName $NewFileName
}
