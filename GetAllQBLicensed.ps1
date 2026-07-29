$dirs = Get-ChildItem "C:\ProgramData\Common Files\Intuit"
foreach ($dir in $dirs) {
    $year = $dir.ToString().Split(" ")
    $path = "C:\ProgramData\Common Files\Intuit\" + $dir.ToString() + "\qbregistration.dat"
    if (Test-Path $path -PathType Leaf) {
        $foundVER = (select-string -Path $path -Pattern 'VERSION number=".*?">' -All).Matches.Value
        $foundFLA = (select-string -Path $path -Pattern 'FLAVOR name=".*?"' -All).Matches.Value
        $foundLIC = (select-string -Path $path -Pattern '<LicenseNumber>.*?</LicenseNumber>' -All).Matches.Value
        $foundID  = (select-string -Path $path -Pattern '<InstallID>.*?</InstallID>' -All).Matches.Value
        $count = 0
        while ($count -lt $foundVER.Length) {
            $string = "Found version: " + $foundVER[$count].Split('"')[1] + " " + $foundFLA[$count].Split('"')[1] + "`nLicense Number: " + $foundLIC[$count].Split('>')[1].Split('<')[0] + "`nID: " + $foundID[$count].Split('>')[1].Split('<')[0] + "`n`n"
            write-host $string
            $count++
        }
    }
}
