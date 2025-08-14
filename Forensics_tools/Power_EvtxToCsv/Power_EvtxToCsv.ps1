
<#
Power-EVTXtoCSV
Parses a given EVTX file and exports all fields to CSV
Author: Abhijit Mohanta
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$EvtxFile
)

# Banner
Write-Host "============================================="
Write-Host "   Power-EVTXtoCSV - Full EVTX to CSV Parser"
Write-Host "   Author : Abhijit Mohanta"
Write-Host "   Input  : $EvtxFile"
Write-Host "============================================="
Write-Host ""


# Output CSV path
$OutputCSV = [System.IO.Path]::ChangeExtension($EvtxFile, ".csv")

Write-Host "Parsing $EvtxFile ..."

$Parsed = Get-WinEvent -Path $EvtxFile | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $fields = @{}

    # Add System fields (check attributes and inner text)
    foreach ($node in $xml.Event.System.ChildNodes) {
        if ($node.Attributes.Count -gt 0) {
            foreach ($attr in $node.Attributes) {
                $fields["$($node.LocalName)_$($attr.Name)"] = $attr.Value
            }
        }
        if ($node.InnerText -and -not $fields.ContainsKey($node.LocalName)) {
            $fields[$node.LocalName] = $node.InnerText
        }
    }

    # Add EventData fields
    foreach ($data in $xml.Event.EventData.Data) {
        if ($data.HasAttribute("Name")) {
            $fields[$data.Name] = $data.'#text'
        } else {
            $fields["Data_$($fields.Count)"] = $data.'#text'
        }
    }

    New-Object PSObject -Property $fields
}

# Export to CSV
$Parsed | Export-Csv -NoTypeInformation -Path $OutputCSV

Write-Host "Parsing complete. Output saved to $OutputCSV"
