#===================================================================================
#
# Script Name  : 7zip-enable-motw-detect.ps1
# Description  : Detect if 7-Zip is present and if the MOTW (Mark-of-the-web) feature is enabled
# Notes        : See the following web links for more info on this:
#                  Awareness post on Twitter : https://twitter.com/ForensicITGuy/status/1795885763109716254
#                  Article                   : https://www.bleepingcomputer.com/news/microsoft/7-zip-now-supports-windows-mark-of-the-web-security-feature/
#                  
# Author       : Barry
# Date         : 30/05/2024
# Version      : 1.0
# ChangeLog    : 
#
#===================================================================================
# Define Variables

$regPath = 'Registry::HKCU\SOFTWARE\7-Zip'
$valueKey = 'Options'
$valueName = 'WriteZoneIdExtract'
$requiredValue = 1

# Main script
try {

    # First, check if 7-Zip is present
    if (Get-ItemProperty $regPath ) {
        # 7-Zip is present
        #write-host "OK: 7-Zip is present in registry"

        try{  
            Get-ItemProperty -Path "$regpath\$valueKey" -Name $valueName -ErrorAction Stop | Out-Null

            $currentValue = Get-ItemProperty -Path "$regpath\$valueKey" | Select-Object -ExpandProperty $valueName -ErrorAction SilentlyContinue
            if ($currentValue -eq $requiredvalue) {
                Write-Host "OK: 7-Zip already has MOTW enabled."
           		Exit 0
            } else {
                Write-Host "WARN: 7-Zip Reg value exists, but MOTW is not enabled"
                Write-Host "WARN: 7-Zip Current value: $currentValue"
                Write-Host "WARN: 7-Zip Required value: $requiredValue"
           		Exit 1
            } 
        }  
        catch [System.Management.Automation.ItemNotFoundException] {  
            Write-Host "WARN: 7-Zip MOTW is not enabled"
       		Exit 1
        }  
        catch {  
            Write-Host "WARN: 7-Zip MOTW is not enabled"
       		Exit 1
        }
    } else {
        # 7-Zip is not present
        Write-Output "OK: 7-Zip was not found. No action required"
		Exit 0
    }
}
catch{
    $errMsg = $_.exeption.essage
    Write-Output $errMsg
    exit 1
}
