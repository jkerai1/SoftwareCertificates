#===================================================================================
#
# Script Name  : 7zip-enable-motw-detect-remediate.ps1
# Description  : Enable the MOTW (mark-of-the-web) setting in 7-Zip, if it is present
# Notes        : 
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
        #write-host "DEBUG: 7-Zip is present in registry"

        try{  
            Get-ItemProperty -Path "$regpath\$valueKey" -Name $valueName -ErrorAction Stop | Out-Null

            $currentValue = Get-ItemProperty -Path "$regpath\$valueKey" | Select-Object -ExpandProperty $valueName -ErrorAction SilentlyContinue
            if ($currentValue -eq $requiredvalue) {
                Write-Host "DEBUG: 7-Zip already has MOTW enabled. No action required"
            } else {
                Write-Host "DEBUG: 7-Zip Reg value exists, but MOTW is not enabled"
                Write-Host "DEBUG: 7-Zip Current value: $currentValue"
                Write-Host "DEBUG: 7-Zip Required value: $requiredValue"
            } 
        }  
        catch [System.Management.Automation.ItemNotFoundException] {  
            Write-Host "DEBUG: 7-Zip MOTW is not enabled"

            Write-Host "DEBUG: Creating registry key : $regpath\$valueKey"
            New-Item -Path "$regpath\$valueKey" -Force

            Write-Host "DEBUG: Setting value for key : $requiredValue"
            New-ItemProperty -Path "$regpath\$valueKey" -Name $ValueName -Value $requiredValue -Type DWord -Force  
        }  
        catch {  
            #New-ItemProperty -Path $KeyPath -Name $ValueName -Value $ValueData -Type String -Force  
        }
    } else {
        # 7-Zip is not present
        Write-Output "Missing: 7-Zip was not found. No action required"
		Exit 0
    }
}
catch{
    $errMsg = $_.exeption.essage
    Write-Output $errMsg
    exit 1
}
