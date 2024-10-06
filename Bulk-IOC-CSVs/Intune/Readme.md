# Intune Stuff!  

# Browser Extensions 
Browser extension [whitelisting](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Intune/WhitelistedExtensionIDs.md) is MUCH better than [blacklisting](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Intune/Intune%20Browser%20Extension_IDs_the_user_should_be_prevented_from_installing.csv). However if this is something you are struggling to achieve, this list may give you a good starting point for both options.  

I've included in my blocklist:  

VPNs, crypto, ungoverened AI (including grammarly), Piracy and screen wake tools 

I Created a variant of [OpenIntuneBaseline](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/blob/main/WINDOWS/IntuneManagement/SettingsCatalog/Win%20-%20OIB%20-%20Microsoft%20Edge%20-%20U%20-%20Extensions%20-%20v3.1.json) for Browser extensions for Device as I needed a variant for AVD with my own whitelisting, if its useful feel free to use!

If you don't have MDE TVM Bolt on the following KQL may be useful for hunting for CRX Downloads:

```
let UnsanctionedExtensions = externaldata (ExtensionID: string) [@'https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Intune/Intune%20Browser%20Extension_IDs_the_user_should_be_prevented_from_installing.csv'] with (format=txt);
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".crx"
//| where InitiatingProcessFileName == "chrome.exe"
| where FolderPath contains "Webstore Downloads"
| extend ExtensionID = trim_end(@"_\d{5}.crx",FileName)
| extend ExtensionURL = strcat("https://chrome.google.com/webstore/detail/",ExtensionID)
| extend RiskyExtension = iff((ExtensionID in~(UnsanctionedExtensions)), "Yes","No")
| summarize count() by ExtensionID,ExtensionURL, RiskyExtension
```

# List of disallowed applications (User)

With regards to blocking process names, this is a weak policy and can be bypassed as it runs in user context and only applicable to file explorer however can add an extra layer if WDAC is not an option.

This Setting can be nice to layer but reality is it can be bypassed easily. The corresponding Reg key lives in User land also.    

"This policy setting only prevents users from running programs that are started by the File Explorer process. It doesn't prevent users from running programs, such as Task Manager, which are started by the system process or by other processes. Also, if users have access to the command prompt (Cmd.exe), this policy setting doesn't prevent them from starting programs in the command window even though they would be prevented from doing so using File Explorer."  

https://learn.microsoft.com/en-gb/windows/client-management/mdm/policy-csp-admx-shellcommandpromptregedittools?WT.mc_id=Portal-fx#disallowapps

```
let DisallowedProcessNames = externaldata (DisallowedProcess: string) [@'https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Intune/DisallowedProcessList.txt'] with (format=txt);
DeviceProcessEvents
| where TimeGenerated > ago(90d)
| where FileName in~(DisallowedProcessNames) or InitiatingProcessFileName has_any(DisallowedProcessNames)// or InitiatingProcessCommandLine has_any(DisallowedProcessNames)
| summarize count() by FileName, InitiatingProcessFileName,ProcessVersionInfoCompanyName //, ProcessCommandLine

```

![image](https://github.com/user-attachments/assets/13c0059d-af09-430a-818a-8862d3664895)

