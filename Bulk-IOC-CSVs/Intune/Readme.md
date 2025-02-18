# Intune Stuff!  

# Browser Extensions 
Browser extension [whitelisting](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Intune/WhitelistedExtensionIDs.md) is MUCH better than [blacklisting](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Intune/Intune%20Browser%20Extension_IDs_the_user_should_be_prevented_from_installing.csv). However if this is something you are struggling to achieve, this list may give you a good starting point for both options.  
> Alternatively consider Edge For Business which can provide a flow for users to request browser extensions natively. See [Edge For Business Config](#Edge-For-Business-Config)
> ![image](https://github.com/user-attachments/assets/2058794f-8819-48cc-9975-3cb544dc262c)
> ![image](https://github.com/user-attachments/assets/57b4e829-9938-4c7f-9a14-ca4d8d01b405)


I've included in my blocklist:  

VPNs, crypto, ungoverened AI (including grammarly), Piracy and screen wake tools 

I Created a variant of [OpenIntuneBaseline](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/blob/main/WINDOWS/IntuneManagement/SettingsCatalog/Win%20-%20OIB%20-%20Microsoft%20Edge%20-%20U%20-%20Extensions%20-%20v3.1.json) for Browser extensions for Device as I needed a variant for AVD with my own whitelisting, if its useful feel free to use!

If you don't have MDE TVM Bolt on the following KQL may be useful for hunting for CRX Downloads for chromium based browsers:

```
let UnsanctionedExtensions = externaldata (ExtensionID: string) [@'https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Intune/Intune%20Browser%20Extension_IDs_the_user_should_be_prevented_from_installing.csv'] with (format=txt);
DeviceFileEvents
| where TimeGenerated > ago(90d)
| where ActionType == "FileCreated"
| where FileName endswith ".crx"
//| where InitiatingProcessFileName == "chrome.exe" //if you need to filter down to chrome vs edge
| where FolderPath contains "Webstore Downloads"
| extend ExtensionID = trim_end(@"_\d{2,6}.crx", FileName)
| extend ExtensionURL = strcat("https://chrome.google.com/webstore/detail/",ExtensionID)
| extend EdgeExtensionURL = strcat("https://microsoftedge.microsoft.com/addons/detail/",ExtensionID)
| extend RiskyExtension = iff((ExtensionID in~(UnsanctionedExtensions)), "Yes","N/A")
| summarize count() by ExtensionID,ExtensionURL, EdgeExtensionURL, RiskyExtension
//| where ExtensionID != "kbfnbcaeplbcioakkpcpgfkobkghlhen" //Grammarly
//| where RiskyExtension == "Yes"
```

If you have the TVM bolt-on then Browser Extension hunting is trivial in Advanced Hunting (no native Sentinel Connector yet)

```
let UnsanctionedExtensions = externaldata (ExtensionID: string) [@'https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Intune/Intune%20Browser%20Extension_IDs_the_user_should_be_prevented_from_installing.csv'] with (format=txt);
DeviceTvmBrowserExtensions
//| join UnsanctionedExtensions on $left.ExtensionId == $right.ExtensionID
| summarize count() by ExtensionId, BrowserName, ExtensionName,ExtensionDescription
```

To just view the List of extensions and the URLs, you can export this List and then Run the ExtensionNameGrabber.py: 
```
let UnsanctionedExtensions = externaldata (ExtensionID: string) [@'https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Intune/Intune%20Browser%20Extension_IDs_the_user_should_be_prevented_from_installing.csv'] with (format=txt);
UnsanctionedExtensions
| extend ExtensionURL = strcat("https://chrome.google.com/webstore/detail/",ExtensionID)
```
Example of Named list [here](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Intune/Unsanctioned_extensions_with_names.csv) 

# Edge For Business Config
> Also Known as Microsoft Edge Management Service

Allows you to quickly build a baseline for Edge For Business which is heavily based of [Open Intune Baseline, see my fork here](https://github.com/jkerai1/OpenIntuneBaseline). Import the [Profile JSON](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Intune/Edge%20for%20business%20Config%20Profile.json) from https://admin.microsoft.com under Settings > Microsoft Edge


You'll need to create an empty profile first to import it too

![image](https://github.com/user-attachments/assets/4ddcadbe-7b32-4a98-8d3c-c751bf701d4a)

Then you can hit import 

![image](https://github.com/user-attachments/assets/3cdd98ea-86f3-40b9-a8de-159c8daaeb63)

This is only merely a baseline, do not blindly roll out to all groups (by default it will not apply to any groups). You will need to configure extensions manually (I've left in some extensions I allow/use and also demonstrate how to do minimium extension version). 
> I block the profile creation plane because creation of a new profile can affect settings in the Edge for business work profile

You may want to unblock 3rd party LLMs too though if you use them. At current it blocks chat.openai.com but not chatgpt.com or chatgpt.es 🙄 (I have fed this back) . I have added these blocks manually to this baseline as well as a few other good sites to block such as pastebin, onionmail.   

> Note they fixed chatgpt domains however some more risky LLMs like deepseek are still missing  

![image](https://github.com/user-attachments/assets/27f50ea0-84d0-456d-b53c-4d9c0d90fad6)  
> You'll need to consider conflicts between Edge For Business and Intune Edge policies and which one will take precedence.
![image](https://github.com/user-attachments/assets/d20b8c92-fded-4d74-bccc-9a56ab7cb0e4)  
> If you use enrollment token you'll also need chose the priority here also  
![image](https://github.com/user-attachments/assets/7a38daf6-0647-4218-b0b2-979c64f8fc2b)  

Also note that because I have denied the ability to delete history this prevents the sync of history & open tabs to the profile, pro vs con. Feel free to remove this setting.  

Also consider leveraging the built in applocker policy to block non-edge browsers which is found under "Customization Settings" > Security Settings > "Additional Settings"

![image](https://github.com/user-attachments/assets/97b10191-a901-40a4-a7fa-623af0f7cd7f)

This in the background creates an Intune policy called "Block Third Party Browsing - Microsoft Edge management service" with Custom-OMA URI of ./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/MicrosoftEdgeManagement1/EXE/Policy & ./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/MicrosoftEdgeManagement2/StoreApps/Policy:  

![image](https://github.com/user-attachments/assets/f220f9e1-28f6-4e3f-baca-a60b3340d569)
> The XML can be found [here](https://github.com/jkerai1/SoftwareCertificates/tree/main/Browsers#browser-applocker-example-----non-edge-browsers)

I've left in ChromeExtension API Blocked permissions (such as ones that have ability to modifiy cookies and history - some are only available on chromeOS but there is no harm in including these here) in case for future usage and your organisation has no flow for picking up user requested extensions. The API Reference can be found here: https://developer.chrome.com/docs/extensions/mv2/reference

If you need to figure out what permission maps to the manifest, hop into developer mode

![image](https://github.com/user-attachments/assets/69f6d107-8091-405e-8f25-0bcbd2d956e4)


and then run 
```
chrome.runtime.getManifest()
```

BitWarden           | NordVPN
:-------------------------:|:-------------------------:
![image](https://github.com/user-attachments/assets/8201b90f-a9dd-4a38-b924-3e6c28c509f2) | ![image](https://github.com/user-attachments/assets/37ba05af-e55c-40aa-8188-c9f54c25da19)
  


# HostFile  

Extra blocking via HostFiles if MDE IOC is not an option, with some example sites you probably should be blocking    

![image](https://github.com/user-attachments/assets/ac7121b5-a1d2-4a1c-8725-bbc90f194280)
> Reference https://www.nielskok.tech/intune/set-hosts-file-via-intune/  

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
| summarize make_list(DeviceName) by FileName, InitiatingProcessFileName,ProcessVersionInfoCompanyName //, ProcessCommandLine
```

![image](https://github.com/user-attachments/assets/13c0059d-af09-430a-818a-8862d3664895)



