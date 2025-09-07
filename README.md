[![GitHub stars](https://img.shields.io/github/stars/jkerai1/SoftwareCertificates?style=flat-square)](https://github.com/jkerai1/SoftwareCertificates/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/jkerai1/SoftwareCertificates?style=flat-square)](https://github.com/jkerai1/SoftwareCertificates/network)
[![GitHub issues](https://img.shields.io/github/issues/jkerai1/SoftwareCertificates?style=flat-square)](https://github.com/jkerai1/SoftwareCertificates/issues)
[![GitHub pulls](https://img.shields.io/github/issues-pr/jkerai1/SoftwareCertificates?style=flat-square)](https://github.com/jkerai1/SoftwareCertificates/pulls)

![TotalCountofSoftwareCertificates](https://img.shields.io/badge/TotalCountofSoftwareCertificates-768-green)
# SoftwareCertificates  

Repository for Software Certs for easy software blocking (or allowing) across corp environments, for example, using [MDE IOC](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/indicator-certificates?view=o365-worldwide)/AppLocker/[WDAC](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac-and-applocker-overview)/ Intune Remediation Script/ Intune EPM (I would recommend Reusable settings here)     

> WDAC is the preferred and best method for blocking executables but can be a monster to tackle and maintain with the possibility to brick a machine, if you need intend to rollout WDAC I recommend to check this [out](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/WDACConfig) before doing so. I have written a blog post about WDAC [here](https://www.linkedin.com/posts/jay-kerai-cyber_intune-opensource-appcontrol-activity-7286366737460002816-6p-b/) also  

:warning:__Caution__: Some Certs for unsanctioned applications may be used for other applications from the same org that may be legitimate e.g. BlueJeans Conferencing (sanctioned) BlueJeans Remote Desktop Control (unsanctioned) :warning:

:warning: Please do not upload these certs en masse without checking, you may be impacting a user or service - there is no native way to bulk upload indicators in the MDE portal!:warning:

App Ref: https://appwiki.checkpoint.com/appwikisdb/public.htm  or https://getintopc.com/all-software-categories/

Of course there are ways around Cert Blocking (e.g. ImageRemoveCertificate API, signTool, wait for certificate thumbprint to rotate, SigThief, delcert - more opportunities for detection😉). See [Testing Manipulated Executables](https://github.com/jkerai1/SoftwareCertificates/tree/ManipulatedExes/Manipulated%20Exes%20For%20Testing)  



Useful Ref For Programs people install on fresh desktop: https://ninite.com/ (also worth blocking ninite's cert)  
# How to block a certificate in MDE?  

> Note that Certificate thumbprints will rotate as certificates are rolled so this is NOT the best way to block applications, WDAC is the best preferred method to block applications, see early note on WDAC. After you block a certificate ensure to block any URLs the user may grab the executable from to prevent rolled certificates.    


Download the Repo by hitting the "Code button" then "[Download Zip](https://github.com/jkerai1/SoftwareCertificates/archive/refs/heads/main.zip)"  

Unzip the downloaded folder  

![image](https://github.com/jkerai1/SoftwareCertificates/assets/55988027/95a7565b-cde4-4314-b4c1-3fc453b42b09)

From [Defender](https://security.microsoft.com) navigate to Settings > Endpoints > Indicators and then the "certificates" tab on the right of the sub menu  

![image](https://github.com/jkerai1/SoftwareCertificates/assets/55988027/145b27f1-4770-46f2-b9ce-39c84b87bb20)

Then hit "add Item" next to the plus  

Browse for the certificate from the unzipped folder. Fill in the title and description

![image](https://github.com/jkerai1/SoftwareCertificates/assets/55988027/24aa1f5f-123e-437c-a5ac-ca01ed61013f)

Hit Next. The default mode is "allow" so change this to "Block And Remediate" and then hit next

![image](https://github.com/jkerai1/SoftwareCertificates/assets/55988027/74227ca9-da26-4bdb-a719-ac301303a022)

Set the Scope of the block, then hit "next" and then "finish"

Example:  
![image](https://github.com/jkerai1/SoftwareCertificates/assets/55988027/7352a94b-1bf5-41b0-b26c-6acd118a27c4)


# To Export Software Certificates - Pull Requests Welcome:

**Looking to automate this process with Python but for now see below**  

Right Click on Exe, Select Properties:

Go To Digital Signature Tab:  
![image](https://user-images.githubusercontent.com/55988027/222768857-102613c0-fa21-4193-aca8-4682a5439604.png)


Click details then View Certificate:  

![image](https://user-images.githubusercontent.com/55988027/222768203-9015f003-8f3f-4823-af34-c06a3d897d0b.png)  
![image](https://user-images.githubusercontent.com/55988027/222769196-22285fb2-c829-4a28-a655-8909cacc6c4a.png)

Details Tab:  
![image](https://user-images.githubusercontent.com/55988027/222769122-882f8644-b232-4d18-900a-ee930d286343.png)


Copy To File:  
![image](https://user-images.githubusercontent.com/55988027/222768521-e6df24dc-76b2-46c7-b8d2-8c5d02c8337e.png)

Export as Cer:  
![image](https://user-images.githubusercontent.com/55988027/222768623-1c6c9523-19ff-4d0f-a7ce-623036ed77fa.png)  

# KQL

Monitor Blocks - Sentinel + DeviceFileCertificateInfo Table:
```
DeviceEvents
| where (ActionType == "SmartScreenUrlWarning" and AdditionalFields.Experience == "CustomBlockList") or (AdditionalFields.ThreatName contains "EUS:Win32/Custom" and ActionType == "AntivirusDetection") or (AdditionalFields.ResponseCategory == "CustomBlockList" and ActionType == "ExploitGuardNetworkProtectionBlocked")
| join kind=leftouter DeviceFileCertificateInfo on SHA1
|extend VT_hash = iff(isnotempty(SHA1),strcat(@"https://www.virustotal.com/gui/file/",SHA1),SHA1)
|extend VT_domain = iff(isnotempty(RemoteUrl),strcat(@"https://www.virustotal.com/gui/domain/",RemoteUrl),RemoteUrl)
| summarize by FileName, RemoteUrl,DeviceName, Signer, InitiatingProcessAccountName, InitiatingProcessFileName, SHA1, VT_hash, VT_domain
```
> Note you cannot use DeviceNetworkEvents for this because of how MDE performs TCP handshake  

If you don't ingest  DeviceFileCertificateInfo to sentinel you can use Advanced Hunting instead:

```
DeviceEvents
| where (ActionType == "SmartScreenUrlWarning" and todynamic(AdditionalFields).Experience == "CustomBlockList") or (todynamic(AdditionalFields).ThreatName contains "EUS:Win32/Custom" and ActionType == "AntivirusDetection") or ((todynamic(AdditionalFields).ResponseCategory) == "CustomBlockList" and ActionType == "ExploitGuardNetworkProtectionBlocked")
|extend VT_hash = iff(isnotempty(SHA1),strcat(@"https://www.virustotal.com/gui/file/",SHA1),SHA1)
|extend VT_domain = iff(isnotempty(RemoteUrl),strcat(@"https://www.virustotal.com/gui/domain/",RemoteUrl),RemoteUrl)
| join kind=leftouter DeviceFileCertificateInfo on SHA1
| summarize by FileName, RemoteUrl,DeviceName, Signer, InitiatingProcessAccountName, InitiatingProcessFileName, SHA1, VT_hash, VT_domain
```
Find Unusual Software Certificates:

```
DeviceFileCertificateInfo
| join DeviceFileEvents on SHA1
//|extend VT_hash = iff(isnotempty(SHA1),strcat(@"https://www.virustotal.com/gui/file/",SHA1),SHA1)
| summarize count() by Signer //FileName,SHA1,Issuer,FileOriginUrl
| where Signer !contains "Google "
| where not(Signer has_any("Intel","fortinet",".net","citrix","microsoft","HP Inc.","adobe","cisco","Avaya Inc.","Zoom Video Communications, Inc.","zscaler","oracle","Advanced Micro Devices Inc.","Lenovo","Hewlett-Packard Company","RingCentral","Symantec","Mozilla","Dell Technologies Inc.")) 
| order by count_
```

# How to Upload the Bulk IOC CSV to MDE (Bulk-IOC-CSVs Folder)  

⚠️ Potential Business Impact if you upload without running a KQL against the CSV first

As of 13/03/2023, certificates cannot be uploaded in bulk, however for domains, urls and hashes and note there is a limit of 500 for bulk upload, the current typosquat lists will not work as they are too large:  

> Also note all Block lists with merge with MDA Unsanctioned apps so no need to deduplicate manually

Find the CSV of interest (after checking for business impact by checking it with a KQL query) and click on download from the [Bulk-IOC-CSVs Folder](https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs)  

![aaadsa](https://github.com/user-attachments/assets/465eec64-19db-486d-b491-26cc50d610f1)

> Note that the raw button will take you to the raw table, it is the URL of this that you need to ingest as KQL, see [example](https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs#devicenetworkevents-example-kql)

From Defender, Go To Settings on bottom left:  
![image](https://user-images.githubusercontent.com/55988027/224496554-e26e2672-6216-4694-ab8a-015d0c08451a.png)

Then Endpoints:  
![image](https://user-images.githubusercontent.com/55988027/224496573-0a89865c-e882-4eb8-9172-aa3e5a1ba430.png)  

Indicators then Import - note it it doesn't matter whether you are in File Hash,Domain, IP or Cert tab:  

![image](https://user-images.githubusercontent.com/55988027/224496619-136fbd3f-7b3a-405f-9b85-edb993c42e94.png)  

Choose the File you downloaded in the first step, then hit Import then Hit Done - note that duplicates are skipped so you can keep adding to the existing CSV:    

![image](https://user-images.githubusercontent.com/55988027/224496768-7ff90df4-66b2-4398-8307-f424a9ac0303.png)  

# Python Bulk Ripper  

Work In Progress  


# Testing Tampered Executables  
[https://github.com/jkerai1/SoftwareCertificates/tree/main/Manipulated%20Exes%20For%20Testing  ](https://github.com/jkerai1/SoftwareCertificates/tree/ManipulatedExes/Manipulated%20Exes%20For%20Testing)

[See also A good article on abusing code signing certs](https://axelarator.github.io/posts/codesigningcerts/)  

# Stop Users Walking past blocks  

Make sure users cannot override SmartScreen setting in windows settings – lives under App and Browser Control.  
Unticking Smartscreen for edge allows access the custom IOCs because they share the same service (this can be noted in the KQL also)    

![image](https://github.com/user-attachments/assets/3ca1bb3d-c8bc-456a-8733-30d653c196f3)

![image](https://github.com/user-attachments/assets/07d66095-06a7-490c-9b85-8e77d3f5ce07)

Some 3rd party browsers can walk past URL blocks, Seamonkey for example.

# MDA  

https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/MDA  

# Intune  

https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/Intune  

# See More From Me on IOC Blocking!  

[Block TypoSquats in MDE/TABL](https://github.com/jkerai1/DNSTwistToMDEIOC) [![GitHub stars](https://img.shields.io/github/stars/jkerai1/DNSTwistToMDEIOC?style=flat-square)](https://github.com/jkerai1/DNSTwistToMDEIOC/stargazers)  
[Block Malicious Sites from JoeSandbox in MDE/TABL](https://github.com/jkerai1/JoeSandBoxToMDEBlockList) [![GitHub stars](https://img.shields.io/github/stars/jkerai1/JoeSandBoxToMDEBlockList?style=flat-square)](https://github.com/jkerai1/JoeSandBoxToMDEBlockList/stargazers)  
[Block Suspicious TLDs in TenantAllowBlockList](https://github.com/jkerai1/TLD-TABL-Block) [![GitHub stars](https://img.shields.io/github/stars/jkerai1/TLD-TABL-Block?style=flat-square)](https://github.com/jkerai1/TLD-TABL-Block/stargazers)


