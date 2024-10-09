# Collection of useful resources for MDA/ Defender for Cloud Apps / DfCA / MCAS

Not a comprehensive list, just some ideas of the capability of Defender for Cloud Apps (MDA) and some of the settings you may have missed. I truly think MDA is underrated and underutilized by E5 Customers.  
>When creating policies leverage "edit and preview results" and "view policy matches" prior to deploying or deploy in alert/monitor only to reduce potential business impact.  

- [Access Policy](#access-policy)
  * [Block Anonymous IPs](#block-anonymous-ips)
  * [Block user Agents](#block-user-agents)
- [Session Policy](#session-policy)
  * [Block malware Upload](#block-malware-upload)
  * [Block malware download](#block-malware-download)
  * [Block Suspicious File Extension Upload](#block-suspicious-file-extension-upload)
  * [Copy Paste of Credit Card Numbers](#copy-paste-credit-card-numbers)
  * [Require step up if Sending ethereum Address](#require-step-up-if-sending-ethereum-address)
- [App Discovery Policy](#app-discovery-policy)
  * [Auto Block Risky apps](#auto-block-risky-apps)
  * [Auto Unsanction Web Mail](#auto-unsanction-web-mail)
  * [Auto ban Discovered File Transfer apps](#auto-ban-discovered-file-transfer-apps)
  * [Auto ban Discovered Paste apps](#auto-ban-discovered-paste-apps)
  * [Auto ban Discovered Risky Generative AI](#auto-ban-discovered-risky-generative-ai)
  * [Monitor Cloud Storage](#monitor-cloud-storage)
- [Anomaly Detection Policy](#anomaly-detection-policy)
- [Activity Policy](#activity-policy)
  * [Dark Web Monitoring](#dark-web-monitoring)
- [File Policy](#file-policy)
  * [Externally shared source code](#externally-shared-source-code)
  * [File Shared with Personal Email Address](#file-shared-with-personal-email-address)
- [Malware Detection Policy](#malware-detection-policy)
- [Block Script Baseline](#block-script-baseline)
- [App Governance](#app-governance)
  * [Disable Overprivileged App](#disable-overprivileged-app)
  * [Disable High privileged new app](#disable-high-privileged-new-app)
  * [Other policies](#other-policies)
- [Misc](#misc)
  * [Add IP Range for Usage in policies](#add-ip-range-for-usage-in-policies)
  * [Enforce MDA Blocks to MDE](#enforce-mda-blocks-to-mde)
  * [Information Protection](#information-protection)
  * [User Monitoring](#user-monitoring)
  * [File Monitoring](#file-monitoring)
  * [App Onboarding and Maintenance](#app-onboarding-and-maintenance)
  * [Unified Audit Log](#unified-audit-log)
  * [Import Entra Groups](#import-entra-groups)
  * [Integrate with 3rd party Secure Web Gateways For Discovery](#integrate-with-third-party-secure-web-gateways-for-discovery)
  * [Integrate with SaaS Security Posture](#integrate-with-saas-security-posture)
  * [Integrate with Power Automate for alerting](#integrate-with-power-atomate-for-alerting)


Most of the policies below can be built from a policy template. For some reason, access policy/Anomaly Detection Policy does not have a template.  
Navigate to Cloud Apps > Policies > Policy Management to create a new policy or build a policy by selecting template. 


# Access Policy
When Conditional access hands over control to MDA these will then apply, ensure you have a policy to actually send the user to MDA. You will also need this for [Session Policy](#session-policy)

![image](https://github.com/user-attachments/assets/317f1a1e-6fd6-42c6-8ae6-89db26c21ef7)


*Note*: Just because you fail to pass Access policy, it will still show as success in conditional access because Conditional Access successfully handed the session over. You'll need to review the Cloud App > Activity Log from Defender Portal in these scenarios.The Activity Type will be "Log On"

![image](https://github.com/user-attachments/assets/f137756f-8bf9-4c61-89a0-de9a5200f9be)

Alternatively KQL :oncoming_police_car: Query for monitoring Sign-ins to Session Control:
```
CloudAppEvents
//| where ObjectName contiains @"kerai" //filter for username here
| where AuditSource == @"Defender for Cloud Apps access control"
| where ActivityType == @"Login"
//if you want to explore negative values in the LastSeenForUser, Uncomment the below
//| extend SessionId = tostring(SessionData.InLineSessionId)//
//| extend parsedJson = parse_json(LastSeenForUser)  // Parse the JSON column
//| mv-expand dynamic_fields = bag_keys(parsedJson)  // Get all keys dynamically
//| extend value = parsedJson[tostring(dynamic_fields)]  // Extract values for each key
//| where (value) < 0  // Filter out values that are negative
| summarize count() by tostring(LastSeenForUser), ObjectName, tostring(IPTags), ActionType, Application, IsAdminOperation, tostring(UserAgentTags), CountryCode//, SessionId, UserAgent
```

Also note that not all apps are natively supported for MDA Onboarding - e.g. some of  AI/data related portals such 
- ml.azure.com
- customvision.ai
- videoindexer.ai
- web.azuresynapse.net
- speech.microsoft.com
- adf.azure.com
- language.cognitive.azure.com
- cosmos.azure.com

and legacy portals such as 
- oai.azure.com
- admin.cloud.microsoft

Some others include 
- lighthouse.microsoft.com
- mystaff.microsoft.com  (Does anyone actually use this?)
- Viva / Viva Insights (but Viva Engage does work)
- loop.cloud.microsoft

My conclusion is that MDA handover is NOT fit for AI developers and I'd probably go with WVD/AVD instead especially given the data access they may have. Though many of the AI portals are unifying now. A fast way to onboard apps quickly into MDA is to open them all using something like [MSPortals-io](https://msportals.io) after creating a conditional access policy with a session control of "monitor only" scoped to the user doing the onboarding. Add the onboarding user under [App Onboarding and Maintenance](#app-onboarding-and-maintenance) to reduce any potential impact which provides them with the option to bypass if they need to continue doing work. After you have finished onboarding all the apps and created your policies you can go back to the conditional access policy and scope the Session control to custom. Once testing of that is finished you can go back and scope users/apps and exclude any Corporate owned and/or compliant devices. Then clear down any users who can bypass and switch these to an emergency account.

![image](https://github.com/user-attachments/assets/b6b61e28-98b2-4f61-bf21-7cf9e1924f94)

Some apps for some reason do not even prompt me for onboarding despite having a Conditional access policy scoped to all apps such as 
- ADX (dataexplorer.azure.com)
- azureiotcentral.com
- ea.azure.com


For a pilot run you are best scoping just to Office365 in Conditional access. Admin Portals also works if you allow admins to sign-in from BYOD/non-entra Join device. A Conditional Access Policy scoped to these two is what have I have been testing and it has worked out great so far.

The finished List - 38 Items - It's possible I missed a few or some more have become available post writing this. You will not need all of these as some are legacy portals.  

This list can be found under Settings > Cloud Apps > Conditional Access App Control Apps:

Page 1             |  Page 2
:-------------------------:|:-------------------------:
![image](https://github.com/user-attachments/assets/8f85c792-81a0-4f6a-ad38-47897cc82f8c)|  ![image](https://github.com/user-attachments/assets/2d80230f-4a90-43ea-ae1f-a02c8b94b3b3)

All other [3rd party apps will need to be onboarded with SAML](https://learn.microsoft.com/en-us/defender-cloud-apps/proxy-deployment-featured-idp) from Settings > Cloud Apps > Conditional Access App Control Apps:
![image](https://github.com/user-attachments/assets/a4d84b59-91c3-41ef-be90-23bd4ec30e95)

Note that just because many microsoft apps didn't work, this is still coverage to put damage control for Adversary in the middle (AiTM) type phishing as this typically targets Officehome (Office365). If you want to learn more about AiTMs, I'd encourage you to check out my talk on [M365-Security-&-Compliance-User-Group](https://github.com/jkerai1/So-You-ve-Got-MFA-Defending-and-Responding-Against-MFA-Bypass-Techniques-in-Entra)

## Block Anonymous IPs

I'd consider blocking anonymous proxy ,abused hosting 🌩️ (LeaseWeb,OVH, Cloudiver, Digital Ocean, Host Royale, Linode, Cloudflare), Tor/Darknet IPs/Password Spray attacker to be the bare minimum (if it makes sense in your environment of course!!!)
Real shame theres a few abused hosting Providers missing such as hostwinds. Malware C&C/Ten Cent/Sharktech/Alibaba/baCloud/Brute Force Attacker is also not a bad shout here.  

🤔 I want explore the "no tag", dedicated server hosting, Cloud hosting Tags ☁️ to see their impact. These could have their use-cases in the right environments especially when leveraged when scoping to [Entra Groups](#import-entra-groups)  

🛑 I would not recommend trying to do country Locations in MDA Access Policy, this is better suited to Conditional access as then you can hit all users and all apps.  

Country sign-in Conditional access KQL :oncoming_police_car::
```
let CountryCodes = externaldata (country: string,countryOrRegion:string) [@'https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/refs/heads/master/all/all.csv'] with (format=csv, ignoreFirstRecord=True);
SigninLogs
| where TimeGenerated > ago(90d)
| where ResultType == 0
| where isnotempty(countryOrRegion)
| extend countryOrRegion = tostring(LocationDetails.countryOrRegion)
| join kind = leftouter CountryCodes on countryOrRegion
| summarize count() by country, UserPrincipalName
| where country <> "United Kingdom of Great Britain and Northern Ireland"
```

![image](https://github.com/user-attachments/assets/f7623cac-9790-48fa-9060-18b3fa708175)
![image](https://github.com/user-attachments/assets/772da56c-7d87-473b-a15f-42c6663bdd5b)


My KQL :oncoming_police_car: Take on [KQL Consumer VPN Hunting Reference](https://www.kqlsearch.com/query/Consumer%20Vpn%20Logins&clx4u4q3800065iio1udg95wl):
```
let VPNRanges = externaldata (IpRange: string) [@'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt'] with (format=txt);
SigninLogs
| where isnotempty(IPAddress)
| evaluate ipv4_lookup(VPNRanges, IPAddress, IpRange)
| join kind=leftouter IdentityInfo on $left.UserPrincipalName == $right.AccountObjectId
| extend Spur = strcat("https://spur.us/context/", IPAddress)
| summarize by UserPrincipalName, IPAddress, UserAgent, AccountUPN, Spur //User Spur to validate data
| extend IP_0_Address = IPAddress
| extend Account_0_Name = UserPrincipalName
| extend Account = iff(isempty( AccountUPN),Account_0_Name,AccountUPN)
```

[MDE BlockList for Consumer VPNs](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Consumer%20VPNs.csv), Audit with below KQL :oncoming_police_car:, you can upload the list afterwards to MDE. [Instructions here](https://github.com/jkerai1/SoftwareCertificates?tab=readme-ov-file#how-to-upload-the-bulk-ioc-csv-to-mde-bulk-ioc-csvs-folder)

```
let VPNIOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Consumer%20VPNs.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = VPNIOCs
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList)
| summarize count() by RemoteUrl
```
Also consider Browser Extension VPNs, if you don't have MDE DeviceTVM bolt on you can leverage KQL :oncoming_police_car: like the following which is from the [intune](https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/Intune) portion of this repo:

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
| where ExtensionID != "kbfnbcaeplbcioakkpcpgfkobkghlhen" //Grammarly
| where RiskyExtension == "Yes"
```

## Block user Agents

List of keywords from unusual User agents :suspect: can be found at: https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/MDA/BannedUserAgentsList.txt

__Note about user agents:__  Spaces have been included in some user agents to future proof any overlapping strings.    

Some of these User Agents will not be supported in Azure portal natively such as seamonkey. Not all are Browser based, some are OS based and some are just bots/scrappers (I've left all in for hunting purposes)
Everything after the first 30 entries or so is tending to the more niche categories. If you really need to block *ALL* user agents except Edge just Enforce Edge for business instead (Settings > Cloud Apps > Edge For Business Protection) (See Below)

Reference https://whatmyuseragent.com/browser

![Opera block](https://github.com/user-attachments/assets/385cd08f-144c-44d6-8bea-d67542e718ff)

Advanced Hunting KQL :oncoming_police_car: to hunt for these user agents - and yes Steam in-game browser does have its own unique user agent:
```
let UserAgents = externaldata(UserAgent: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/MDA/BannedUserAgentsList.txt"] with (format="txt", ignoreFirstRecord=False); //I switched to txt after some time so ignore the inconsistency with the screenshot
AADSignInEventsBeta
//| where ErrorCode == 0 //Uncomment if you only want successes
| where UserAgent has_any(UserAgents)
| summarize count() by UserAgent //https://user-agents.net/lookup can be a good reason to lookup strings or https://useragents.io/parse
//| summarize count() by UserAgent,AccountUpn,Application //Uncomment to see users and applications
```
![User Agents Test](https://github.com/user-attachments/assets/23d5a733-074a-43cd-b1d4-8a8e50927a84)


Edge For Business Enforcement (Preview):

Settings > Cloud Apps > Edge For Business Protection


![image](https://github.com/user-attachments/assets/36db23a5-65f5-45a3-a54c-f3fd4f7b58ba)


The default block message isn't super useful so I would consider customizing this
![image](https://github.com/user-attachments/assets/981b632a-8ce0-4d96-a1b8-be28363beb2d)  

Also note when you use Edge for business, browser tools (i.e. when you hit F12) will not be available which makes perfect sense as that provides a bypass path to the proxy. This also means Device Emulation/native User Agent switching will not be possible which is a nice bonus.

See More Browser Blocking stuff here:  
[Certificates](https://github.com/jkerai1/SoftwareCertificates/tree/main/Browsers)  
[Domains/URLs](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Browser%20IOCs.csv)  
[User Agent KQL :oncoming_police_car: Parser](https://www.kqlsearch.com/query/Identity-parseuseragent&clmoxrwnu002tmc0k2lnnqbnz)

# Session Policy  

You can also leverage [Purview](https://learn.microsoft.com/en-us/defender-cloud-apps/use-case-proxy-block-session-aad#create-a-block-download-policy-for-unmanaged-devices), block upload/download of file extensions etc (perhaps .doc,.pdf etc.). Malware Upload/Download should be bare minimium. See note above about conditional access to handover session, that is prerequisite here also.  

Policy Templates are available via:  

![image](https://github.com/user-attachments/assets/79b8a3ed-d6ce-4eba-9195-89ecd401975b)


## Block malware Upload
![image](https://github.com/user-attachments/assets/a1bf7a05-fbbc-4e42-a7ff-c4de3adbfec0)
![image](https://github.com/user-attachments/assets/f8d33b1a-05a1-4ee7-88b5-4c7997ab37e9)


## Block malware download
![image](https://github.com/user-attachments/assets/a535b0d3-943b-4d16-a48d-172a51ec46ac)

![image](https://github.com/user-attachments/assets/dd7da79a-ef96-47c5-a2cd-a06a24532f51)

[A suspicious files extension if you need it](https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/MDA/SuspiciousFileExtensions.txt)

## Block Suspicious File Extension Upload

Start building the policy with "Block upload based on real-time content inspection" template. I then remove Data Classification Inspection method as we don't need that. Then from "Filers", select "extension" and start adding in the extensions.  

[A suspicious files extension if you need it](https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/MDA/SuspiciousFileExtensions.txt)

Office 🏢 Activity Suspicious File Extension Upload/Download KQL 🚔

```
let SusFileExtensions = externaldata(Extension: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/MDA/SuspiciousFileExtensions.txt"] with (format="txt", ignoreFirstRecord=False); 
OfficeActivity
| where TimeGenerated > ago(90d)
| where Operation == "FileUploaded" or Operation == "FileDownloaded"
| where SourceFileExtension has_any(SusFileExtensions)
| summarize count() by SourceFileExtension, SourceFileName
```

![image](https://github.com/user-attachments/assets/12f47161-0060-4585-b7ae-e9166bb8e1d9)

![image](https://github.com/user-attachments/assets/e6924d95-a0ac-4b03-aa79-df5082d8bc4a)




## Copy Paste Credit Card Numbers

E.g. blocking Copy paste of Credit Card Numbers

Regex Pattern For Visa Card: ^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$ if you need it for testing  

![image](https://github.com/user-attachments/assets/35977a49-06ea-4ebf-b776-8474acf92f21)

![image](https://github.com/user-attachments/assets/45aa450d-6057-4f87-a8b9-491193954b69)

# Require step up if Sending Ethereum Address

__Note__ step up in Session Policy is in preview  

Force the user into an [authentication context](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#authentication-context) if they send a [ethereum address](blockchain.com), in this case the context is Sign-in Frequency of everytime with passwordless authentication. Leverage with a custom authentication strengths for bonus points. Don't forget to exclude breakglass from Conditional Access when tagging the authentication context.  

ETH Regex Pattern: 0x[a-fA-F0-9]{9}[a-fA-F0-9]{9}[a-fA-F0-9]{9}[a-fA-F0-9]{9}[a-fA-F0-9]{4}  

https://learn.microsoft.com/en-us/defender-cloud-apps/working-with-the-regex-engine, the regex engine seems quite limited, I tried to do ethereum address but hit failure of Quantifiers of type {n,m} n,m must be less than 10 and so yep I tried splitting into blocks of 9️⃣

![image](https://github.com/user-attachments/assets/78e7e3d0-f2c4-48e9-8aee-081aac8d3c5a)

If I hit "Close" I just end up in a prompt loop until I hit "Ok Proceed"
![image](https://github.com/user-attachments/assets/0682cb55-549a-4d53-ac4b-e4778b6a45af)

I actually wasn't allowed back in, might be an issue with the preview. However the point is that someone sending wallet addresses is very suspicious and could be a compromised account so we definitely want to kick them out,note that even though I passed the challenge here the teams message wasn't actually sent.  

![image](https://github.com/user-attachments/assets/9e896a42-6a9e-457a-bc43-32f3fb058767)


# App Discovery Policy

These will scale as apps are added to MDA and users navigate to them. The MDA catalogue is large and grows everyday (33,384 apps currently - even if you tried to block half of these you'd run out of space on MDE IOC as the limit there is 15,000), this is a much more scaleable way to block, if apps are required then sanction them as needed or auto-stick into monitor and review. 
That is to say you don't need to wait for apps to be discovered you can manually unsanction apps before they are even discovered. If you want more ideas of what to manually unsanction check out the [MDA baseline Folder](https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/MDA/MDA-BlockScript-Baseline#going-further)   

⭐ Note that in MDA a ⬆️ higher score means less risky. 🔟 would be a perfect score. The scores are based of General categories (such as diaster recovery, popularity and domain age), security, compliance and legal. You can actually override these if you need to weight more towards one value (lets say you have strict requirement for data at rest being encrypted). This can be done from Settings > Cloud Apps > Score Metrics. Don't forget to hit Save all the way at the bottom after you are done.  
![image](https://github.com/user-attachments/assets/3e701239-65fd-4f40-acf0-6b223b228f63)

Audit your Blocks with the below KQL :oncoming_police_car: :. Smartscreen is used for Edge and Exploit Guard is for 3rd party browsers. In the back-end the blocks are MDE, assuming of course you have remembered to [Enforce MDA Blocks to MDE](#enforce-mda-blocks-to-mde). ❗ Please remember to turn this on or the blocks will not do diddly squat!    

```
DeviceEvents
| where TimeGenerated > ago(90d)
| where (ActionType == "SmartScreenUrlWarning" and AdditionalFields.Experience == "CustomBlockList") or (AdditionalFields.ResponseCategory == "CustomBlockList" and ActionType == "ExploitGuardNetworkProtectionBlocked")
| where tostring(AdditionalFields.DisplayName) has "appName" or isnotempty(tostring(AdditionalFields.ApplicationName))
| extend Application = iff(tostring(AdditionalFields.DisplayName) has "appName",replace_string((tostring(AdditionalFields.DisplayName)),@"appName=",""), (AdditionalFields.ApplicationName))
| extend Application= replace('"', '', Application)
| summarize BlockedURls = make_list(RemoteUrl) by Application
```

## Auto Block Risky apps

![image](https://github.com/user-attachments/assets/68a29e71-f351-4f70-a447-ecb16653461e)

## Auto Unsanction Web Mail

I find 8 to be a good spot for legitimate work email vs personal email. Feel Free to edit this threshold.
Be sure to use the "edit and preview results" to check you are not going to block actual used business mail. Note that Gmail is a 10 so you'll need to unsanction Gmail manually.

![image](https://github.com/user-attachments/assets/dabc23fa-3854-42ce-89e7-73ccffc611c1)


## Auto ban discovered File Transfer apps

You can leverage App Name or Domain Name for Auto discovery Policies.

![image](https://github.com/user-attachments/assets/1ffe7e43-678e-47d3-a431-1f74d53a4d8f)

From Cloud App Catalog We can see the impact if we turn on Advanced Filters:

![image](https://github.com/user-attachments/assets/77b2ce32-eba7-474a-9342-315448f269a8)

This policy will miss a few such as sendnow, sendthisfile, dropsend but these can be done manually or you can create a different policy. You'll want to hit Content Sharing and Cloud Storage categories there.  

## Auto ban discovered Paste apps

❗❗❗❗❗❗❗ I'd HIGHLY recommend blocking at least pastebin as this is often used for exfiltration of data / staging malware payloads (maybe malware payload #1 reaches out to pastebin to get URL for malware payload #2)  

Here it is much safer to enable for both apps and domains: 

![image](https://github.com/user-attachments/assets/8f73a520-ead9-4dc1-9a32-8ea990c0124e)

From Cloud App Catalog We can see the impact if we turn on Advanced Filters:

![image](https://github.com/user-attachments/assets/cab8b03b-d431-478f-b487-6fb7c5202262)

*Note There is only one potential False positive- "Lee Paste" Accounting, risk score 4. You can prematurely mark this as sanctioned/Monitored/Custom Tag if its needed. In the policy you can exclude monitored apps/Custom tags*  

![image](https://github.com/user-attachments/assets/437ffaae-1165-4546-a9d8-f7c91295de81)

See also MDE Blocklist: https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/FileTransfer%20PasteLike%20Sites.csv. Audit with below KQL :oncoming_police_car:, you can upload the list afterwards to MDE. [Instructions here](https://github.com/jkerai1/SoftwareCertificates?tab=readme-ov-file#how-to-upload-the-bulk-ioc-csv-to-mde-bulk-ioc-csvs-folder)


```
let PasteLikeSitesIOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/FileTransfer%20PasteLike%20Sites.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = PasteLikeSitesIOCs
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList )
| summarize count() by RemoteUrl
```

## Auto Ban Discovered Risky Generative AI

OpenAI scores 8️⃣ or 9️⃣ and Copilot scores around 🔟. If you need to block Chatgpt etc I'd block it manually as 9 may be too high for app discovery policy. Bear in mind theres currently 3 OpenAI catergories available  
![image](https://github.com/user-attachments/assets/d7e92b57-1823-45fc-96c8-3638eccadb82)

Also bear in mind savy users might find websites that have chatbots with no content filter so this by no means a substitute for good DLP.  

![image](https://github.com/user-attachments/assets/a36ef817-3fae-4abd-b58e-12de46ae3c86)

A dirty KQL :oncoming_police_car: to search for these - this is by no means a complete list there are just far too many tools (477 GenAI tools currently sitting in MDA catalog)  
As per usual the [MDE Bulk IOC Blocklist](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/PotentiallyUngovernedAITools.csv) is downloadable if you need to import the CSVs for whatever reason. Audit with below KQL :oncoming_police_car:, you can upload the list afterwards to MDE. [Instructions here](https://github.com/jkerai1/SoftwareCertificates?tab=readme-ov-file#how-to-upload-the-bulk-ioc-csv-to-mde-bulk-ioc-csvs-folder)


```
let UngoverenedAI_IOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/PotentiallyUngovernedAITools.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = UngoverenedAI_IOCs
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList )
| summarize count() by RemoteUrl
```
## Monitor Cloud Storage

Monitor if the transfer is above X MB. I don't find the 50 user Filter useful or meaningful in the default policy so I tend to remove this.  

![image](https://github.com/user-attachments/assets/63dbc74c-2fa0-46be-819b-bb303623c1c6)


See also https://github.com/jkerai1/SoftwareCertificates/tree/main/Cloud%20backup%20or%20Exfil%20Tools

# Anomaly Detection Policy

These cannot be manually created, there are some potentially useful ones here that may be disabled by default, ensure to check these out from Cloud Apps > Policy Management (Type: Anomaly Detection Policy). Some of these policies such as Impossible Travel will have a learning period (typically 7 days), it is best to delay enabling these policies if you are in a holiday season/change freeze/brand new tenant for a higher fidelity.  

Also check the MS learn reference: https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy  

Some notes 📓 are: 	

- Activity from suspicious IP addresses - can catch when Identity protection alert auto-resolves say MFA from [AiTM](https://github.com/jkerai1/So-You-ve-Got-MFA-Defending-and-Responding-Against-MFA-Bypass-Techniques-in-Entra), but this should not be relied on as residential proxy can bypass)
- Unusual addition of credentials to an OAuth app - if you aren't monitoring this via Sentinel, worth alerting on as it can serve as a backdoor to a service principal)  
- Activity from infrequent country  - can be useful if you don't do any location blocking (or very early days on it), but I recommend you do some level of location based blocking for some defense in depth using named location in Conditional access, do you really need users signing in from North Korea for instance  
- Suspicious inbox forwarding - if not alerting via Defender For Office/Sentinel, though I would outright [block autoforwarding domains and whitelist](https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-external-email-forwarding)
- Multiple VM creation activities /Multiple delete VM activities - if you realy need to prevent deletions of VMs [Azure Policy Deny Delete](https://www.linkedin.com/pulse/restricting-deletions-incidents-sentinel-jay-kerai-da9te/) is your friend and can be layered with resource locks 🔐
- Suspicious creation activity for cloud region - if you don't use Azure policy "allowed locations" 🌐 and if you don't you probably should
- Impossible travel is OK but ensure to [include any IP ranges as Tags](#add-ip-range-for-usage-in-policies) as Corporate if you have users travelling between two office locations in 2 different geolocations. I'd also suggest increasing the sensitivity as this is usually a false positive and Identity protection / good conditional access can take over the role especially [Continuous Access Elevation with Strict Location Enforcement](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation-strict-enforcement)
- Unusual ISP for an OAuth App - Never seen a true positive from this, ensuring good Identity protection conditional access and IP Tags in MDA [Access Policy](#access-policy) is likely to be more useful
- Unusual file share activity - Could be useful if purview piece is not quite there
- Unusual file deletion activity - same as above, though some of this can be done via Sentinel/Advanced hunting instead with OfficeActivity | where Operation in ("FileDeleted","FileRecycled")
- Multiple storage deletion activities - For the azure insider risk piece
- Activity performed by terminated user - can be nice if you don't have perfect onboarding processes, I haven't seen this trigger thus so far

![image](https://github.com/user-attachments/assets/20a3cf9b-4fae-4be8-9b8f-ad9aece2e812)

Also note you can add goverance actions to anomaly policies for auto-response, annoyingly there is no revoke refresh token ("Require User To Sign-in Again"):
![image](https://github.com/user-attachments/assets/0288fd0d-8380-4f28-a33e-6842ab6a550b)


# Activity Policy

These policies enable you to monitor specific activities carried out by various users, or follow unexpectedly high rates of one certain type of activity, for example a large download of files.

Consider adding a Governance action after testing to suspend user / confirm compromised / revoke token. Require user to sign-in again is just a revoke refresh token in back-end.  

https://learn.microsoft.com/en-us/defender-cloud-apps/user-activity-policies

Templates available:
![image](https://github.com/user-attachments/assets/80e7a001-3051-4ac8-ac0d-41c73a44c3c5)

Some Notes 🗒️ on the Templates:

- Logon From Risky IP address - Basically an Identity protection clone but suppose this can be useful if you need the extra goverance actions or to [integrate with Power Automate for alerting](integrate-with-power-atomate-for-alerting) without the need for Sentinel 🛡️
- Potential Ransomware activity - From experience the ransomware alerts have always been false positives usually from backup file extensions .encrypted etc. Leveraging File Extensions is not the highest of fidelity here and will likely cause panic if you do intend on using this I would lower the priority and rename it to avoid scaring 👻 the security team.
- Mass Download by a single user - Can trigger for OneDrive Syncs 🔄, you could leverage "User Agent string does not contain" ODMTA or  OneDrive but bear in mind that user agent strings are spoofable
- Administrative activity from a non-corporate IP address - Ensure to [Add IP Range as a Corporate tag](#add-ip-range-for-usage-in-policies) before you deploy this
- Activities from suspicious user agents - The list of user agents is quite limited here so if you want to use this be sure to checkout my [user agent list](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/MDA/BannedUserAgentsList.txt) and add any appropriate strings. You will NOT want to add all of these are this will definitely result in false positives e.g. go-resty which is sometimes used by some Azure Tools. Am example of one to add here is ZmEu or gobuster, a better list can be found from: https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_http_user_agents_list.csv#L6 rather than leveraging my list. As stated above user agent is a spoofable string so this should not be relied on.    

## Dark Web Monitoring
![image](https://github.com/user-attachments/assets/eca631a6-2ff2-4e5e-b50d-504446824b38)


# File Policy

File Policies allow you to enforce a wide range of automated 🤖 processes using the cloud provider's APIs. Examples include: Put in Admin Quarantine, Notify Users, Apply Sensitivity Label, Make Private, remove external users  

The best practice guide for File Policy can be found at: https://learn.microsoft.com/en-us/defender-cloud-apps/data-protection-policies#file-policy-best-practices

File Policy Results can be viewed from Cloud Apps > Policies > Policy management, and then select the Information protection tab

![content-matches-ccn](https://github.com/user-attachments/assets/591c11c4-291d-4cad-b371-ff9d5adc7a76)


## Externally shared source code

Don't forget to add other [extensions](https://gist.github.com/ppisarczyk/43962d06686722d26d176fad46879d41) relevant to your org.

![image](https://github.com/user-attachments/assets/e282a56a-780a-41d7-8fdc-7395b3e5285d)

## File Shared with Personal Email Address

Missing The ability to add extra domains? unsure. The only other domains that appear here are the ones I have set as allowed for B2b External collaboration and the default personal emails pictured. Note that there are plenty of other personal email addresses missing here such as proton, gmx, fedora, yandex. Good news is you can do [Auto Unsanction Web Mail](#auto-unsanction-web-mail) to at least stop half of the bleed. After you have discovered what users are personally using you can block them with Exchange transport rule or better yet [TenantAllowBlockList](https://learn.microsoft.com/en-us/defender-office-365/tenant-allow-block-list-email-spoof-configure) which has a higher priority than Exchange Transport Rule. This will cover you also for that Auto-forwarding scenario too.

![image](https://github.com/user-attachments/assets/d686266f-ed45-4fa1-b5e7-4ab7d891ac78)

# Malware Detection Policy

[Off by default](https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy#malware-detection), remember to enable and add any appropriate auto Governance action.

![image](https://github.com/user-attachments/assets/853b5c6e-cd38-4063-a590-caa8c9438020)

Note that the File Sandboxing is an optional tickbox, if you don't want your files potentially entering a sandbox i.e. sensitive code scripts you want to leave this off.

![image](https://github.com/user-attachments/assets/0de57b5b-531d-41ad-9c74-29f70022a7c5)


# Block Script Baseline

Contains export scripts for apps you should probably be blocking in MDA and can apply to various products such as zscaler, cisco, fortigate. This should show the example output from MDA. 

https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/MDA/MDA-BlockScript-Baseline

After you have unsanctioned/sanctioned apps remember to generate blocklist for additional downstream protection:
![image](https://github.com/user-attachments/assets/1c94c17d-f03d-474f-9007-eb4a0d0d3dae)

# Shared digital certificates (file extensions)
Hunting for externally shared PEMs and PFXs could be useful:
![image](https://github.com/user-attachments/assets/131ca9fb-afd3-454b-b949-8be0a09d7cf4)

# App Governance

App Goverance is the new umbrella for Oauth apps, these are designed to govern oauth apps (in Entra terms an [Enterprise Application](https://ericonidentity.com/2023/03/11/aad-app-registrations-and-enterprise-applications-the-definitive-guide/)) registered to Entra (and google/salesforce if you enable these) including visibility, usage and permissions. If a user fell for an illict consent attack and an attacker gained access to corporate data via an Enterprise application this is where you could auto-remediate and revoke permissions for these applications. Noted that illict consent attacks have very much decreased with most "fun" permissions requiring an admin to consent.

If you haven't already I'd strongly recommend changing user consent settings away from "allow consent for apps". By default this is set to "Allow user consent for apps". This setting can be found from Enterprise applications > Consent and Permissions > User Consent Settings

![image](https://github.com/user-attachments/assets/26649403-acb8-4672-b4ab-19610528f918)


## Disable Overprivileged App

![image](https://github.com/user-attachments/assets/9daa039e-5108-476b-84db-5e3db9223507)

## Disable High privileged new app

![image](https://github.com/user-attachments/assets/81a09755-1328-426f-bc71-f19209dab495)

## Other policies

This is the legacy experience but the policies are still available for use in the App Goverance blade, unsure if this is to be depreciated    

The Revoke action is off by default for these policies in MDA so you can turn this on if you'd like.  

This can be done from App Govenrance > Policies > Other Policies  

Policies in this category:

 - Malicious OAuth app consent 
 - Misleading OAuth app name 
 - Misleading publisher name for an OAuth app  

![image](https://github.com/user-attachments/assets/72bfeda8-fca3-4a05-bb90-30ab0b6e0060)


# Misc

## Add IP Range for Usage in policies

Add Corporate IP Range for Usage in policies/Override False positives. If using "Impossible travel" anomaly detection [both sides of the travel need to be in the corporate range to suppress the alert](https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy#impossible-travel).

Settings > Cloud Apps > IP Address ranges  

![image](https://github.com/user-attachments/assets/9deb496c-f3a0-45ae-ab80-eb00433ab90a)

Policy result:

![image](https://github.com/user-attachments/assets/bbca1c5b-1b6c-4cd2-b788-17dc8a1b44e9)


## Enforce MDA Blocks to MDE

Settings > Cloud Apps > Microsoft Defender For Endpoint 

![image](https://github.com/user-attachments/assets/cbf669a5-d6ca-4dbe-b232-f4b5d4ddaf8b)

## Information Protection

This is optional and depends on company compliance requirements. You may not want to scan for labels set by external tenants and you may not want microsoft defender for cloud apps to be able to inspect file content

Microsoft Information Protection settings - this only applies to the App Connector and NOT the Conditional access app control.

Explict Oauth consent will be required to Inspect Protected files

Settings > Cloud Apps > Microsoft Information Protection

![image](https://github.com/user-attachments/assets/1e37ee94-30dd-4b0a-a9b1-8a65c1db47a5)


Explict Oauth consent will be required to Inspect Protected files

This logs as:

![image](https://github.com/user-attachments/assets/435a7417-1d66-4fa3-8cc9-c6d43f0fca14)

![image](https://github.com/user-attachments/assets/04463907-e3bb-4713-984c-c342b6d732ee)

## User Monitoring

I tend to turn this off because it can be annoying:

![image](https://github.com/user-attachments/assets/60dbb043-b918-48ea-b9d3-1ba146f4b11b)

## File Monitoring

Settings > Cloud Apps > Files

![image](https://github.com/user-attachments/assets/0b1c9b52-a74d-4afd-bdb3-e8c094c17391)

## App Onboarding and Maintenance

Always have a back-out plan and allow an account to bypass e.g. breaklass 🥂.  
You need to do add an account to manually onboard the microsoft apps, remember to remove them from any bypasses once the admin has setup the appropriate apps.

Settings > Cloud Apps > App onboarding/maintenance

![image](https://github.com/user-attachments/assets/905b1451-3b92-4abd-98a5-4900272406b1)


## Unified Audit Log

Unified audit log is very nice 🤩 to have, while not MDA focused call-out I'd like to call out that enabling the MDE Unified Audit Log (UAL) can make a life a lot easier for investigators.

Settings > Endpoints > Advanced Features 

![image](https://github.com/user-attachments/assets/b2d42023-abd8-4259-b909-53ddba1646d7)

![image](https://github.com/user-attachments/assets/c01066fb-cd5e-4b81-a1f5-d8efbf475970)


## Import Entra Groups

You may need to scope these policies granularly to user groups to maximize value on these policies, you can import User Groups from Entra by going to Settings > Cloud Apps > User Groups > Import User Group > Office365.  

For example, you may want to apply different access policy to different users, maybe a particularly group should only be signing in from a Zscaler IP then you can select the User group in the access policy and do a IP Tag Does not equal ZScalar with action of block.

![image](https://github.com/user-attachments/assets/820e6f04-95d7-41f9-b798-bdea80661e7a)


## Integrate with third party Secure Web Gateways For Discovery

This will enable your Web gateway to hook into the MDA Cloud app Broker getting you the visibility from the web gateway, note if you leverage web proxy on the MDE device already it will hit MDE/MDA before it hits web gateway anyway from what I have experienced with Zscaler. This means you can use both with no extra configuration and get that double layer of protection but bear in mind that the Zscalar logs will not reflect 1:1 with MDE logs.  

If you leverage the discovery with 3rd party web gateways you do not need to generate the block scripts as it is done automatically.  

↩️ I do not have experience with the below but I have included this for awareness 

- Zscaler - https://learn.microsoft.com/en-us/defender-cloud-apps/zscaler-integration
- iboss - https://learn.microsoft.com/en-us/defender-cloud-apps/iboss-integration
- Corrata - https://learn.microsoft.com/en-us/defender-cloud-apps/corrata-integration
- Menlo - https://learn.microsoft.com/en-us/defender-cloud-apps/menlo-integration
- Open Systems - https://learn.microsoft.com/en-us/defender-cloud-apps/open-systems-integration

![image](https://github.com/user-attachments/assets/c6168762-5188-4a8d-a947-bf6ee69742bb)

## Integrate with SaaS Security Posture

↩️ I do not have experience with the below but I have included this for awareness 

https://learn.microsoft.com/en-us/defender-cloud-apps/security-saas

![security-saas-choose-secure-score-main-instance](https://github.com/user-attachments/assets/606226ed-de53-4214-8655-f657ea8b887f)

## Integrate with Power Automate for alerting

↩️ I leverage Sentinel 🛡️ + Logic apps over power automate but the option is there within Policies to add action to trigger power automate 

The power automate playbooks can be managed from Settings > Cloud Apps > Playbooks  

https://learn.microsoft.com/en-us/defender-cloud-apps/flow-integration

![flow-when-alert](https://github.com/user-attachments/assets/8763b893-a2f4-4b1f-96a4-c92f8e1c0530)  

![flow-alerts-config](https://github.com/user-attachments/assets/7cda0d8d-3a0e-4816-af43-0848097b1a6c)

The power automate playbooks can be managed from Settings > Cloud Apps > Playbooks
![flow-extensions](https://github.com/user-attachments/assets/aed997b2-80e1-46a9-b41c-82307317b094)


