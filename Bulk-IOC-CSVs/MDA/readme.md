# Collection of useful resources for MDA/ Defender for Cloud Apps / DfCA / MCAS

Not a comprehensive list, just some ideas of the capability of Defender for Cloud Apps (MDA) and some of the settings you may have missed. I truly think MDA is underrated and underutilized by E5 Customers.  

> 💡 When creating policies leverage "edit and preview results" (this will only work with the activies match tab - ensure to have activties selected or you'll pull the whole log) and "view policy matches" prior to deploying or deploy in alert/monitor only to reduce potential business impact.  

- [Access Policy](#access-policy)
  * [Block Anonymous IPs](#block-anonymous-ips)
  * [Block User Agents](#block-user-agents)
- [Session Policy](#session-policy)
  * [Block Malware Upload](#block-malware-upload)
  * [Block Malware download](#block-malware-download)
  * [Block Suspicious File Extension Upload](#block-suspicious-file-extension-upload)
  * [Block Download of Highly Sensitive Files](#block-download-of-highly-sensitive-Files)
  * [Copy Paste of Credit Card Numbers](#copy-paste-credit-card-numbers)
  * [Copy Paste of JWTs](#Copy-Paste-of-JWTs)  
  * [Require Step up if Sending Ethereum Address](#require-step-up-if-sending-ethereum-address)
- [App Discovery Policy](#app-discovery-policy)
  * [Auto Block Risky apps](#auto-block-risky-apps)
  * [Auto Unsanction Web Mail](#auto-unsanction-web-mail)
  * [Auto Ban Discovered File Transfer apps](#auto-ban-discovered-file-transfer-apps)
  * [Auto Ban Discovered Paste apps](#auto-ban-discovered-paste-apps)
  * [Auto Ban Discovered Torrent Sites](#auto-ban-discovered-Torrent-Sites)
  * [Auto Ban Discovered Risky Generative AI](#auto-ban-discovered-risky-generative-ai)
  * [Auto Ban Discovered Personal Messaging Apps](#Auto-Ban-Discovered-Personal-Messaging-Apps)
  * [Auto Ban Discovered Social Networking](#auto-ban-discovered-social-networking)
  * [Monitor Cloud Storage](#monitor-cloud-storage)
  * [Monitor Newly Created Apps](#monitor-new-created-apps)
- [Anomaly Detection Policy](#anomaly-detection-policy)
- [Activity Policy](#activity-policy)
  * [Dark Web Monitoring](#dark-web-monitoring)
  * [Logon on From Outdated Browser](#logon-on-from-outdated-browser)
- [File Policy](#file-policy)
  * [Externally Shared Source Code](#externally-shared-source-code)
  * [File Shared with Personal Email Address](#file-shared-with-personal-email-address)
- [Malware Detection Policy](#malware-detection-policy)
- [Block Script Baseline](#block-script-baseline)
- [App Governance](#app-governance)
  * [Disable Overprivileged App](#disable-overprivileged-app)
  * [Disable High privileged new app](#disable-high-privileged-new-app)
  * [Other Policies](#other-policies)
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
  * [Enrich cloud discovery data with Microsoft Entra usernames](#enrich-cloud-discovery-data-with-microsoft-entra-usernames)
  * [Automatic Log Upload from Network](#Automatic-Log-Upload-from-Network)
  * [Secure Score](#Secure-Score)
  * [Network Requirements](#etwork-Requirements)
  * [Behaviour During Downtime](#Behaviour-During-Downtime)
 

Most of the policies below can be built from a policy template. For some reason, access policy/Anomaly Detection Policy does not have a template.  
Navigate to Cloud Apps > Policies > Policy Management to create a new policy or build a policy by selecting template. 


# Access Policy
When Conditional access hands over control to MDA these will then apply (by default ALL Access policies will apply unless you filter by groups/users), ensure you have a policy to actually send the user to MDA. You will also need this conditional access policy for [Session Policy](#session-policy)

![image](https://github.com/user-attachments/assets/317f1a1e-6fd6-42c6-8ae6-89db26c21ef7)
> Note you only need to configure this in 1 Conditional access policy to apply to the user

*Note*: Just because you fail to pass Access policy, it will still show as success in conditional access because Conditional Access successfully handed the session over. You'll need to review the Cloud App > Activity Log from Defender Portal in these scenarios.The Activity Type will be "Log On". Update October 2024: https://learn.microsoft.com/en-us/defender-cloud-apps/release-notes#new-conditional-access-app-control--inline-data-in-advanced-hunting-cloudappevents-table  

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
- myworkaccount.microsoft.com

My conclusion is that MDA handover is NOT fit for AI developers and I'd probably go with WVD/AVD instead especially given the data access they may have. Though many of the AI portals are unifying now. A fast way to onboard apps quickly into MDA is to open them all using something like [MSPortals-io](https://msportals.io) after creating a conditional access policy with a session control of "monitor only" scoped to the user doing the onboarding. Add the onboarding user under [App Onboarding and Maintenance](#app-onboarding-and-maintenance) to reduce any potential impact which provides them with the option to bypass if they need to continue doing work. After you have finished onboarding all the apps and created your policies you can go back to the conditional access policy and scope the Session control to custom. Once testing of that is finished you can go back and scope users/apps and exclude any Corporate owned and/or compliant devices. Then clear down any users who can bypass and switch these to an emergency account.

![image](https://github.com/user-attachments/assets/b6b61e28-98b2-4f61-bf21-7cf9e1924f94)

Some apps for some reason do not even prompt me for onboarding despite having a Conditional access policy scoped to all apps such as 
- ADX (dataexplorer.azure.com)
- azureiotcentral.com
- ea.azure.com

> Note that when you enter the MDA Proxy all URLs will be written with .mcas.ms at the end in non-[Edge for Business browsers](https://learn.microsoft.com/en-us/defender-cloud-apps/in-browser-protection). Functionally this has no difference, however note when copying URLs that you may need to remove .mcas.ms. For example if giving a sharepoint link to Copilot, while Copilot is on behalf on flow the bot may not be able to authenticate past the proxy.

For a pilot run you are best scoping just to Office365 in Conditional access. Admin Portals also works if you allow admins to sign-in from BYOD/non-entra Join device. A Conditional Access Policy scoped to these two is what have I have been testing and it has worked out great so far.

![image](https://github.com/user-attachments/assets/7aae8bb4-99c1-49e5-9e66-82d2b87c1773)
> My 2 conditions are Client Apps: Browser & Exclude Device Filter device.isCompliant -eq True -and device.deviceOwnership -eq "Company"

The finished List - 38 Items - It's possible I missed a few or some more have become available post writing this. You will not need all of these as some are legacy portals.  

This list can be found under Settings > Cloud Apps > Conditional Access App Control Apps:

Page 1             |  Page 2
:-------------------------:|:-------------------------:
![image](https://github.com/user-attachments/assets/8f85c792-81a0-4f6a-ad38-47897cc82f8c)|  ![image](https://github.com/user-attachments/assets/2d80230f-4a90-43ea-ae1f-a02c8b94b3b3)

All other [3rd party apps will need to be onboarded with SAML](https://learn.microsoft.com/en-us/defender-cloud-apps/proxy-deployment-featured-idp) from Settings > Cloud Apps > Conditional Access App Control Apps:
![image](https://github.com/user-attachments/assets/a4d84b59-91c3-41ef-be90-23bd4ec30e95)
> The reason from what I can tell for why you need to do this on top of having the Enterprise Application in Entra is that you need the assertion URL or you will run into redirect error

Note that just because many microsoft apps didn't work, this is still enough coverage to put damage control for Adversary in the middle (AiTM) type phishing as this typically targets Officehome (Office365). If you want to learn more about AiTMs, I'd encourage you to check out my talk on [M365-Security-&-Compliance-User-Group](https://github.com/jkerai1/So-You-ve-Got-MFA-Defending-and-Responding-Against-MFA-Bypass-Techniques-in-Entra)

> I tested Windows, MacOS, Linux and Android and they all behaved fine with the MDA Proxy. However noted that Android/iOS should really be going via MAM/MDM instead. The devices tested where not Intune enrolled/entra joined/registered or MDE enrolled in any way shape or form. That is to say that Access/Session Policy works on BYOD.  

## Block Anonymous IPs

I'd consider blocking anonymous proxy, abused hosting 🌩️ (LeaseWeb,OVH, Cloudiver, Digital Ocean, Host Royale, Linode, Cloudflare), Tor/Darknet IPs/Password Spray attacker to be the bare minimum (if it makes sense in your environment of course!!!)
Real shame theres a few abused hosting Providers missing such as hostwinds. Malware C&C/Ten Cent/Sharktech/Alibaba/baCloud/Brute Force Attacker is also not a bad shout here.  

🤔 I want explore the "no tag", dedicated server hosting, Cloud hosting Tags ☁️ to see their impact. These could have their use-cases in the right environments especially when leveraged when scoping to [Entra Groups](#import-entra-groups)  

🛑 I would not recommend trying to do banned country Locations in MDA Access Policy, this is better suited to Conditional access as then you can hit all users and all apps.  

Country sign-in Conditional access KQL :oncoming_police_car::
```
let CountryCodes = externaldata (country: string,countryOrRegion:string) [@'https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/refs/heads/master/all/all.csv'] with (format=csv, ignoreFirstRecord=True);
SigninLogs
| where TimeGenerated > ago(90d)
| where ResultType == 0
| extend countryOrRegion = tostring(LocationDetails.countryOrRegion)
| where isnotempty(countryOrRegion)
| join kind = leftouter CountryCodes on countryOrRegion
|extend VT_IP= iff(isnotempty(IPAddress),strcat(@"https://www.virustotal.com/gui/ip-address/",IPAddress),IPAddress)
| summarize count() by country, UserPrincipalName, VT_IP
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
| extend UserPrincipalName = iff(countof(UserPrincipalName,"-") == 4, AccountUPN, UserPrincipalName)
| summarize count() by UserPrincipalName, IPAddress, UserAgent, Spur
```

[MDE BlockList for Consumer VPNs Domains/URLs](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Consumer%20VPNs.csv), Audit with below KQL :oncoming_police_car:, you can upload the list afterwards to MDE. [Instructions here](https://github.com/jkerai1/SoftwareCertificates?tab=readme-ov-file#how-to-upload-the-bulk-ioc-csv-to-mde-bulk-ioc-csvs-folder)

```
let VPNIOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Consumer%20VPNs.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = VPNIOCs
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList)
| extend VT_domain = iff(isnotempty(RemoteUrl),strcat(@"https://www.virustotal.com/gui/domain/",RemoteUrl),RemoteUrl)
| summarize count() by RemoteUrl,VT_domain
```
Also consider Browser Extension VPNs, if you don't have MDE DeviceTVM bolt on you can leverage KQL :oncoming_police_car: on DeviceFileEvents to find recent downloads of Browser extensions. The following query is from the [intune](https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/Intune) portion of this repo:

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
| where ExtensionID != "cnlefmmeadmemmdciolhbnfeacpdfbkd" //Grammarly
| where RiskyExtension == "Yes"
```

## Block User Agents
> Remember that User Agents can be spoofed and even accidentally so e.g. Request Desktop site on Mobile Browser. See my blog post about this [here](https://www.linkedin.com/posts/jay-kerai-cyber_browsers-mam-whoops-activity-7217520619532267521-HgPE)   

List of keywords from unusual User agents :suspect: can be found at: https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/MDA/BannedUserAgentsList.txt

__Note about user agents:__  Spaces have been included in some user agents to future proof any overlapping strings. Also note that some browsers do not fingerprint differently, for example, Brave desktop will just fingerprint as Chrome.     

Some of these User Agents will not be supported in Azure portal natively such as seamonkey. Not all are Browser based, some are OS based and some are just bots/scrappers (I've left all in for hunting purposes)
Everything after the first 30 entries or so is tending to the more niche categories. If you just want to block robots then use [user agent tag of "robot"](#logon-on-from-outdated-browser) in a seperate Access Policy (additional filters act as an "AND" not an "OR"). If you really need to block *ALL* user agents except Edge just Enforce Edge for business instead (Settings > Cloud Apps > Edge For Business Protection) (See Below)

Reference https://whatmyuseragent.com/browser  

I have an Edge For Business Config File available from the [Intune Section of this repo](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Intune/Readme.md#edge-for-business-config)  

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


![image](https://github.com/user-attachments/assets/78c58e1e-8b55-4a7f-b055-2e9607ed3067)


The default block message isn't super useful so I would consider customizing this - The average end user probably doesn't know what Edge for Business means:  
![image](https://github.com/user-attachments/assets/981b632a-8ce0-4d96-a1b8-be28363beb2d)  

Also note when you use Edge for business with MDA, browser tools (i.e. when you hit F12) will not be available which makes perfect sense as that provides a bypass path to the proxy. This also means Device Emulation/native User Agent switching will not be possible which is a nice bonus.

See More Browser Blocking stuff here:  
[Certificates](https://github.com/jkerai1/SoftwareCertificates/tree/main/Browsers)  
[Domains/URLs](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Browser%20IOCs.csv)  
[User Agent KQL :oncoming_police_car: Parser](https://www.kqlsearch.com/query/Identity-parseuseragent&clmoxrwnu002tmc0k2lnnqbnz)

> Note that 3rd party browsers will appear as BYOD to Entra and this is because it can't pull the DeviceId claim across without the [SSO Extension](https://chromewebstore.google.com/detail/microsoft-single-sign-on/ppnbnpeolgkicgegkbkbjmhlideopiji) (legacy) or the [CloudAPAuthEnabled](https://chromeenterprise.google/policies/#CloudAPAuthEnabled) Registry Key, this key can only be set via [ADMX/Administrative Template](https://scloud.work/google-chrome-single-sign-on-sso-azure-ad/). There is no Settings Catalog (CSP) option in Intune, so you'll have to use administrative template. Also by default private tabs in Edge will not pull across DeviceID claim. If you need to use an admin account leverage browser profile instead to keep data seperate.

# Session Policy  

> See note about conditional access to handover session in [Access Policy](#access-policy), that is prerequisite here also.  

The huge benefit to using Session Policy is that the receiving device does not need to be Intune enrolled/MDE enrolled/Entra joined/registered in any way shape or form. This allows us to essentially protect business data from BYOD devices, I wouldn't really bother using session control on Intune and Endpoint enrolled devices as we can control the configurations on those devices, with BYOD we cannot. I put an exclude filter compliant and corporate owned devices from my conditional access policy for Conditional Access App Control. You can also filter out Intune Compliant devices in Session Control if you do want that granularity but as I do that in conditional access I will not do this in this section. Note that the default policy templates will try to include this tag so I manually delete it.   

⚠️ Session Policy ONLY works for browser-based applications so you'll need to block Mobile and desktop apps in Conditional access policy.I actually recommend creating 1 Conditional access policy to target browser and 1 to target Mobile & Desktop Clients and blocking in the later if you don't have strict device filter/ require Hybrid join grant in Conditional Access policy already       

You can also leverage [Purview](https://learn.microsoft.com/en-us/defender-cloud-apps/use-case-proxy-block-session-aad#create-a-block-download-policy-for-unmanaged-devices), block upload/download of file extensions etc (perhaps .doc,.pdf etc.) with session policy. Malware Upload/Download should be bare minimium. 

Policy Templates are available via:  

![image](https://github.com/user-attachments/assets/79b8a3ed-d6ce-4eba-9195-89ecd401975b)


## Block Malware Upload  
Template: Block upload of potential malware (based on Microsoft Threat Intelligence  

![image](https://github.com/user-attachments/assets/a1bf7a05-fbbc-4e42-a7ff-c4de3adbfec0)
![image](https://github.com/user-attachments/assets/f8d33b1a-05a1-4ee7-88b5-4c7997ab37e9)


## Block Malware download  

Template: Block download of potential malware (based on Microsoft Threat Intelligence)

![image](https://github.com/user-attachments/assets/a535b0d3-943b-4d16-a48d-172a51ec46ac)

![image](https://github.com/user-attachments/assets/dd7da79a-ef96-47c5-a2cd-a06a24532f51)

## Block Suspicious File Extension Upload

Start building the policy with "Block upload based on real-time content inspection" template. I then remove Data Classification Inspection method as we don't need that. Then from "Filters", select "extension" and start adding in the extensions.  

Note that I deliberately don't give a custom block message here, I don't want to give the user any information about what happened. If the user is aware of what file extensions are allowed they may look for an alternative binary. Furthermore this allows makes it easier to bypass by spoofing file extensions, there is no header/metadata inspection happening here. Attacker could also container their binary in another format like an .iso or .zip, use [double file extensions - T1036.007](https://attack.mitre.org/techniques/T1036/007/). You should definitely be leveraging an exectuable file extension upload policy option with the above [malware Upload](#block-malware-upload)/download session policies for extra coverage. Ensure this file extensions policy is a seperate policy from the above for maximium coverage.    

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

Renaming extension bypasses and I'm able to upload - no header inspection taking place:  
![image](https://github.com/user-attachments/assets/db683daf-6919-4870-9293-132e24c5101b)

I tried to craft a [Right to Left Override](https://attack.mitre.org/techniques/T1036/002/) with a [few lines of python](https://github.com/ctrlaltdev/RTLO-attack/tree/master) and actually managed to lock myself out by hitting [attack disruption](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption) 😆:  

Alert             |                   Timeline         | Action Center
:-------------------------:|:-------------------------:|:---------------------------------------:
![Attack Disruption](https://github.com/user-attachments/assets/b6b59f20-37b9-46ac-9799-bc1a9acc495a)| ![image](https://github.com/user-attachments/assets/cd40b403-452e-4c84-9382-5678ba9aa3b5)|![image](https://github.com/user-attachments/assets/e1c214ab-1ac2-4872-95d8-016d002ac674)  

Anyway after releasing myself from containment (reminder to always have a backup plan), I carry on:  

![image](https://github.com/user-attachments/assets/c4d5592e-7b41-4898-a7e6-449a89a7b55c) 

I am prevented but note the error message is backwards 🐛!  

![image](https://github.com/user-attachments/assets/2217750f-3a00-4c32-a052-9311a29c0299)

If we flip our logic we can exploit this and we won't be blocked but I suppose this is very niche category:  

![image](https://github.com/user-attachments/assets/02c0ddd8-9cfe-4097-9a89-07600b337b17)


# Block Download of Highly Sensitive Files

You probably don't want someone to download sensitive files onto their BYOD device so you can leverage sensitivity labels/Trainable Classifiers/Sensitivite Info Types to prevent this activity. You can start building from the "block Download based of real-time content" template. Just for demonstration purpose I chose all sensitive info types, the wizard actually discourages this and if you do bulk action select it will only select the ones in the view, so in this demo I manually clicked through every page. You can also use your custom Purview Trainable Classifiers/Sensitive Info Types here also if you wish instead which is a big bonus if you have already built a custom classifier/info types.  

Users may try to bypass file downloading by copy/pasting so ensure you cover yourself there, see below example for Credit card numbers.    
   
Sensitive Info Type Examples           |  Trainable Classifier Examples | Sensitivity Label 
:-------------------------:|:-------------------------:|:-------------------------:
![image](https://github.com/user-attachments/assets/6e03eeae-83a7-48d5-a6d6-514d3853a603)| ![image](https://github.com/user-attachments/assets/42c4d375-c143-488e-9d22-71d56617bbe3) |![image](https://github.com/user-attachments/assets/82456396-56fd-4565-9e64-ac61ec78c168)


> I'm no DLP expert but from my understanding Data Classification Service will perform better than the Built-in DLP Service. Be sure to use Data Classification Service and not the built-in DLP legacy service. It should choose Data Classification Service by default.  

## Copy Paste Credit Card Numbers

Block users from copy pasting content potentially sensitive content, you can't use sensitivity labels/SIT/Trainable classifiers here.    

Leverage the in-built preset for Finance: Credit card number    

Regex Pattern For Visa Card: ^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$ if you need it for testing. My test document can also be found [here](https://github.com/jkerai1/SoftwareCertificates/raw/refs/heads/main/Bulk-IOC-CSVs/MDA/Test%20credit%20card%20Numbers.docx), in this test I uploaded it to my onedrive from outside the proxy (i.e an Intune compliant device) then copy pasted the contents while inside the MDA proxy    

![image](https://github.com/user-attachments/assets/35977a49-06ea-4ebf-b776-8474acf92f21)

![image](https://github.com/user-attachments/assets/45aa450d-6057-4f87-a8b9-491193954b69)  

> You can also extend this to "Send Item" if you want to, example of this below 

# Require step up if Sending Ethereum Address

> __Note__ step up in Session Policy is in preview  

Force the user into an [authentication context](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#authentication-context) if they send a [ethereum address](blockchain.com), in this case the context is Sign-in Frequency of everytime with passwordless authentication. Leverage with a custom authentication strengths for bonus points. See my article here on [Passwordless quirks](https://www.linkedin.com/pulse/passwordlessphishing-resistant-considerations-entra-jay-kerai-zh6nc). Don't forget to exclude breakglass from Conditional Access when tagging the authentication context.  
> If you want to see how to setup authentication context on video check out my section from [Microsoft EMS Virtual Event 2024](https://youtu.be/hc11q4404H0?t=4033)

ETH Regex Pattern: 0x[a-fA-F0-9]{9}[a-fA-F0-9]{9}[a-fA-F0-9]{9}[a-fA-F0-9]{9}[a-fA-F0-9]{4}  

https://learn.microsoft.com/en-us/defender-cloud-apps/working-with-the-regex-engine, the regex engine seems quite limited, I tried to do ethereum address but hit failure of Quantifiers of type {n,m} n,m must be less than 10 and so yep I tried splitting into blocks of 9️⃣

![image](https://github.com/user-attachments/assets/78e7e3d0-f2c4-48e9-8aee-081aac8d3c5a)

If I hit "Close" I just end up in a prompt loop until I hit "Ok Proceed"
![image](https://github.com/user-attachments/assets/0682cb55-549a-4d53-ac4b-e4778b6a45af)

I actually wasn't allowed back in, might be an issue with the preview. However the point is that someone sending wallet addresses is very suspicious and could be a compromised account so we definitely want to kick them out,note that even though I passed the challenge here the teams message wasn't actually sent.  

> Update: tried in multiple tenants with a variety of conditions, same error so this likely an issue with the preview.

![image](https://github.com/user-attachments/assets/9e896a42-6a9e-457a-bc43-32f3fb058767)

> I haven't tested it but Slack is also supported for "Send Item" if Slack is connected to MDA

This pattern will also work in Purview, I couldn't get other patterns to work so I am under the impression MDA and purview leverage a similiar regex engine.

![image](https://github.com/user-attachments/assets/74ff2f68-ad86-41e4-b9c5-22ba0f185d2f)  
![WhatsApp Image 2024-11-06 at 20 20 43](https://github.com/user-attachments/assets/7dd809d7-ad65-4e17-b3ff-0c601cfd180e)


## Copy Paste of JWTs  

Using similiar logic to above we can block phrases matching Javascript Web Tokens which could be a token exfil, this would be incredibly rare as there are better ways to exfil tokens outside the view of MCAS proxy.

Keyword: "eyJ0e" (but also eyJhbGc is valid)  

![image](https://github.com/user-attachments/assets/79813b9f-8331-4939-8674-002ce711a506)  

![image](https://github.com/user-attachments/assets/58a1422f-9783-4afc-9531-1c29e84a6736)  

# App Discovery Policy
> This works via Network Logs from MDE, Secure Web Gateway or custom log collector. There is no dependency here for conditional access here, only Access/Session policies require conditional access.

These will scale as apps are added to MDA and users navigate to them. The MDA catalogue is large and grows everyday (33,384 apps currently - even if you tried to block half of these you'd run out of space on MDE IOC as the limit there is 15,000), this is a much more scaleable way to block, if apps are required then sanction them as needed or auto-stick into monitor and review.  

That is to say you don't need to wait for apps to be discovered you can manually unsanction apps before they are even discovered. If you want more ideas of what to manually unsanction check out the [MDA baseline Folder](https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/MDA/MDA-BlockScript-Baseline#going-further)   

Ensure MDA Discovery is enabled for MDE. This can be found from Settings > Endpoints > Advanced Features > Microsoft Defender For Cloud Apps  

![image](https://github.com/user-attachments/assets/607e6363-5b14-4745-b821-4dcae7052295)

> The blocks in the back-end are propogated to MDE. The benefit of Unsanctioning via MDA rather than standard MDE IOC is that you will get all MDA associated domains to the app, the blocks will also persist if someone was to delete them via Indicators. If you need to remove an MDA Indicator do it via MDA first then delete in MDE as it can take up to 2 hours to propagate. You can then also [Integrate with 3rd party Secure Web Gateways For Discovery](#integrate-with-third-party-secure-web-gateways-for-discovery) for automatic blocking in these also. Where possible use MDA over MDE. If you import an MDE IOC list that overlaps with MDA, the block will not duplicate which is a nice bonus, the name and description will overwrite though with the name/description from the CSV which is a non-issue and potentially desirable. The application tag will remain.

![image](https://github.com/user-attachments/assets/bf7abd0e-3468-420b-b0ff-08d7367ad78f)


⭐ Note that in MDA a ⬆️ higher score means less risky. 🔟 would be a perfect score. The scores are based of General categories (such as diaster recovery, popularity and domain age), security, compliance and legal. You can actually override these if you need to weight more towards one value (lets say you have strict requirement for data at rest being encrypted). This can be done from Settings > Cloud Apps > Score Metrics. Don't forget to hit Save all the way at the bottom after you are done.  
![image](https://github.com/user-attachments/assets/3e701239-65fd-4f40-acf0-6b223b228f63)

The Governance Actions for discovery can be found under Settings > Cloud Apps > Governance Log

![image](https://github.com/user-attachments/assets/b177ff19-e98f-4306-8d4e-1a8172bd12d9)

Audit your Blocks across to MDE with the below KQL :oncoming_police_car:. Smartscreen is used for Edge and Exploit Guard is for 3rd party browsers. In the back-end the blocks are MDE, assuming of course you have remembered to [Enforce MDA Blocks to MDE](#enforce-mda-blocks-to-mde). ❗ Please remember to turn this on or the blocks will not do diddly squat from an MDE Point of view!    

```
DeviceEvents
| where TimeGenerated > ago(90d)
| where (ActionType == "SmartScreenUrlWarning" and AdditionalFields.Experience == "CustomBlockList") or (AdditionalFields.ResponseCategory == "CustomBlockList" and ActionType == "ExploitGuardNetworkProtectionBlocked")
| where tostring(AdditionalFields.DisplayName) has "appName" or isnotempty(tostring(AdditionalFields.ApplicationName))
| extend Application = iff(tostring(AdditionalFields.DisplayName) has "appName",replace_string((tostring(AdditionalFields.DisplayName)),@"appName=",""), (AdditionalFields.ApplicationName))
| extend Application= replace('"', '', Application)
| summarize BlockedURls = make_list(RemoteUrl) by Application
```
The MDA Apps can be found in MDE IOC by filtering on "Application", this is available from Settings > Endpoints > Indicators. Note that Sanctioned applications will NOT create an allow indicator.    

![image](https://github.com/user-attachments/assets/aad7f79c-b51f-421d-b182-aa7bcb7fc1e9)

> App Discovery does not actually require any additional permission from M365 App Connector because it can infer from the connections from MDE agent / 3rd party Secure Web Gateways   

## Auto Block Risky apps

![image](https://github.com/user-attachments/assets/bfdba71a-6637-4c3a-a247-2e73acec97cb)  


## Auto Unsanction Web Mail

I find 8️⃣ to be a good spot for legitimate work email vs personal email. Feel Free to edit this threshold.
Be sure to use the "edit and preview results" to check you are not going to block actual used business mail. Note that Gmail is a 10 so you'll need to unsanction Gmail manually. Also note this will not block email delivery just users signing into personal email from an MDE Enrolled device (assuming you enforce MDA to MDE).  

![image](https://github.com/user-attachments/assets/dabc23fa-3854-42ce-89e7-73ccffc611c1)


## Auto Ban Discovered File Transfer apps

You can leverage App Name or Domain Name for Auto discovery Policies.

![image](https://github.com/user-attachments/assets/1ffe7e43-678e-47d3-a431-1f74d53a4d8f)

From Cloud App Catalog We can see the impact if we turn on Advanced Filters:

![image](https://github.com/user-attachments/assets/77b2ce32-eba7-474a-9342-315448f269a8)

This policy will miss a few such as sendnow, sendthisfile, dropsend but these can be done manually or you can create a different policy. You'll want to hit Content Sharing and Cloud Storage categories there.

Alternatively you can create another discovery policy with the following filters:

However note there are a LOT of results, and even almost 5,000 when we bump the risk score to 6, ensure to sanction/review all legitmate business apps first from cloud app discovery as you won't want to scroll through pages and pages of apps.  

![image](https://github.com/user-attachments/assets/abcaba27-8b2d-4220-b041-2409df07935b)

In my case I only have 2 hits neither of which is LOB and both with very low amount of traffic (little point in sanctioning these 2) so I am happy to proceed and block with a risk score of 5:  

![image](https://github.com/user-attachments/assets/6a0424da-562d-4ed2-9ca3-472f0036408f)

🏆 For best practice use "App Tag Does not Equal Sanctioned" rather than "App Tags Equals Monitored or No Value", this is because you can actually create extra tags if you need them in MDA so a creation of a new tag may leave a gap in policy:  

![image](https://github.com/user-attachments/assets/ed8394de-a787-4936-b636-5458cccdced8)

Example of Custom Tag - Create one from Settings > Cloud Apps > App Tags > Add app Tag:
![image](https://github.com/user-attachments/assets/999b5d8f-674e-483f-9ed7-ea82bcad655d)


## Auto Ban Discovered Paste apps

❗ I'd HIGHLY recommend blocking at least Pastebin as this is often used for exfiltration of data / staging malware payloads (maybe malware payload #1 reaches out to pastebin to get URL for malware payload #2)    

Here it is much safer to enable for both apps and domains: 

![image](https://github.com/user-attachments/assets/8f73a520-ead9-4dc1-9a32-8ea990c0124e)

From Cloud App Catalog We can see the impact if we turn on Advanced Filters:

![image](https://github.com/user-attachments/assets/cab8b03b-d431-478f-b487-6fb7c5202262)

*Note There is only one potential False positive- "Lee Paste" Accounting, risk score 4. You can prematurely mark this as sanctioned/Monitored/Custom Tag if its needed. In the policy you can exclude monitored apps/Custom tags*  

![image](https://github.com/user-attachments/assets/437ffaae-1165-4546-a9d8-f7c91295de81)

See also MDE Blocklist: [https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/FileTransfer%20PasteLike%20Sites.csv](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/FileTransfer%20PasteLike%20Sites.csv). Audit with below KQL :oncoming_police_car:, you can upload the list afterwards to MDE. [Instructions here](https://github.com/jkerai1/SoftwareCertificates?tab=readme-ov-file#how-to-upload-the-bulk-ioc-csv-to-mde-bulk-ioc-csvs-folder)


```
let PasteLikeSitesIOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/FileTransfer%20PasteLike%20Sites.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = PasteLikeSitesIOCs
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList )
|extend VT_domain = iff(isnotempty(RemoteUrl),strcat(@"https://www.virustotal.com/gui/domain/",RemoteUrl),RemoteUrl)
| summarize count() by RemoteUrl,VT_domain
```
## Auto Ban Discovered Torrent Sites  

Similiar to above but for torrents

![image](https://github.com/user-attachments/assets/cfc93f42-6002-4051-a84f-49add7e8e22b)

If we "edit and preview results", we don't see a single legitimate hit (but that is not to say there may be a legitimate app added that has torrent in its name, but I find this to be fairly unlikely)  

![image](https://github.com/user-attachments/assets/2f6fccb8-7f72-4dd0-85b9-bdfeed39fc61)


See also my MDE Blocklist for Piracy: [https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/FileTransfer%20PasteLike%20Sites.csv](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Piracy.csv). Audit with below KQL :oncoming_police_car:, you can upload the list afterwards to MDE. [Instructions here](https://github.com/jkerai1/SoftwareCertificates?tab=readme-ov-file#how-to-upload-the-bulk-ioc-csv-to-mde-bulk-ioc-csvs-folder)

```
let PiracyIOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Piracy.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = PiracyIOCs
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList )
| extend VT_domain = iff(isnotempty(RemoteUrl),strcat(@"https://www.virustotal.com/gui/domain/",RemoteUrl),RemoteUrl)
| summarize count() by RemoteUrl,VT_domain
```
> See also https://github.com/jkerai1/SoftwareCertificates/tree/main/Piracy for Software Certificate IOCs

## Auto Ban Discovered Risky Generative AI

OpenAI scores 8️⃣ or 9️⃣ and Copilot scores around 🔟. If you need to block Chatgpt etc I'd block it manually as 9 may be too high for app discovery policy. Bear in mind theres currently 3 OpenAI catergories available  

![image](https://github.com/user-attachments/assets/d7e92b57-1823-45fc-96c8-3638eccadb82)

Also bear in mind savy users might find legitimate company websites that have chatbots with no content filter so this by no means a substitute for good DLP.  

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
| extend VT_domain = iff(isnotempty(RemoteUrl),strcat(@"https://www.virustotal.com/gui/domain/",RemoteUrl),RemoteUrl)
| summarize count() by RemoteUrl,VT_domain
```
> Want a visual demo? See this [video from Microsoft](https://www.youtube.com/watch?v=ZQI4A7W4E_4)
 
## Auto Ban Discovered Personal Messaging Apps

This serves as not only an exfil path but a malware delivery path. Imagine a user receives a phish via a personal messaging app, this would bypass protections of Defender for Office and the such, so we definitely want to be monitoring or blocking this. 

☎️ I strongly recommend to unsanction Discord and telegram manually. These have a lot of problems in a business environment (data exfilitration - discord webhooks/manual, illegal activities, NSFW, Discord's CDN being abused to host malware). Don't get me wrong I am in a lot of genuinely good tech discords (like [Microsoft EMS](https://discord.com/invite/msems)) and they are super useful but I can use a personal device away from the company to access these at my own leisure.    

![image](https://github.com/user-attachments/assets/ff680848-4699-4cfb-8028-44cc4e97387f)  

Examining the catalog we don't see too much of an impact, however ⚠️ remember to manually sanction any of these applications you may want to use for diaster recovery!  

![image](https://github.com/user-attachments/assets/b33c407c-e065-47d0-8a06-86857ab8ea13)

> See also https://github.com/jkerai1/SoftwareCertificates/tree/main/Messaging%20or%20Conferencing Software Certificate IOCs

Dirty Chat Application KQL :oncoming_police_car: - some apps were not in MDA library so I have requested them:  
```
let ChatIOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/ChatSites.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = ChatIOCs
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList )
| extend VT_domain = iff(isnotempty(RemoteUrl),strcat(@"https://www.virustotal.com/gui/domain/",RemoteUrl),RemoteUrl)
| summarize count() by RemoteUrl,VT_domain //,DeviceName, InitiatingProcessAccountUpn 
```


## Auto Ban Discovered Social Networking

![image](https://github.com/user-attachments/assets/393e2ef6-d22b-4bea-ae04-06f460a5a6c2)


Same as the above really in terms but bear in mind there are some expected Social networks here such as LinkedIn, Viva Engage. Also keep in mind or Facebook/Twitter if your org has prescence and marketing on these platforms. You may want to hit this with Device groups instead to allow certain users to access - this leverages MDE Device Groups in the back-end but there is a pre-requiste:

You'll need to create a scope profile first which can be done from Settings > Cloud Apps > App Tags

![image](https://github.com/user-attachments/assets/9209c5e8-3021-4419-8dd0-873e2165f0ca)

Then to unsanction you'll want to hit the 3 dots and unsantion rather than leveraging the normal 🚫 icon:

![image](https://github.com/user-attachments/assets/c1930f97-a48b-4ea2-8442-309ab8e6729c)

Then we can select the scope profile we just made: 

![image](https://github.com/user-attachments/assets/e610c9da-7414-4283-85f8-23e7722c72e4)

> Its quite annoying you can't see if your scope profile is an include or exclude here. I would recommend choosing a naming convention that includes what you are doing so you don't accidentally deploy the inverse of what you intended to do. Don't forget also you can add Notes to each app in MDA from the same 3 dots. Its the last option.

![image](https://github.com/user-attachments/assets/fd851acd-6c48-4473-a72f-2dc63ac8107a)

![image](https://github.com/user-attachments/assets/56034a53-5c13-4154-92c2-e7a5f55e6899)


## Monitor Cloud Storage

Monitor if the transfer is above X MB. I don't find the 50 user Filter useful or meaningful in the default policy so I tend to remove this.  

![image](https://github.com/user-attachments/assets/63dbc74c-2fa0-46be-819b-bb303623c1c6)

See also https://github.com/jkerai1/SoftwareCertificates/tree/main/Cloud%20backup%20or%20Exfil%20Tools for Software Certificate IOCs

> Also check out the [Living Off Trusted Sites (LOTS) Project](https://lots-project.com/) and searching for +exfiltration


## Monitor Newly Created Apps

You may want to keep an eye on newly founded apps. Annoyingly you can't do a dynamic year here so eventually you'll need to move this forward at some point in time.  

![image](https://github.com/user-attachments/assets/b8924ff1-d7e5-4ba0-a93b-3609c28c352e)

Also I strongly recommend enabling [Web Content filtering for newly registered domains in MDE](https://learn.microsoft.com/en-us/defender-endpoint/web-content-filtering#turn-on-web-content-filtering). To block sites that are newly registered in the past 30 days and haven't yet been moved to another category. If you want to audit before you whack this in, create a web content filtering Policy with no categories (Settings > Endpoints > Web Content Filtering). 

![image](https://github.com/user-attachments/assets/2b25b9d2-7cb8-41b6-b115-41661a1a47a8)

Then reports will be available from Reports > Web Protection,be sure to expand the time range if you have been in audit mode for a while, by default its 30 days.  

![image](https://github.com/user-attachments/assets/c6cc2ee5-f652-4ab0-a7c0-ad41d9331b4b)

> You'll also want to make sure Web Content Filtering is also turned on from Settings > Endpoints > Advanced Features

# Anomaly Detection Policy

These cannot be manually created, there are some potentially useful ones here that may be disabled by default, ensure to check these out from Cloud Apps > Policy Management (Type: Anomaly Detection Policy). Some of these policies such as Impossible Travel will have a learning period (typically 7 days), it is best to delay enabling these policies if you are in a holiday season/change freeze/brand new tenant for a higher fidelity.  

Also check the MS learn reference: https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy  

Some notes 📓 are: 	

- Activity from suspicious IP addresses - can catch when Identity protection alert auto-resolves say MFA from [AiTM](https://github.com/jkerai1/So-You-ve-Got-MFA-Defending-and-Responding-Against-MFA-Bypass-Techniques-in-Entra), but this should not be relied on as residential proxy can bypass)
- Unusual addition of credentials to an OAuth app - if you aren't monitoring this via Sentinel, worth alerting on as it can serve as a backdoor to a service principal  
- Activity from infrequent country  - can be useful if you don't do any location blocking (or very early days on it), but I recommend you do some level of location based blocking for some defense in depth using named location in Conditional access, do you really need users signing in from North Korea for instance  
- Suspicious inbox forwarding - if not alerting via Defender For Office/Sentinel, though I would outright [block autoforwarding domains and whitelist](https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-external-email-forwarding)
- Multiple VM creation activities /Multiple delete VM activities - if you realy need to prevent deletions of VMs [Azure Policy Deny Delete](https://www.linkedin.com/pulse/restricting-deletions-incidents-sentinel-jay-kerai-da9te/) is your friend and can be layered with resource locks 🔐
- Suspicious creation activity for cloud region - if you don't use Azure policy "allowed locations" 🌐 and if you don't you probably should
- Impossible travel is OK but ensure to [include any IP ranges as Tags](#add-ip-range-for-usage-in-policies) as Corporate if you have users travelling between two office locations in 2 different geolocations. I'd also suggest increasing the sensitivity as this is usually a false positive and Identity protection / good conditional access can take over the role especially [Continuous Access Elevation with Strict Location Enforcement](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation-strict-enforcement)
- Unusual ISP for an OAuth App - Never seen a true positive from this, ensuring good Identity protection conditional access and IP Tags in MDA [Access Policy](#access-policy) is likely to be more useful from an Entra Perspective, note that the Oauth App in question may not actually be onboarded into Conditional Access Session control
- Unusual file share activity - Could be useful if purview piece is not quite there
- Unusual file deletion activity - same as above, though some of this can be done via Sentinel/Advanced hunting instead with OfficeActivity | where Operation in ("FileDeleted","FileRecycled")
- Multiple storage deletion activities - For the azure insider risk piece
- Activity performed by terminated user - can be nice if you don't have perfect onboarding processes, I haven't seen this trigger thus so far

![image](https://github.com/user-attachments/assets/20a3cf9b-4fae-4be8-9b8f-ad9aece2e812)

Also note you can add goverance actions to anomaly policies for auto-response, annoyingly there is no revoke refresh token ("Require User To Sign-in Again"):
![image](https://github.com/user-attachments/assets/0288fd0d-8380-4f28-a33e-6842ab6a550b)

> For Policies to work correctly ensure M365 AND Azure are configured in App Connectors. Be sure to include 3rd party clouds such as AWS/GCP for greater coverage on Cloud based alerting.  

# Activity Policy

These policies enable you to monitor specific activities carried out by various users, or follow unexpectedly high rates of one certain type of activity, for example a large download of files.

Consider adding a Governance action after testing to suspend user / confirm compromised / Require User to Sign-in again (revoke refresh token). Require user to sign-in again is just a revoke refresh token in back-end.  

Audit for Governance actions can be found under Settings > Cloud Apps > Goverance Log

![image](https://github.com/user-attachments/assets/fe23d419-c533-4401-a0a1-f59cc53af9a5)

https://learn.microsoft.com/en-us/defender-cloud-apps/user-activity-policies

Templates available:

![image](https://github.com/user-attachments/assets/80e7a001-3051-4ac8-ac0d-41c73a44c3c5)

Some Notes 🗒️ on the Templates:

- Logon From Risky IP address - Basically an Identity protection clone but suppose this can be useful if you need the extra goverance actions or to [integrate with Power Automate for alerting](integrate-with-power-atomate-for-alerting) without the need for Sentinel 🛡️
- Potential Ransomware activity - From experience the ransomware alerts have always been false positives usually from backup file extensions .encrypted etc. Leveraging File Extensions is not the highest of fidelity here and will likely cause panic if you do intend on using this I would lower the priority and rename it to avoid scaring 👻 the security team.
- Mass Download by a single user - Can trigger for OneDrive Syncs 🔄, you could leverage "User Agent string does not contain" ODMTA or  OneDrive but bear in mind that user agent strings are spoofable
- Administrative activity from a non-corporate IP address - Ensure to [Add IP Range as a Corporate tag](#add-ip-range-for-usage-in-policies) before you deploy this
- Activities from suspicious user agents - The list of user agents is quite limited here so if you want to use this be sure to checkout my [user agent list](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/MDA/BannedUserAgentsList.txt) and add any appropriate strings. You will NOT want to add all of these are this will definitely result in false positives e.g. go-resty which is sometimes used by some Azure Tools. Am example of one to add here is ZmEu or gobuster, a better list can be found from: https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_http_user_agents_list.csv#L6 rather than leveraging my list. As stated above user agent is a spoofable string so this should not be relied on. If you are too lazy to add User Agents manually just use the User Agent tag of Robot instead and delete the existing "User Agent String contains".        

> Ensure M365 is connected via App Connectors and has visibility for Activity Monitoring and apprioprate governance actions  
![image](https://github.com/user-attachments/assets/3901e203-3b9f-4576-9960-6377f084d22f)


## Dark Web Monitoring
Alert on any activity from Dark Web or bad IPs and mark user compromised & Revoke token via Require user to sign-in again, ensure to not include failed logons as we don't want to cause impact for unsuccesful sign-ins. Once the user is marked compromised this will set their User Risk to high in Entra which will then apply the [User Risk policy](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-policies#user-risk-based-conditional-access-policy) if you have one (if you don't I recommend one - ensure to not mix User Risk and Sign-in Risk in the same policy as this acts as an "AND" not an "OR"). Remember that true passwordless users will not have their password so will be unable to perform a password reset, so you may want to exclude a group of Passwordless users from the conditional access policy (it should not be done in MDA). You may also want to exclude breakglass from the Dark Web Policy depending on your risk appetite 🍰 (You can also create a seperate Activity Policy to alert + email on Breakglass sign-ins from any IP too but I'd recommend to do Sentinel/Azure Monitor instead if these are available to you). Ensure to preview the results before applying.  

![image](https://github.com/user-attachments/assets/19db6887-3e35-465d-9dba-9cc1c5970609)


# Logon on From Outdated Browser

Some UI elements failed to load on out of date browsers, you can actually use an activity policy to alert users for outdated browser/operating system, so they can self remediate without raising a ticket to helpdesk (I'm not sure average user will self-remediate out of date OS but mentioning it anyway). This policy is under the template "Log on from an outdated browser". You could actually use an access policy instead to block them outright but I would not recommend using Access Policy in block for Outdated Operating System just yet as that could have impact to Windows 10 users in the future.

![image](https://github.com/user-attachments/assets/00e82e46-1e3a-4f2f-b9f5-a4eb121eae01)

![image](https://github.com/user-attachments/assets/5b72b0bd-c6a1-486a-af54-75b2099edfcd)

The email notification isn't particularly verbose so there is some advantage to using an Access Policy as you can give much clearer instructions to the user of what to do by customizing the block message:  

![image](https://github.com/user-attachments/assets/63be225b-3ac7-4905-88b3-b00738fdbaef)

# File Policy

File Policies allow you to enforce a wide range of automated 🤖 processes using the cloud provider's APIs. Examples include: Put in Admin Quarantine, Notify Users, Apply Sensitivity Label, Make Private, remove external users  

>Be sure to do [Information Protection](#information-protection) if you want to intergrate [Purview with Defender for cloud apps with File Policies](https://learn.microsoft.com/en-us/defender-cloud-apps/azip-integration) as well as ensuring Defender for Cloud Apps can see files in M365 ([File Monitoring](#file-monitoring))

The best practice guide for File Policy can be found at: https://learn.microsoft.com/en-us/defender-cloud-apps/data-protection-policies#file-policy-best-practices

File Policy Results can be viewed from Cloud Apps > Policies > Policy management, and then select the Information protection tab

![content-matches-ccn](https://github.com/user-attachments/assets/591c11c4-291d-4cad-b371-ff9d5adc7a76)

> Note that File Policy is great feature but its not a substitute for proper Purview DLP as a preventation method

🥬 FYI if you try to trash a file after disconnecting the app connector for M365 Files you'll see this prompt, you'll need to renable from App Connectors see [File Monitoring](#file-monitoring)  

![image](https://github.com/user-attachments/assets/81637828-8771-4b70-81e8-f574227d7770)


## Externally shared source code  

Template Policy, you may want to drop the Access level depending on the use case      

Don't forget to add other [extensions](https://gist.github.com/ppisarczyk/43962d06686722d26d176fad46879d41) relevant to your org.

![image](https://github.com/user-attachments/assets/e282a56a-780a-41d7-8fdc-7395b3e5285d)


## File Shared with Personal Email Address  

Template Policy  

Missing The ability to add extra domains? unsure. The only other domains that appear here are the ones I have set as allowed for B2b External collaboration and the default personal emails pictured. Note that there are plenty of other personal email addresses missing here such as proton, gmx, fedora, yandex. Good news is you can do [Auto Unsanction Web Mail](#auto-unsanction-web-mail) to at least stop half of the bleed. After you have discovered what users are personally using you can block them with Exchange transport rule or better yet [TenantAllowBlockList](https://learn.microsoft.com/en-us/defender-office-365/tenant-allow-block-list-email-spoof-configure) which has a higher priority than Exchange Transport Rule. This will cover you also for that Auto-forwarding scenario too.

![image](https://github.com/user-attachments/assets/d686266f-ed45-4fa1-b5e7-4ab7d891ac78)

# Malware Detection Policy

[Off by default](https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy#malware-detection), remember to enable and add any appropriate auto Governance action.

> You must have at least one app connected using app connectors and this connector must be able to see the files, For example in App Connectors Microsoft 365 > Microsoft 365 Files Must be ticked. See [File Monitoring](#file-monitoring)

![image](https://github.com/user-attachments/assets/853b5c6e-cd38-4063-a590-caa8c9438020)

Note that the File Sandboxing is an optional tickbox, if you don't want your files potentially entering a sandbox i.e. sensitive code scripts you want to leave this off.

![image](https://github.com/user-attachments/assets/0de57b5b-531d-41ad-9c74-29f70022a7c5)

![image](https://github.com/user-attachments/assets/c9c7118d-bd52-417c-a035-9ec71707a3dc)


I decided to see if this policy could detect some of my favourite cloud hacking tools🧰 for a 😆 - results below 3️⃣:/9️⃣:
![image](https://github.com/user-attachments/assets/17a7eebe-b0f5-4676-8012-a3d50f261e5b)

Not malware per se as they are tools but interesting to see the results. I'd say if we actually look at the code of some of these like o365 creeper and fireprox they aren't inheritently malicious and do fairly normal things for python scripts. I may have edited the code to change the hash 😉. Can you spot the odd tool out? 🧩        

You may want to alert the user involved, as you can no longer alert the user natively in MDA you can leverage a logic app (or power automate). The Entites are mapped, making life much easier.  

![image](https://github.com/user-attachments/assets/df065633-e28a-4d1a-8a1f-888142b0346a)



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

> Note App Goverance will not show ALL apps registered to Entra, only priviliged and risky ones

If you haven't already I'd strongly recommend changing user consent settings in Entra away from "allow consent for apps". By default this is set to "Allow user consent for apps". This setting can be found from Enterprise applications > Consent and Permissions > User Consent Settings

![image](https://github.com/user-attachments/assets/26649403-acb8-4672-b4ab-19610528f918)

Also ensure users cannot create Service Principals/App Registrations (Entra > User Settings > Users can register Applications). Also ensure other 2 are configured as by default Entra lets users create tenants/Service Principals/Security groups - below is my best practice:  

![image](https://github.com/user-attachments/assets/b50320d0-a31a-4903-9c50-fd00d094715c)


> Ensure M365 apps are connected to app governance from Settings > Cloud Apps > App Connectors > Microsoft 365 > Edit Connector

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

![Revoke Office Oauth App](https://github.com/user-attachments/assets/66973a0d-919c-49b9-9168-64378b00ea95)



# Misc

## Add IP Range for Usage in policies

Add Corporate IP Range for Usage in policies/Override False positives. If using "Impossible travel" anomaly detection [both sides of the travel need to be in the corporate range to suppress the alert](https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy#impossible-travel).

Settings > Cloud Apps > IP Address ranges  

![image](https://github.com/user-attachments/assets/9deb496c-f3a0-45ae-ab80-eb00433ab90a)

Policy result:

![image](https://github.com/user-attachments/assets/bbca1c5b-1b6c-4cd2-b788-17dc8a1b44e9)

> Need to sync Entra Trusted Named Locations to MDA? Check out https://365bythijs.be/2020/03/31/sync-named-locations-to-mcas-ip-ranges-using-azure-automation/

## Enforce MDA Blocks to MDE

To make any advantage of Unsanctioned 🚫 Apps you'll need to enable this from

Settings > Cloud Apps > Microsoft Defender For Endpoint 

![image](https://github.com/user-attachments/assets/cbf669a5-d6ca-4dbe-b232-f4b5d4ddaf8b)  
> You may want to include a custom message in the blocks to guide users where they should go to raise tickets to get apps unsanctioned if you want to do that kind of thing

Also ensure that Network protection is in block mode and that Custom Indicators is also turned on:

![image](https://github.com/user-attachments/assets/9fa81c57-eed8-4c5b-9d0d-7a575a2e1b96)

https://learn.microsoft.com/en-us/defender-cloud-apps/mde-govern
> While you are here Ensure Defender for Cloud apps is turned on from Settings > Endpoints > Advanced Features

## Information Protection

This is optional and depends on company compliance requirements. You may not want to scan for labels set by external tenants and you may not want microsoft defender for cloud apps to be able to inspect file content, however if you plan on using File Policies you will at least need to tick the first box.  

Microsoft Information Protection settings - this only applies to the App Connector and NOT the Conditional access app control.

Explict Oauth consent will be required to Inspect Protected files

Settings > Cloud Apps > Microsoft Information Protection

![image](https://github.com/user-attachments/assets/1e37ee94-30dd-4b0a-a9b1-8a65c1db47a5)

https://learn.microsoft.com/en-us/defender-cloud-apps/azip-integration#how-to-integrate-microsoft-purview-with-defender-for-cloud-apps  

Explict Oauth consent will be required to Inspect Protected files

This logs as:

![image](https://github.com/user-attachments/assets/435a7417-1d66-4fa3-8cc9-c6d43f0fca14)

![image](https://github.com/user-attachments/assets/04463907-e3bb-4713-984c-c342b6d732ee)

## User Monitoring

I tend to turn this off because it can be annoying - at least when I was testing MDA. You may want to turn it back on afterwards:

![image](https://github.com/user-attachments/assets/60dbb043-b918-48ea-b9d3-1ba146f4b11b)

## File Monitoring

For Purview to see files in SaaS Apps - Settings > Cloud Apps > Files  

![image](https://github.com/user-attachments/assets/0b1c9b52-a74d-4afd-bdb3-e8c094c17391)  

For Microsoft 365 Files you need to do this via Settings > Cloud Apps > App Connectors > Microsoft 365 > Edit Connector  

![image](https://github.com/user-attachments/assets/ce5a7ae9-1650-4033-80fc-5cfeff0d575a)

🛑 A lot of the policies and ideas discussed in this write-up depend on the above being enabled for M365 so ensure to check that all these boxes are ticked!  

> Note that App Connectors is for APIs and not for Conditional Access Session Control, these are 2 seperate things. Also note for malware policy to work with M365 you need to enable the above for M365, for app governance actions you will need M365 Apps.

## App Onboarding and Maintenance

Always have a back-out plan and allow an account to bypass e.g. breaklass 🥂. See also [Behaviour During Downtime](#Behaviour-During-Downtime).   
You need to add an account to manually onboard the microsoft apps, remember to remove them from any bypasses once the admin has setup the appropriate apps.

Settings > Cloud Apps > App onboarding/maintenance

![image](https://github.com/user-attachments/assets/905b1451-3b92-4abd-98a5-4900272406b1)

> Admins should not really be logging in from BYOD this is bad practice and should be blocked in Conditional Access

## Unified Audit Log

Unified audit log is very nice 🤩 to have, while not MDA focused call-out I'd like to call out that enabling the MDE Unified Audit Log (UAL) can make a life a lot easier for investigators 🔎.

Settings > Endpoints > Advanced Features 

![image](https://github.com/user-attachments/assets/b2d42023-abd8-4259-b909-53ddba1646d7)

![image](https://github.com/user-attachments/assets/c01066fb-cd5e-4b81-a1f5-d8efbf475970)

I was unable to find actions regarding sanctioning/unsanctioning applications in Unified Audit Log but it was available in the Activity log (Settings > Cloud Apps > Activity Log) - Strange!  

![image](https://github.com/user-attachments/assets/2226fef6-a120-415c-b370-88e7657e7e34)


## Import Entra Groups

You may need to scope these policies granularly to user groups to maximize value on these policies, you can import User Groups from Entra by going to Settings > Cloud Apps > User Groups > Import User Group > Office365.  

For example, you may want to apply different access policy to different users, maybe a particularly group should only be signing in from a Zscaler IP then you can select the User group in the access policy and do a IP Tag Does not equal Zscaler with action of block.

![image](https://github.com/user-attachments/assets/820e6f04-95d7-41f9-b798-bdea80661e7a)


## Integrate with third party Secure Web Gateways For Discovery

This will enable your Web gateway to hook into the MDA Cloud app Broker getting you the visibility from the web gateway, note if you leverage web proxy on the MDE device already it will hit MDE/MDA before it hits web gateway anyway from what I have experienced with Zscaler. This means you can use both with no extra configuration and get that double layer of protection but bear in mind that the Zscaler logs will not reflect 1:1 with MDE logs.  

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

## Enrich cloud discovery data with Microsoft Entra usernames

Cloud discovery data can now be enriched with Microsoft Entra username data. When you enable this feature, the username, received in discovery traffic logs (such as Secure Web Gateway or from log collector), is matched and replaced by the Microsoft Entra username. Cloud discovery enrichment enables the following features:

> You can investigate Shadow IT usage by Microsoft Entra user. The user will be shown with its UPN.  
> You can correlate the Discovered cloud app use with the API collected activities.  
> You can then create custom reports based on Microsoft Entra user groups. For example, a Shadow IT report for a specific Marketing department.  

Settings > Cloud Apps > User Enrichment 

![image](https://github.com/user-attachments/assets/12e414c9-6c02-430a-b945-6dec9ae36b66)

# Automatic Log Upload from Network

↩️ I have not used the below but included for reference. I personally find this to be low down on the list of priorities as I work with MDE Estates where the discovery can happen via the MDE Agent which covers majority of use-cases. The collector would probably make more sense for you if you have many non-MDE devices on the on-prem network accessing corporate data and you have many custom apps you've added to cloud discovery (maybe a Line of business app built especially for your org) 

Log collectors enable you to upload logs from your on-prem network. In the back-end its just a docker container that parses the firewall logs and uploads it to MDA for analysis. Note that the container doesn't actually have to be deployed on-prem you can still deploy it on Azure ☁️, you can also use a SIEM server as a source to the log collector. 

It can be configured from Settings > Cloud Apps > Automatic log Upload
https://learn.microsoft.com/en-us/defender-cloud-apps/discovery-docker

![image](https://github.com/user-attachments/assets/11658fac-1498-43d7-aa4b-8b567cb3d9b4)

After you have configured the log collector (or [Secure Web Gateway](#Integrate-with-third-party-Secure-Web-Gateways-For-Discovery) you can create a snapshot report:

![snapshot-report-management](https://github.com/user-attachments/assets/8c002286-41f6-471c-87be-3dfd3daa81cc)
> Microsoft suggests doing a manual upload of a sample log first so you can ensure MDA can parse the logs before you deploy the log collector. There is support for a wide range for appliances but if yours is not supported there is the option to create a custom parser.

![cloud-discovery-snapshot-verify](https://github.com/user-attachments/assets/fe2f0d49-1f55-4e56-8f59-c38dcddef513)


# Secure Score

We have 5️⃣ recommendations here at the time of writing and I've filtered Secure Score by Defender for cloud apps. It looks like the legacy oauth policy recommendation is still in here even though I have moved to app governance!  

![image](https://github.com/user-attachments/assets/cf668dee-dfae-412d-9b44-5eb77a5de664)

If I try to create a policy I notice we have two activity policy types when I go to filter - I wouldn't worry too much about this and this will likely disappear as app governance is rolled out:

![image](https://github.com/user-attachments/assets/5df1bf04-9516-4565-b53b-5128323f92de)

> If you want to read more about my thoughts on Secure Score, check out my [blog post](https://www.linkedin.com/posts/jay-kerai-cyber_microsoft-securescore-entra-activity-7245764184607531008-QZZS)

# Network Requirements

List of URLs/IPS and ports required for various bits of MDA to work. Could be useful for troubleshooting. You'll definitely need this if you intend on rolling out [Automatic-Log-Upload-from-Network](#Automatic-Log-Upload-from-Network)  

https://learn.microsoft.com/en-us/defender-cloud-apps/network-requirements

# Behaviour During Downtime  

💩 happens - decide what you want to happen in the event MDA has any downtime and an access/session policy cannot be enforced. By Default this is set to Allow.  

Settings > Cloud Apps > Conditional Access App Control > General Settings  

![image](https://github.com/user-attachments/assets/707abcd0-84e7-4dc6-8579-de46f8a40c3f)
> Consider Business Continuity before selecting Block Access, you won't have much to secure if your business isn't making 💲🤑
 
 

# Fin  

Hopefully I have demonstrated that MDA is much more powerful than you think and you have a better understanding on how it works!  

I'd also recommend checking out [samilamppu.com](https://samilamppu.com) who has some excellent content on MDA.  

![image](https://github.com/user-attachments/assets/f1541d26-e285-4d35-ac03-92dbf9b27685)
