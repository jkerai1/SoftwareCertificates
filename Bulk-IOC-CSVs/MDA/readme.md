# Collection of useful ideas for MDA/ Defender for Cloud Apps / DfCA / MCAS

Not a comprehensive list, just some ideas of the capability of MDA and some of the settings you may have missed. I truly think MDA is underrated and underutilized by E5 Customers.  
>When creating policies leverage "edit and preview results" and "view policy matches" prior to deploying or deploy in alert/monitor only to reduce potential business impact.  

- [Access Policy](#access-policy)
  * [Block Anonymous IPs](#block-anonymous-ips)
  * [Block user Agents](#block-user-agents)
- [Session Policy](#session-policy)
  * [Block malware Upload](#block-malware-upload)
  * [Block malware download](#block-malware-download)
  * [Copy Paste of Credit Card Numbers](#copy-paste-credit-card-numbers)
- [App Discovery Policy](#app-discovery-policy)
  * [Auto Block Risky apps](#auto-block-risky-apps)
  * [Auto Unsanction Web Mail](#auto-unsanction-web-mail)
  * [Auto ban Discovered File Transfer apps](#auto-ban-discovered-file-transfer-apps)
  * [Auto ban Discovered Paste apps](#auto-ban-discovered-paste-apps)
  * [Auto ban Discovered Risky Generative AI](#auto-ban-discovered-risky-generative-ai)
  * [Monitor Cloud Storage](#monitor-cloud-storage)
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


Most of the policies below can be built from a policy template. For some reason, access policy does not have a template. Navigate to Cloud Apps > Policies > Policy Management to create a new policy or build a policy by selecting template.


# Access Policy

I'd consider blocking anonymous/abused hosting IPs to be the bare miniuium. When Conditional access hands over control to MDA these will then apply, ensure you have a policy to actually send the user to MDA.

![image](https://github.com/user-attachments/assets/317f1a1e-6fd6-42c6-8ae6-89db26c21ef7)


*Note*: Just because you fail to pass Access policy, it will still show as success in condiitonal access because Conditional Access successfully handed the session over. You'll need to review the Cloud App Activity Log  in these scenarios.

![image](https://github.com/user-attachments/assets/f137756f-8bf9-4c61-89a0-de9a5200f9be)

## Block Anonymous IPs
![image](https://github.com/user-attachments/assets/f7623cac-9790-48fa-9060-18b3fa708175)
![image](https://github.com/user-attachments/assets/772da56c-7d87-473b-a15f-42c6663bdd5b)

[KQL Consumer VPN Hunting Reference](https://www.kqlsearch.com/query/Consumer%20Vpn%20Logins&clx4u4q3800065iio1udg95wl)

## Block user Agents

List of User agents can be found at: https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/MDA/BannedUserAgentsList.txt

__Note about user agents:__  Spaces have been included in some user agents to future proof any overlapping strings.    

MSIE and Trident refer to IE  

That some of these browsers will not be supported in AZ portal natively such as seamonkey. Everything after the first 30 or so is tending to the more niche categories. If you really need to block ALL user agents just Enforce Edge for business instead (Settings > Cloud Apps > Edge For Business Protection) (See Below)

Reference https://whatmyuseragent.com/browser

![Opera block](https://github.com/user-attachments/assets/385cd08f-144c-44d6-8bea-d67542e718ff)


Edge For Business Enforcement (Preview):

Settings > Cloud Apps > Edge For Business Protection


![image](https://github.com/user-attachments/assets/6e81968b-1d9a-4114-a5ec-0441f8110573)


See More Browser Blocking stuff here:  
[Certificates](https://github.com/jkerai1/SoftwareCertificates/tree/main/Browsers)  
[Domains/URLs](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Browser%20IOCs.csv)  
[User Agent KQL Parser](https://www.kqlsearch.com/query/Identity-parseuseragent&clmoxrwnu002tmc0k2lnnqbnz)

# Session Policy  

You can also leverage Purview, file extensions etc. Malware Upload/Download should be bare minimium. See note above about conditional access to handover session, that is prerequiste here also.  

Policy Templates are available via:  

![image](https://github.com/user-attachments/assets/79b8a3ed-d6ce-4eba-9195-89ecd401975b)


## Block malware Upload
![image](https://github.com/user-attachments/assets/a1bf7a05-fbbc-4e42-a7ff-c4de3adbfec0)
![image](https://github.com/user-attachments/assets/f8d33b1a-05a1-4ee7-88b5-4c7997ab37e9)


## Block malware download
![image](https://github.com/user-attachments/assets/a535b0d3-943b-4d16-a48d-172a51ec46ac)

![image](https://github.com/user-attachments/assets/dd7da79a-ef96-47c5-a2cd-a06a24532f51)

## Copy Paste Credit Card Numbers

E.g. blocking Copy paste of Credit Card Numbers

Regex Pattern For Visa Card: ^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$ 

![image](https://github.com/user-attachments/assets/35977a49-06ea-4ebf-b776-8474acf92f21)

![image](https://github.com/user-attachments/assets/45aa450d-6057-4f87-a8b9-491193954b69)

# App Discovery Policy

These will scale as apps are added to MDA and users navigate to them. The MDA catalogue is large and grows everyday, this is a much more scaleable way to block, if apps are required then sanction them as needed or auto-stick into monitor and review. That is to say you don't need to wait for apps to be discovered you can manually unsanction apps before they are even discovered.  

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


## Auto ban discovered Paste apps

Here it is much safer to enable for both apps and domains: 

![image](https://github.com/user-attachments/assets/8f73a520-ead9-4dc1-9a32-8ea990c0124e)

From Cloud App Catalog We can see the impact if we turn on Advanced Filters:

![image](https://github.com/user-attachments/assets/cab8b03b-d431-478f-b487-6fb7c5202262)

*Note There is only one potential False positive- "Lee Paste" Accounting, risk score 4. You can prematurely mark this as sanctioned/Monitored/Custom Tag if its needed. In the policy you can exclude monitored apps/Custom tags*  

![image](https://github.com/user-attachments/assets/437ffaae-1165-4546-a9d8-f7c91295de81)

See also MDE Blocklist: https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/FileTransfer%20PasteLike%20Sites.csv

## Auto Ban Discovered Risky Generative AI

![image](https://github.com/user-attachments/assets/a36ef817-3fae-4abd-b58e-12de46ae3c86)


## Monitor Cloud Storage

Monitor if the transfer is above X MB. I don't find the 50 user Filter useful or meaningful in the default policy so I tend to remove this.  

![image](https://github.com/user-attachments/assets/63dbc74c-2fa0-46be-819b-bb303623c1c6)


See also https://github.com/jkerai1/SoftwareCertificates/tree/main/Cloud%20backup%20or%20Exfil%20Tools

# Activity Policy

Consider adding a Governance action after testing to suspend user / confirm compromised / revoke token. Require user to sign-in again is just a revoke refresh token in back-end.

## Dark Web Monitoring
![image](https://github.com/user-attachments/assets/eca631a6-2ff2-4e5e-b50d-504446824b38)


# File Policy

## Externally shared source code

Don't forget to add other [extensions](https://gist.github.com/ppisarczyk/43962d06686722d26d176fad46879d41) relevant to your org.

![image](https://github.com/user-attachments/assets/e282a56a-780a-41d7-8fdc-7395b3e5285d)

## File Shared with Personal Email Address

Missing The ability to add extra domains? unsure. The only other domains that appear here are the ones I have set as allowed for B2b External collaboration

![image](https://github.com/user-attachments/assets/d686266f-ed45-4fa1-b5e7-4ab7d891ac78)

# Malware Detection Policy

May be off by default, remember to enable and add any apprioprate auto Governance action.

![image](https://github.com/user-attachments/assets/853b5c6e-cd38-4063-a590-caa8c9438020)

# Block Script Baseline

Contains export scripts for apps you should probably be blocking in MDA and can apply to various products such as zscaler, cisco, fortigate. This should show the example output from MDA. 

https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/MDA/MDA-BlockScript-Baseline

After you have unsanctioned/sanctioned apps remember to generate blocklist for additional downstream protection:
![image](https://github.com/user-attachments/assets/1c94c17d-f03d-474f-9007-eb4a0d0d3dae)

# App Governance

## Disable Overprivileged App

![image](https://github.com/user-attachments/assets/9daa039e-5108-476b-84db-5e3db9223507)

## Disable High privileged new app

![image](https://github.com/user-attachments/assets/81a09755-1328-426f-bc71-f19209dab495)

## Other policies

This is the legacy experience  

The Revoke action is off by default in MDA for App Govenrance so you can turn this on if you'd like.  

This can be done from App Govenrance > Policies > Other Policies  

Policies in this category:

 - Malicious OAuth app consent 
 - Misleading OAuth app name 
 - Misleading publisher name for an OAuth app  

![image](https://github.com/user-attachments/assets/72bfeda8-fca3-4a05-bb90-30ab0b6e0060)


# Misc

## Add IP Range for Usage in policies

Add Corporate IP Range for Usage in policies/Override False positives.

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

Always have a back-out plan

Settings > Cloud Apps > App onboarding/maintenance

![image](https://github.com/user-attachments/assets/905b1451-3b92-4abd-98a5-4900272406b1)


## Unified Audit Log

Settings > Endpoints > Advanced Features 

![image](https://github.com/user-attachments/assets/b2d42023-abd8-4259-b909-53ddba1646d7)



