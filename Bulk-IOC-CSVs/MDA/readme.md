# Collection of useful ideas for MDA/ Defender for Cloud Apps / DfCA / MCAS


# Access Policy

Many Clever things can be done here but I'd consider blocking anonymous/hosting Ips to be the bare miniuium:

__Block "bad"/ hosting IPs__  
![image](https://github.com/user-attachments/assets/f7623cac-9790-48fa-9060-18b3fa708175)
![image](https://github.com/user-attachments/assets/772da56c-7d87-473b-a15f-42c6663bdd5b)

__Block user Agents:__

![Opera block](https://github.com/user-attachments/assets/385cd08f-144c-44d6-8bea-d67542e718ff)

Alternatively you can use Edge For Business Enforcement:

Settings > Cloud Apps > Edge For Business Protection


![image](https://github.com/user-attachments/assets/6e81968b-1d9a-4114-a5ec-0441f8110573)




# Session Policy  

You can also leverage Purview, file extensions etc. Malware Upload/Download should be bare minimium.

__Block malware Upload__
![image](https://github.com/user-attachments/assets/a1bf7a05-fbbc-4e42-a7ff-c4de3adbfec0)
![image](https://github.com/user-attachments/assets/f8d33b1a-05a1-4ee7-88b5-4c7997ab37e9)


__Block malware download__
![image](https://github.com/user-attachments/assets/a535b0d3-943b-4d16-a48d-172a51ec46ac)

![image](https://github.com/user-attachments/assets/dd7da79a-ef96-47c5-a2cd-a06a24532f51)

# App Discovery Policy

__Block Risky apps__

![image](https://github.com/user-attachments/assets/68a29e71-f351-4f70-a447-ecb16653461e)

__Auto Unsanction Web Mail__

I find 8 to be a good spot for legitimate work email vs personal email. Be sure to use the "edit and preview results" to check you are not going to block actual used business mail. Note that Gmail is a 10 so you'll need to unsanction manually.

![image](https://github.com/user-attachments/assets/dabc23fa-3854-42ce-89e7-73ccffc611c1)


__Auto ban discovered Transfer apps__

![image](https://github.com/user-attachments/assets/1ffe7e43-678e-47d3-a431-1f74d53a4d8f)

__Auto ban discovered Paste apps__

![image](https://github.com/user-attachments/assets/8f73a520-ead9-4dc1-9a32-8ea990c0124e)

__Monitor Cloud Storage__

![image](https://github.com/user-attachments/assets/13b017a8-3c76-4ebc-aeca-c92a3a01e3d6)


# Activity Policy

Consider adding a goverance action after testing to suspend user / confirm compromised / revoke token. Require user to sign-in again is just a revoke refresh token in back-end.

__Dark Web Monitoring__
![image](https://github.com/user-attachments/assets/eca631a6-2ff2-4e5e-b50d-504446824b38)


# File Policy

Externally shared source code. Should be on by default but don't forget to add other extensions relevant to your org.

![image](https://github.com/user-attachments/assets/e282a56a-780a-41d7-8fdc-7395b3e5285d)


# Malware Detection Policy

May be off by default, remember to enable and add any apprioprate auto goverance action.

![image](https://github.com/user-attachments/assets/853b5c6e-cd38-4063-a590-caa8c9438020)

# Block Script Baseline

Contains export scripts for apps you should probably be blocking in MDA and can apply to various products such as zscaler, cisco, fortigate. This should show the example output from MDA. 

https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/MDA/MDA-BlockScript-Baseline

After you have unsanctioned/sanctioned apps remember to generate blocklist for additional downstream protection:
![image](https://github.com/user-attachments/assets/1c94c17d-f03d-474f-9007-eb4a0d0d3dae)

# App Goverance

The Revoke action is off by default in MDA for App Goverance so you can turn this on if you'd like.  

This can be done from App Goverance > Policies > Other Policies  

Malicious OAuth app consent / Misleading OAuth app name / Misleading publisher name for an OAuth app  

![image](https://github.com/user-attachments/assets/72bfeda8-fca3-4a05-bb90-30ab0b6e0060)




# Misc

__Add Corporate IP Range for Usage in policies/Override False positives__

Settings > Cloud Apps > IP Address ranges  

![image](https://github.com/user-attachments/assets/9deb496c-f3a0-45ae-ab80-eb00433ab90a)


__Enforce MDA Blocks to MDE__ 

Settings > Cloud Apps > Microsoft Defender For Endpoint 

![image](https://github.com/user-attachments/assets/cbf669a5-d6ca-4dbe-b232-f4b5d4ddaf8b)

__Information Protection__


Settings > Cloud Apps > Microsoft Information Protection

![image](https://github.com/user-attachments/assets/1e37ee94-30dd-4b0a-a9b1-8a65c1db47a5)
