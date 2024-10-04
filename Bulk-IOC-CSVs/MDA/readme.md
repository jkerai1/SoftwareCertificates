# Collection of useful ideas for MDA/ Defender for Cloud Apps / DfCA / MCAS

Not a comprehensive list, just some ideas of the capability of MDA and some of the settings you may have missed. When creating policies leverage "edit and preview results" and "view policy matches" prior to deploying or deploy in alert/monitor only to reduce potential business impact.

# Access Policy

Many Clever things can be done here but I'd consider blocking anonymous/hosting Ips to be the bare miniuium. When Conditional access hands over control to MDA these will then apply.  

Note: Just because you fail to pass Access policy, it will still show as success in condiitonal access because CA successfully handed the session over

__Block "bad"/ hosting IPs__  
![image](https://github.com/user-attachments/assets/f7623cac-9790-48fa-9060-18b3fa708175)
![image](https://github.com/user-attachments/assets/772da56c-7d87-473b-a15f-42c6663bdd5b)

__Block user Agents:__

List of User agents can be found at: https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/MDA/MDA-BannedUserAgentsList.txt
![Opera block](https://github.com/user-attachments/assets/385cd08f-144c-44d6-8bea-d67542e718ff)

Alternatively you can use Edge For Business Enforcement (Preview):

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

__Copy Paste__

E.g. blocking Copy paste of Credit Card Numbers

Regex Pattern For Visa Card: ^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$ 

![image](https://github.com/user-attachments/assets/35977a49-06ea-4ebf-b776-8474acf92f21)


# App Discovery Policy

These will scale as apps are added to MDA and users navigate to them. The MDA catalogue is large and grows everyday, this is a much more scaleable way to block, if apps are required then sanction them as needed or auto-stick into monitor and review. 

__Auto Block Risky apps__

![image](https://github.com/user-attachments/assets/68a29e71-f351-4f70-a447-ecb16653461e)

__Auto Unsanction Web Mail__

I find 8 to be a good spot for legitimate work email vs personal email. Feel Free to edit this threshold.
Be sure to use the "edit and preview results" to check you are not going to block actual used business mail. Note that Gmail is a 10 so you'll need to unsanction Gmail manually.

![image](https://github.com/user-attachments/assets/dabc23fa-3854-42ce-89e7-73ccffc611c1)


__Auto ban discovered File Transfer apps__

Leveraging domain here may have too much impact, for paste also using domain is safer.

![image](https://github.com/user-attachments/assets/1ffe7e43-678e-47d3-a431-1f74d53a4d8f)

__Auto ban discovered Paste apps__

![image](https://github.com/user-attachments/assets/8f73a520-ead9-4dc1-9a32-8ea990c0124e)

See also MDE Blocklist: https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/FileTransfer%20PasteLike%20Sites.csv

__Monitor Cloud Storage__

Monitor if the transfer is above X %
![image](https://github.com/user-attachments/assets/13b017a8-3c76-4ebc-aeca-c92a3a01e3d6)

See also https://github.com/jkerai1/SoftwareCertificates/tree/main/Cloud%20backup%20or%20Exfil%20Tools

# Activity Policy

Consider adding a Governance action after testing to suspend user / confirm compromised / revoke token. Require user to sign-in again is just a revoke refresh token in back-end.

__Dark Web Monitoring__
![image](https://github.com/user-attachments/assets/eca631a6-2ff2-4e5e-b50d-504446824b38)


# File Policy

Externally shared source code. Should be on by default but don't forget to add other extensions relevant to your org.

![image](https://github.com/user-attachments/assets/e282a56a-780a-41d7-8fdc-7395b3e5285d)


# Malware Detection Policy

May be off by default, remember to enable and add any apprioprate auto Govenrance action.

![image](https://github.com/user-attachments/assets/853b5c6e-cd38-4063-a590-caa8c9438020)

# Block Script Baseline

Contains export scripts for apps you should probably be blocking in MDA and can apply to various products such as zscaler, cisco, fortigate. This should show the example output from MDA. 

https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/MDA/MDA-BlockScript-Baseline

After you have unsanctioned/sanctioned apps remember to generate blocklist for additional downstream protection:
![image](https://github.com/user-attachments/assets/1c94c17d-f03d-474f-9007-eb4a0d0d3dae)

# App Govenrance

__Disable Overprivileged App__

![image](https://github.com/user-attachments/assets/9daa039e-5108-476b-84db-5e3db9223507)

__Disable High privileged new app__

![image](https://github.com/user-attachments/assets/81a09755-1328-426f-bc71-f19209dab495)

__Other policies [Legacy Experience]__

The Revoke action is off by default in MDA for App Govenrance so you can turn this on if you'd like.  

This can be done from App Govenrance > Policies > Other Policies  

Malicious OAuth app consent / Misleading OAuth app name / Misleading publisher name for an OAuth app  

![image](https://github.com/user-attachments/assets/72bfeda8-fca3-4a05-bb90-30ab0b6e0060)


# Misc

__Add Corporate IP Range for Usage in policies/Override False positives/Add Extra Tag for Blocking__

Settings > Cloud Apps > IP Address ranges  

![image](https://github.com/user-attachments/assets/9deb496c-f3a0-45ae-ab80-eb00433ab90a)


__Enforce MDA Blocks to MDE__ 

Settings > Cloud Apps > Microsoft Defender For Endpoint 

![image](https://github.com/user-attachments/assets/cbf669a5-d6ca-4dbe-b232-f4b5d4ddaf8b)

__Information Protection__

This is optional and depends on company compliance requirements.   

Explict Oauth consent will be required to Inspect Protected files, this only applys to the App Connector and NOT the Conditional access app control.

Settings > Cloud Apps > Microsoft Information Protection

![image](https://github.com/user-attachments/assets/1e37ee94-30dd-4b0a-a9b1-8a65c1db47a5)

__User Monitoring__

I tend to turn this off because it can be annoying:

![image](https://github.com/user-attachments/assets/60dbb043-b918-48ea-b9d3-1ba146f4b11b)

__File Monitoring__

Settings > Cloud Apps > Files

![image](https://github.com/user-attachments/assets/0b1c9b52-a74d-4afd-bdb3-e8c094c17391)

__App Onboarding/Maintenance__

Always have a back-out plan

Settings > Cloud Apps > App onboarding/maintenance

![image](https://github.com/user-attachments/assets/905b1451-3b92-4abd-98a5-4900272406b1)



