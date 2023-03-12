Use These For Testing/Building Detections for Exes that have been manipulated. 

SigThief - Brave.exe - Swapped with Signal Cert using Sig Thief  
SigThief-Brave (2).exe - Swapped With AMD Cert using Sig Thief  
DelCert - NordVPNSetup.exe - Cert Deleted using Delcert  
NoCert - SigThief -BraveBrowserSetup - Cert Removed using SigThief  

# Post-Testing:

Note that the certificate is NOT valid as the hash has changed  
Ensure SmartScreen is enabled, if you force users to use edge even better  
Ensure UAC blocks Applications with Revoked/Invalid Certificates: https://learn.microsoft.com/en-us/troubleshoot/windows-client/identity/uac-blocks-elevation-executable-apps  
Enable MDE Attack Surface Reduction rules - Particulary:  
> Block executable files from running unless they meet a prevalence, age, or trusted list criterion
> Block untrusted and unsigned processes that run from USB
> Block executable content from email client and webmail
> Block abuse of exploited vulnerable signed drivers
Ideally set UAC control to highest  - *Detection Oppurtunity*: Monitor UAC Bypass techniques  

When you upload a cert to MDE it also uploads the hash that was signed by cert which also blocks the hash which adds extra layer to Cert Removal Attack - however hash based blocking is not scalable  

Lets suppose you reverse engineer an executable to change the hash, a few things will happen:
>Cert wouldnt be valid if hash is changed - UAC/SmartScreen will block this if set  
>Lets suppose you remove the cert after changing hash - Then SmartScreen/ASR/WDAC would fire as foreign unsigned executable  
>If MZ compression is used on this executable then CheckSum might fail  

SmartScreen Blocking Examples:  

At Browser Level when downloading:  
![image](https://user-images.githubusercontent.com/55988027/224532539-bfe6cb2a-c904-4c47-a663-decbeafe752c.png)  

At Execution Level:  
![image](https://user-images.githubusercontent.com/55988027/224532555-60b30708-a7d6-469f-9725-a673e5947fab.png)  

Blocking without smartscreen:  

![image](https://user-images.githubusercontent.com/55988027/224571628-5fce3d24-acba-4f55-b148-2806fb880d51.png)  

MDE Attack Surface Reduction Rule Test:  

**PENDING**  

ASR Rule Reference:  
https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide  

# How to manipulate Certificates  

SigThief:  
https://github.com/secretsquirrel/SigThief  
https://axelarator.github.io/posts/codesigningcerts/  

DelCert:  
https://github.com/MadhukarMoogala/delcert  
https://forum.xda-developers.com/t/delcert-sign-strip-tool.416175/  

ImageRemoveCertificate:  
https://learn.microsoft.com/en-us/windows/win32/api/imagehlp/nf-imagehlp-imageremovecertificate  

SignTool:  
https://stackoverflow.com/questions/31869552/how-to-install-signtool-exe-for-windows-10  


Further Reading: https://axelarator.github.io/posts/codesigningcerts/  
