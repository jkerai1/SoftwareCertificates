Use These For Testing/Building Detections for Exes that have been manipulated

Post-Testing:

Ensure SmartScreen is enabled as per the test, if you force users to use edge even better  
Ensure UAC blocks Applications with Revoked Certificates: https://learn.microsoft.com/en-us/troubleshoot/windows-client/identity/uac-blocks-elevation-executable-apps


SmartScreen Examples:  

At Browser Level when downloading:  
![image](https://user-images.githubusercontent.com/55988027/224532539-bfe6cb2a-c904-4c47-a663-decbeafe752c.png)  

At Execution Level:  
![image](https://user-images.githubusercontent.com/55988027/224532555-60b30708-a7d6-469f-9725-a673e5947fab.png)  


How to manipulate Certificates  

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
