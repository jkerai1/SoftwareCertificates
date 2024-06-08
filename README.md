[![GitHub stars](https://img.shields.io/github/stars/jkerai1/SoftwareCertificates?style=flat-square)](https://github.com/jkerai1/SoftwareCertificates/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/jkerai1/SoftwareCertificates?style=flat-square)](https://github.com/jkerai1/SoftwareCertificates/network)
[![GitHub issues](https://img.shields.io/github/issues/jkerai1/SoftwareCertificates?style=flat-square)](https://github.com/jkerai1/SoftwareCertificates/issues)
[![GitHub pulls](https://img.shields.io/github/issues-pr/jkerai1/SoftwareCertificates?style=flat-square)](https://github.com/jkerai1/SoftwareCertificates/pulls)

SoftwareCertificates
Repository for Software Certs for easy software blocking (or allowing) across corp environments, for example, using MDE IOC/AppLocker/WDAC

e.g. https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/indicator-certificates?view=o365-worldwide


Caution: Some Certs for unsanctioned applications may be used for other applications from the same org that may be legitimate e.g. BlueJeans Conferencing (sanctioned) BlueJeans Remote Desktop Control (unsanctioned)

please do not bulk upload these certs without checking, chances are it will break your environment!

For what its worth personally WDAC >>>> Applocker

App Ref: https://appwiki.checkpoint.com/appwikisdb/public.htm  or https://getintopc.com/all-software-categories/

Also See A good article on abusing code signing certs: https://axelarator.github.io/posts/codesigningcerts/  

Of course there are ways around Cert Blocking (e.g. ImageRemoveCertificate API, signTool, SigThief, delcert - more opportunities for detection😉) 

Useful Ref For Programs people install on fresh desktop: https://ninite.com/ (also worth blocking ninite's cert)


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

# How to Upload the Bulk IOC CSV to MDE

As of 13/03/2023, certificates cannot be uploaded in bulk, however for domains, urls and hashes:  

From Defender, Go To Settings on bottom left:  
![image](https://user-images.githubusercontent.com/55988027/224496554-e26e2672-6216-4694-ab8a-015d0c08451a.png)

Then Endpoints:  
![image](https://user-images.githubusercontent.com/55988027/224496573-0a89865c-e882-4eb8-9172-aa3e5a1ba430.png)  

Indicators then Import - note it it doesn't matter whether you are in File Hash,Domain, IP or Cert tab:  

![image](https://user-images.githubusercontent.com/55988027/224496619-136fbd3f-7b3a-405f-9b85-edb993c42e94.png)  

Choose File, then hit Import then Hit Done - note that duplicates are skipped so you can keep adding to the existing CSV:    

![image](https://user-images.githubusercontent.com/55988027/224496768-7ff90df4-66b2-4398-8307-f424a9ac0303.png)  

# Python Bulk Ripper  

Work In Progress  


# Testing Tampered Executables  
[https://github.com/jkerai1/SoftwareCertificates/tree/main/Manipulated%20Exes%20For%20Testing  ](https://github.com/jkerai1/SoftwareCertificates/tree/ManipulatedExes/Manipulated%20Exes%20For%20Testing)
