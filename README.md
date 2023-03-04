# SofwareCertificates
Repository for Software Certs for easy software blocking across corp environments, for example, using MDE IOC/AppLocker/WDAC

e.g. https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/indicator-certificates?view=o365-worldwide


Caution: Some Certs for unsanctioned applications may be used for other applications from the same org that may be legitimate e.g. BlueJeans Conferencing (sanctioned) BlueJeans Remote Desktop Control (unsanctioned)


Useful Ref For Programs people install on fresh desktop: https://ninite.com/ (also worth blocking ninite's cert)

App Ref: https://appwiki.checkpoint.com/appwikisdb/public.htm  

Also See: https://axelarator.github.io/posts/codesigningcerts/  


# To Export Software Certificates - Pull Requests Welcome:
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

