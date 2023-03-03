# SofwareCertificates
Repository for Software Certs for easy software blocking across corp environments, for example, using MDE IOC or GPO

e.g. https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/indicator-certificates?view=o365-worldwide


Caution: Some Certs for unsanctioned applications may be used for other applications from the same org that may be legitimate e.g. BlueJeans Conferencing (sanctioned) BlueJeans Remote Desktop Control (unsanctioned)


Useful Ref For Programs people install on fresh desktop: https://ninite.com/ (also worth blocking ninite's cert)

App Ref: https://appwiki.checkpoint.com/appwikisdb/public.htm  

Also See: https://axelarator.github.io/posts/codesigningcerts/  


To Export Software Certificates:
Right Click on Exe, Select Properties:

Go To Digital Signature Tab:  
![image](https://user-images.githubusercontent.com/55988027/222768088-e2f4ccfd-5cf5-4bfd-97d6-716e6a2e7636.png)

View Certificate:  

![image](https://user-images.githubusercontent.com/55988027/222768203-9015f003-8f3f-4823-af34-c06a3d897d0b.png)

Details Tab: 
![image](https://user-images.githubusercontent.com/55988027/222768233-2ada4ab9-fd4b-4588-87a4-2e39ad09fecc.png)
 
Copy To File:
![image](https://user-images.githubusercontent.com/55988027/222768521-e6df24dc-76b2-46c7-b8d2-8c5d02c8337e.png)

Export as Cer:  
![image](https://user-images.githubusercontent.com/55988027/222768623-1c6c9523-19ff-4d0f-a7ce-623036ed77fa.png)

