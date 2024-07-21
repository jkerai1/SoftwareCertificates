Bulk CSV lists for blocking IOCs that aren't certificates  


Note there is a limit of 500 IOCs at a time in bulk 

Crowdstrike being looked at via https://urlscan.io/search/#crowdstrike*  

# DeviceNetworkEvents Example KQL 

```
let CrowdstrikeIOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/main/Bulk-IOC-CSVs/Crowdstrike%20MDE%20IOC%20-%20Impersonation%20of%20crowdstrike%20over%20global%20outages.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = CrowdstrikeIOCs
| project IndicatorValue;
DeviceNetworkEvents
| where RemoteUrl in~(DomainList )
```
# Email Events Example KQL
```
let CrowdstrikeIOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/main/Bulk-IOC-CSVs/Crowdstrike%20MDE%20IOC%20-%20Impersonation%20of%20crowdstrike%20over%20global%20outages.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = CrowdstrikeIOCs
| project IndicatorValue;
EmailEvents
| where SenderFromDomain in~(DomainList)
```

# Email URL info KQL   
```
let CrowdstrikeIOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/main/Bulk-IOC-CSVs/Crowdstrike%20MDE%20IOC%20-%20Impersonation%20of%20crowdstrike%20over%20global%20outages.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = CrowdstrikeIOCs
| project IndicatorValue;
EmailUrlInfo
| where UrlDomain in~(DomainList)
| join EmailEvents on NetworkMessageId
```

# See More From Me on IOC Blocking!  

[Block TypoSquats in MDE/TABL](https://github.com/jkerai1/DNSTwistToMDEIOC) [![GitHub stars](https://img.shields.io/github/stars/jkerai1/DNSTwistToMDEIOC?style=flat-square)](https://github.com/jkerai1/DNSTwistToMDEIOC/stargazers)  
[Block Malicious Sites from JoeSandbox in MDE/TABL](https://github.com/jkerai1/JoeSandBoxToMDEBlockList) [![GitHub stars](https://img.shields.io/github/stars/jkerai1/JoeSandBoxToMDEBlockList?style=flat-square)](https://github.com/jkerai1/JoeSandBoxToMDEBlockList/stargazers)  
[Block Suspicious TLDs in TenantAllowBlockList](https://github.com/jkerai1/TLD-TABL-Block) [![GitHub stars](https://img.shields.io/github/stars/jkerai1/TLD-TABL-Block?style=flat-square)](https://github.com/jkerai1/TLD-TABL-Block/stargazers)
