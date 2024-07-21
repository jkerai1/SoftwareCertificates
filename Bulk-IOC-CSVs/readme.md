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

# All in One KQL 

```
let CrowdstrikeIOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/main/Bulk-IOC-CSVs/Crowdstrike%20MDE%20IOC%20-%20Impersonation%20of%20crowdstrike%20over%20global%20outages.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = CrowdstrikeIOCs
| project IndicatorValue;
let emailurl = EmailUrlInfo
| where UrlDomain in~(DomainList)
| join EmailEvents on NetworkMessageId;
let emailevent = EmailEvents
| where SenderFromDomain in~(DomainList);
DeviceNetworkEvents
| where RemoteUrl in~(DomainList )
| union emailurl, emailevent
```

# BlocklistProject
```
let PornBlockListProj = externaldata(type: string)[@"https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt"] with (format="csv", ignoreFirstRecord=False)
| where type !startswith "#"
| where type !startswith "#"
| extend RemoteUrl = replace_string(replace_string(type,"0.0.0.0", "")," ","")
| project RemoteUrl;
let PiracyBlockListProj=  externaldata(type: string)[@"https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt"] with (format="csv", ignoreFirstRecord=False)
| where type !startswith "#"
| where type !startswith "#"
| extend RemoteUrl = replace_string(replace_string(type,"0.0.0.0", "")," ","")
| project RemoteUrl;
let TorrentBlockListProj = externaldata(type: string)[@"https://raw.githubusercontent.com/blocklistproject/Lists/master/torrent.txt"] with (format="csv", ignoreFirstRecord=False)
| where type !startswith "#"
| where type !startswith "#"
| extend RemoteUrl = replace_string(replace_string(type,"0.0.0.0", "")," ","")
| project RemoteUrl;
let PhishingBlockListProj = externaldata(type: string)[@"https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt"] with (format="csv", ignoreFirstRecord=False)
| where type !startswith "#"
| where type !startswith "#"
| extend RemoteUrl = replace_string(replace_string(type,"0.0.0.0", "")," ","")
| project RemoteUrl;
let MalwareBlockListProj = externaldata(type: string)[@"https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt"] with (format="csv", ignoreFirstRecord=False)
| where type !startswith "#"
| where type !startswith "#"
| extend RemoteUrl = replace_string(replace_string(type,"0.0.0.0", "")," ","")
| project RemoteUrl;
let RansomBlockListProj = externaldata(type: string)[@"https://raw.githubusercontent.com/blocklistproject/Lists/master/ransomware.txt"] with (format="csv", ignoreFirstRecord=False)
| where type !startswith "#"
| where type !startswith "#"
| extend RemoteUrl = replace_string(replace_string(type,"0.0.0.0", "")," ","")
| project RemoteUrl;
DeviceNetworkEvents
| where RemoteUrl in~(PornBlockListProj) or RemoteUrl in~(TorrentBlockListProj) or RemoteUrl in~(PiracyBlockListProj) or RemoteUrl in~(PhishingBlockListProj) or  RemoteUrl in~(MalwareBlockListProj) or RemoteUrl in~(RansomBlockListProj)
| summarize count() by RemoteUrl
```

# See More From Me on IOC Blocking!  

[Block TypoSquats in MDE/TABL](https://github.com/jkerai1/DNSTwistToMDEIOC) [![GitHub stars](https://img.shields.io/github/stars/jkerai1/DNSTwistToMDEIOC?style=flat-square)](https://github.com/jkerai1/DNSTwistToMDEIOC/stargazers)  
[Block Malicious Sites from JoeSandbox in MDE/TABL](https://github.com/jkerai1/JoeSandBoxToMDEBlockList) [![GitHub stars](https://img.shields.io/github/stars/jkerai1/JoeSandBoxToMDEBlockList?style=flat-square)](https://github.com/jkerai1/JoeSandBoxToMDEBlockList/stargazers)  
[Block Suspicious TLDs in TenantAllowBlockList](https://github.com/jkerai1/TLD-TABL-Block) [![GitHub stars](https://img.shields.io/github/stars/jkerai1/TLD-TABL-Block?style=flat-square)](https://github.com/jkerai1/TLD-TABL-Block/stargazers)
