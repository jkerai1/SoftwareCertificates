Minecraft is one game I'd very cautious about considering lots of the custom mods/maps end up being malware
Unfortunately it is signed by microsoft now. I'd also block roblox

# KQL  

```
let GamingDomains = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Gaming.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = GamingDomains
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList)
| summarize count() by RemoteUrl
```
