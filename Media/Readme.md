VLC is probably the only program here I'd expect to see in corp env


# KQL [In Progress]

[MDE Domain Block List](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/streaming-sites.csv)
```
let StreamDomains = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/streaming-sites.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = StreamDomains
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList)
| summarize count() by RemoteUrl

```
