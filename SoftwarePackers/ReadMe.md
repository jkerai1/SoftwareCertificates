These should be blocked, no questions asked no software deployment should be used via either of these


# KQL


```
let SoftwareDownloadDomains = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/SoftwarePackersOrSoftwareDownloadProxySites.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = SoftwareDownloadDomains
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList)
| extend VT_domain = iff(isnotempty(RemoteUrl),strcat(@"https://www.virustotal.com/gui/domain/",RemoteUrl),RemoteUrl)
| summarize count() by RemoteUrl, VT_domain
// After Hunting visit https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs, download the CSV and consider uploading to MDE to block all domains. Remove any results that are legitimate usage.

```


# Bulk IOC List

https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/SoftwarePackersOrSoftwareDownloadProxySites.csv
