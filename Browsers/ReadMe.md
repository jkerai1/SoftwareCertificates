I would outright block any unmanaged Browser  

You could apply a soft-lock and stop users signing into entra with an unmanaged browser by enforcing token protection in conditional access. unless they install the SSO extension to get that WAM functionality they would be blocked from accessing corporate data.

See [Intune Section](https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/Intune) for Process Names and browser extension blocking/whitelisting  and [MDA for BYOD situations](https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/MDA)

# KQL 
```
let BrowserDomains = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Browser%20IOCs.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = BrowserDomains
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList)
| summarize count() by RemoteUrl

```
