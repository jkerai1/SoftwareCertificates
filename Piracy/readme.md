Self Explantory

Nicotine/Soulseek not signed

See also: https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Piracy.csv

# KQL

```
let PiracyDomains = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Piracy.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = PiracyDomains
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList)
| summarize count() by RemoteUrl

```


# Blocklist project
```
let PiracyBlockListProj=  externaldata(type: string)[@"https://raw.githubusercontent.com/blocklistproject/Lists/master/piracy.txt"] with (format="csv", ignoreFirstRecord=False)
| where type !startswith "#"
| extend RemoteUrl = replace_string(replace_string(type,"0.0.0.0", "")," ","")
| project RemoteUrl;
let TorrentBlockListProj = externaldata(type: string)[@"https://raw.githubusercontent.com/blocklistproject/Lists/master/torrent.txt"] with (format="csv", ignoreFirstRecord=False)
| where type !startswith "#"
| extend RemoteUrl = replace_string(replace_string(type,"0.0.0.0", "")," ","")
| project RemoteUrl;
DeviceNetworkEvents
| where RemoteUrl in~(TorrentBlockListProj) or RemoteUrl in~(PiracyBlockListProj)
| summarize count() by RemoteUrl

```
