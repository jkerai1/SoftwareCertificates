Most of this is Org discretion really

I would advise for PWAs (progressive web app) over the executable wherever possible due to lower permission level - then you can further monitor access via defender for cloud apps

Discord can house some nasty malware - the application usage itself isn't usually the problem (Sure electron has its problems) but its due to how the hosting works, very easy to get free hosting of malware via discord's CDN

Telegram is another one I'd cautious about due to the large amount of piracy/hacker groups spreading files via this platform


# KQL

URL Blocklist available: https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/ChatSites.csv  
> ive Excluded Zoom, slack etc from here and left google hangouts in warn

MDA personal app category is missing a chunk of these domains, but I would recommend with layering with https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/MDA#auto-ban-discovered-personal-messaging-apps for extra level of protection  

```
let ChatIOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/ChatSites.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = ChatIOCs
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList )
| summarize count() by RemoteUrl,DeviceName, InitiatingProcessAccountUpn

```
