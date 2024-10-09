Most of these should be red flags in any environment  

RClone is not signed sadly but I would definitely be concerned if I saw Rclone in any environment  

[Checkout Living Off Trusted Sites (LOTS) Project](https://lots-project.com/)

⚠️[Checkout MDE Blocklist CSV for FileTransfer/PasteLike Sites](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/FileTransfer%20PasteLike%20Sites.csv) - could have business impact, run the below KQL before deploying, you may need to remove records from the CSV before deploying ⚠️
# KQL

```
let TransferIOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/FileTransfer%20PasteLike%20Sites.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = TransferIOCs
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList )
| summarize count() by RemoteUrl

```
