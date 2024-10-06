
# KQL

# Coin Domains
```
let Crypto = externaldata(type:string)[@"https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/ZeroDot1_CoinBlockerLists/master/domains.list"] with (format="csv", ignoreFirstRecord=True);
let DomainList = Crypto
| where type !startswith "#"
| extend RemoteUrl = replace_string(type, " ", "")
| project RemoteUrl;
DeviceNetworkEvents
| where RemoteUrl in~(DomainList)
| summarize count() by RemoteUrl
```

# Process
```
DeviceProcessEvents //Ref https://www.kqlsearch.com/query/Cryptominingdetection&clyfkv3xv00yimc0qpggs4hdy
| where ProcessCommandLine has_any ( 
    "--cpu-priority=", 
    "--donate-level=0", 
    " -o pool.", 
    " --nicehash", 
    " --algo=rx/0 ", 
    "stratum+tcp://", 
    "stratum+udp://", 
    "sh -c /sbin/modprobe msr allow_writes=on", 
    "LS1kb25hdGUtbGV2ZWw9", 
    "0tZG9uYXRlLWxldmVsP", 
    "tLWRvbmF0ZS1sZXZlbD", 
    "c3RyYXR1bSt0Y3A6Ly", 
    "N0cmF0dW0rdGNwOi8v", 
    "zdHJhdHVtK3RjcDovL", 
    "c3RyYXR1bSt1ZHA6Ly", 
    "N0cmF0dW0rdWRwOi8v", 
    "zdHJhdHVtK3VkcDovL"
)
```
# See Also 

[BlockList](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Crypto.csv) 

```
let CryptoDomains = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Crypto.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = CryptoDomains
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl has_any(CryptoDomains)

```
