
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
