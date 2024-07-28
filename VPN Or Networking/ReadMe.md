All Mostly Garbage

OpenVPN/Cisco/Fortigate may be expected 

For what its worth I think the best 3 public vpns are Mullvad, proton and windscribe  

Ngrok commonly abused my Threat Actors  


# NordVPN KQL

```
let VPNRanges = externaldata (IpRange:string) [@'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt'] with (format=txt);
SigninLogs
| where isnotempty(IPAddress)
| where ResultType == 0
| evaluate ipv4_lookup(VPNRanges, IPAddress, IpRange)
| join kind=leftouter IdentityInfo on $left.UserPrincipalName== $right.AccountObjectId
| extend Spur = strcat("https://spur.us/context/",IPAddress)
| summarize by UserPrincipalName, IPAddress, UserAgent ,AccountUPN, Spur//, JobTitle
```
