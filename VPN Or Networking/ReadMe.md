All Mostly Garbage

OpenVPN/Cisco/Fortigate may be expected 

For what its worth I think the best 3 public vpns are Mullvad, proton and windscribe  

Ngrok commonly abused my Threat Actors  

See [MDA section for Anonymous VPN](https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/MDA#block-anonymous-ips)
See [MDE Domain Block List](https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Consumer%20VPNs.csv)

# KQL

Consumer VPN download Pages
```
let VPNIOCs = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Consumer%20VPNs.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = VPNIOCs
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList)
| summarize count() by RemoteUrl

```


Consumer VPN Hunting by IP
```
let VPNRanges = externaldata (IpRange: string) [@'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt'] with (format=txt);
SigninLogs
| where isnotempty(IPAddress)
| evaluate ipv4_lookup(VPNRanges, IPAddress, IpRange)
| join kind=leftouter IdentityInfo on $left.UserPrincipalName == $right.AccountObjectId
| extend Spur = strcat("https://spur.us/context/", IPAddress)
| summarize by UserPrincipalName, IPAddress, UserAgent, AccountUPN, Spur //User Spur to validate data
| extend IP_0_Address = IPAddress
| extend Account_0_Name = UserPrincipalName
| extend Account = iff(isempty( AccountUPN),Account_0_Name,AccountUPN)
```

Detect Tor DNS request, Credit: Suraj Kumar
```
DeviceNetworkEvents 
| where TimeGenerated > ago(90d)
| extend AdditionalFields_query = tostring(parse_json(AdditionalFields)["query"]) 
| where AdditionalFields_query endswith ".onion"
| summarize count() by AdditionalFields_query, DeviceName
```


IP-API Geolocation API 
# Swagger

```
swagger: '2.0'
info:
  title: IPAPICustomConnector
  description: IP-API Geolocation API - Basic Querying
  version: '1.0'
host: ip-api.com
basePath: /json
schemes:
  - http
consumes: []
produces: []
paths:
  /{ipaddress}:
    get:
      responses:
        default:
          description: default
          schema:
            type: object
            properties:
              query:
                type: string
                description: query
              status:
                type: string
                description: status
              country:
                type: string
                description: country
              countryCode:
                type: string
                description: countryCode
              region:
                type: string
                description: region
              regionName:
                type: string
                description: regionName
              city:
                type: string
                description: city
              zip:
                type: string
                description: zip
              lat:
                type: number
                format: float
                description: lat
              lon:
                type: number
                format: float
                description: lon
              timezone:
                type: string
                description: timezone
              isp:
                type: string
                description: isp
              org:
                type: string
                description: org
              as:
                type: string
                description: as
      summary: Query IP
      operationId: Query
      parameters:
        - name: ipaddress
          in: path
          required: true
          type: string
definitions: {}
parameters: {}
responses: {}
securityDefinitions: {}
security: []
tags: []
```
