I would outright Block any unmanaged Remote access Tool in corporate environment to reduce risk of a user being tricked into letting unauthorized party on device
Threat Actors themselves like using RMM to disguse their persistence  

Block list URLs coming soon!  

# KQL

```
let VPNRanges = externaldata (IpRange: string) [@'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt'] with (format=txt); 
SigninLogs
| where isnotempty(IPAddress)
| evaluate ipv4_lookup(VPNRanges, IPAddress, IpRange)
| join kind=leftouter IdentityInfo on $left.UserPrincipalName == $right.AccountObjectId
| extend Spur = strcat("https://spur.us/context/", IPAddress)
| summarize by UserPrincipalName, IPAddress, UserAgent, AccountUPN, Spur
| extend IP_0_Address = IPAddress
| extend Account_0_Name = UserPrincipalName
```




```
let RMMtools = externaldata (description: string, remote_domain: string, remote_utility: string, remote_utility_fileinfo: string) 
    ["https://raw.githubusercontent.com/splunk/security_content/refs/heads/develop/lookups/remote_access_software20240726.csv"] with(format='csv', ignoreFirstRecord=true); ////Shoutout to Frankie Li for highlighting this on LinkedIN
RMMtools
| where remote_utility != ""
| join kind=inner DeviceProcessEvents on $left.remote_utility == $right.InitiatingProcessFileName
| summarize by DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, ProcessVersionInfoCompanyName, ProcessVersionInfoFileDescription, description

```


Below is from https://www.kqlsearch.com/query/Find%20Rmm%20Processes&clmnyai1o00005ip4gm8dlvyr
```
DeviceProcessEvents
| where FileName has_any (
    "acticalRMM",
    "Action1",
    "AeroAdmin",
    "AgentMon.exe",
    "Ammyy",
    "AnyDesk",
    "Atera",
    "AteraAgent.exe",
    "AteraRC.exe",
    "Auvik.Agent.exe",
    "Auvik.Engine.exe",
    "awesome-rat",
    "ccme_sm.exe",
    "chaos",
    "Chrome Remote Desktop",
    "ConnectWise",
    "DameWare Mini Remote Control",
    "Dameware",
    "Deployment tools",
    "Domotz.exe",
    "DomotzClient.exe",
    "eHorus",
    "Fixme",
    "FlawedAmmyy",
    "friendspeak",
    "Get2",
    "getandgo",
    "GetASRSettings.exe",
    "GoToAssist",
    "Intelliadmin",
    "ir_agent.exe",
    "klnagent.exe",
    "konea.exe",
    "kworking.exe",
    "LogMeIn.exe",
    "LogMeIn",
    "LTAService.exe",
    "LTClient.exe",
    "LTSvcMon.exe",
    "MeshCentral",
    "mRemoteNG",
    "NAPClt.exe",
    "NetSupport",
    "ngrok",
    "NinjaRMM.exe",
    "NinjaRMM",
    "NinjaRMMAgent.exe",
    "nssm",
    "OCS Agent",
    "PDQDeploy",
    "Plink",
    "Pulseway.TrayApp.exe",
    "PulsewayService.exe",
    "putty.exe",
    "QuickAssist",
    "BASupSrvc",
    "BASupSrvcCnfg",
    "Radmin",
    "RealVNC",
    "Remote Manipulator System",
    "Remote Utilities",
    "RemotePC",
    "rustdesk",
    "ScreenConnect.Client.exe",
    "ScreenConnect.ClientService.exe",
    "ScreenConnect.Service.exe",
    "ScreenConnect.WindowsClient.exe",
    "ScreenConnect",
    "Splashtop",
    "SupRemo",
    "Syncro",
    "tacticalrmm",
    "TakeControlRDViewer.exe",
    "Tanium",
    "teamviewer.exe",
    "TigerVNC",
    "TightVNC",
    "tmate",
    "UltraViewer",
    "VncClient.exe",
    "VNCconnect",
    "WAPT",
    "Webex remote",
    "winvnc.exe",
    "ZA_Connect.exe",
    "ZohoAssist"
    )
| summarize count() by FileName
| sort by count_ desc 

```
