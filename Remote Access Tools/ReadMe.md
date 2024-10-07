I would outright Block any unmanaged Remote access Tool in corporate environment to reduce risk of a user being tricked into letting unauthorized party on device
Threat Actors themselves like using RMM to disguse their persistence  

Block list URLs coming soon!  

# KQL


```
let RMMtools = externaldata (description: string, remote_domain: string, remote_utility: string, remote_utility_fileinfo: string) 
    ["https://raw.githubusercontent.com/splunk/security_content/refs/heads/develop/lookups/remote_access_software20240726.csv"] with(format='csv', ignoreFirstRecord=true); ////Shoutout to Frankie Li for highlighting this on LinkedIN
RMMtools
| where remote_utility != ""
| join kind=inner DeviceProcessEvents on $left.remote_utility == $right.InitiatingProcessFileName
| summarize by DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, ProcessVersionInfoCompanyName, ProcessVersionInfoFileDescription, description

```
```
let RMMSoftware = externaldata(RMMSoftware: string)[@"https://raw.githubusercontent.com/cyb3rmik3/Hunting-Lists/main/rmm-software.csv"] with (format="csv", ignoreFirstRecord=True);
let ExclDevices = datatable(excludeddev :string)  // Add as many devices you would like to exclude
 ["DeviceName1",
  "DeviceName2",
  "DeviceName3"];
let Timeframe = 7d; // Choose the best timeframe for your investigation
DeviceProcessEvents
    | where Timestamp > ago(Timeframe)
    | where ProcessVersionInfoCompanyName has_any (RMMSoftware)
    | where not(DeviceName in (['ExclDevices']))
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessCommandLine, AccountName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
    | sort by Timestamp desc

```

```
// First part based on tweet by: @Antonlovesdnb https://x.com/Antonlovesdnb/status/1840823846720385482
let LOLRMM = externaldata(Name:string,Category:string,Description:string,Author:string,Date:datetime,LastModified:datetime,Website:string,Filename:string,OriginalFileName:string,PEDescription:string,Product:string,Privileges:string,Free:string,Verification:string,SupportedOS:string,Capabilities:string,
Vulnerabilities:string,InstallationPaths:string,Artifacts:string,Detections:string,References:string,Acknowledgement:string)[@"https://lolrmm.io/api/rmm_tools.csv"] with (format="csv", ignoreFirstRecord=True);
let ParsedExecutables = LOLRMM
    | distinct InstallationPaths
    | extend FileNames = extract_all(@"\b([a-zA-Z0-9 _-]+\.exe)", InstallationPaths)
    | mv-expand FileNames
    | where isnotempty(FileNames)
    | project FileNames = tolower(FileNames)
    | distinct FileNames;
DeviceNetworkEvents
| where tolower(InitiatingProcessFileName) in (ParsedExecutables)
| where ActionType == "ConnectionSuccess"
| summarize TotalEvents = count(), ExecutableCount = dcount(InitiatingProcessFileName), Executables = make_set(InitiatingProcessFileName) by DeviceName, DeviceId

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
