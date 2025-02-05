I have added AV Folder in this repo for a few reasons:

1) Some AV adds exclusions reducing visibility or can outright disable defender
2) a user Running AV is a pretty big red flag and cause for concern
3) AV may need to be allowed by Software Cert
4) AV usually runs as SYSTEM so if youre able to abuse an EDR youd be able to run as system and youd be unable to be killed by another EDR due to being system
5) AVs run at kernel level which could lead to outages (e.g. crowdstrike 19/07/2024)  

See: https://www.linkedin.com/posts/jay-kerai-cyber_devfender-automateeverything-hacktheplanet-ugcPost-7102342764511535104-gM-F

# KQL

https://github.com/jkerai1/KQL-Queries/blob/main/Defender/Antivirus%20Domains%20-%20MDE%20DeviceNetworkEvents.kql

# Domain Bulk IOC BlockList 

https://github.com/jkerai1/SoftwareCertificates/blob/main/Bulk-IOC-CSVs/Antivirus%20IOCs.csv

