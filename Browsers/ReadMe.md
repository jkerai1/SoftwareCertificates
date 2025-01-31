I would outright block any unmanaged Browser  

You could apply a soft-lock and stop users signing into entra with an unmanaged browser by enforcing token protection in conditional access. unless they install the SSO extension to get that WAM functionality they would be blocked from accessing corporate data.

See [Intune Section](https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/Intune) for Process Names and browser extension blocking/whitelisting  and [MDA for BYOD situations](https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/MDA)

# KQL 
```
let BrowserDomains = externaldata(type: string, IndicatorValue: string)[@"https://raw.githubusercontent.com/jkerai1/SoftwareCertificates/refs/heads/main/Bulk-IOC-CSVs/Browser%20IOCs.csv"] with (format="csv", ignoreFirstRecord=True);
let DomainList = BrowserDomains
| project IndicatorValue;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemoteUrl in~(DomainList)
//| where RemoteUrl != "dl.google.com" // if you allow google chrome
| summarize count() by RemoteUrl
```

# Browser AppLocker Example   - Non-Edge Browsers

This has been lifted from the edge management service option (aka Edge for business) - you can create a dummy policy from https://admin.microsoft.com/Adminportal/Home#/Edge/PolicyConfiguration/:
> If you do consider Edge for Business/Edge Management Service is viable for your business and want an importable template to baseline from check out the intune section of this repo [here](https://github.com/jkerai1/SoftwareCertificates/tree/main/Bulk-IOC-CSVs/Intune#edge-for-business-config)
> 
![Untitled](https://github.com/user-attachments/assets/2a7242be-dd5d-482d-99e6-8494894e75cf)  

In the backend this will deploy an intune policy "Block Third Party Browsing - Microsoft Edge management service" with the following 2 OMA-URIs  

![Untitled](https://github.com/user-attachments/assets/194618d3-f9b9-4ded-8a88-7ae28ba806a0)  

![image](https://github.com/user-attachments/assets/16f2324a-6151-4fcb-93f8-40a05a975194)

> I have dumped the XMLs here however these XMLs may update automatically from the edge management service and thus shouldn't be taken as fully updated. Note this WILL block chrome/firefox and will miss a few obscure browsers.

OMA-URI: ./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/MicrosoftEdgeManagement1/EXE/Policy
```
<RuleCollection Type="Exe" EnforcementMode="Enabled">
	<FilePublisherRule Id="06fdf5f2-4434-4b6b-b836-59dc1ee29b86" Name="&quot;&quot;, in OPERA GX INSTALLER, from O=OPERA NORWAY AS, L=OSLO, S=OSLO, C=NO" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=OPERA NORWAY AS, L=OSLO, S=OSLO, C=NO" ProductName="OPERA GX INSTALLER" BinaryName="">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="10d0ad50-5220-4ae7-b23a-fb2c81d7561b" Name="CHROME.EXE, in GOOGLE CHROME, from O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" ProductName="GOOGLE CHROME" BinaryName="CHROME.EXE">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="14a0952e-e740-4f5b-9983-68fb308a9a4f" Name="OPERA INTERNET BROWSER, from O=OPERA NORWAY AS, L=OSLO, S=OSLO, C=NO" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=OPERA NORWAY AS, L=OSLO, S=OSLO, C=NO" ProductName="OPERA INTERNET BROWSER" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="162e5a37-462a-4aa2-8e00-c6a309d4db7c" Name="FIREFOX, from O=MOZILLA CORPORATION, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=MOZILLA CORPORATION, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" ProductName="FIREFOX" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="2065bf10-abc5-4e0e-be01-0c0ebbc6806a" Name="&quot;&quot;, in OPERA GX INTERNET BROWSER, from O=OPERA NORWAY AS, L=OSLO, S=OSLO, C=NO" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=OPERA NORWAY AS, L=OSLO, S=OSLO, C=NO" ProductName="OPERA GX INTERNET BROWSER" BinaryName="">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="3f67adfe-d25e-4e0f-9469-13277a461a4e" Name="BRAVE BROWSER, from O=BRAVE SOFTWARE, INC., L=SAN FRANCISCO, S=CALIFORNIA, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=BRAVE SOFTWARE, INC., L=SAN FRANCISCO, S=CALIFORNIA, C=US" ProductName="BRAVE BROWSER" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="4603e22e-3ac8-4ba2-814e-b124fdaacb58" Name="OPERA INSTALLER, from O=OPERA NORWAY AS, L=OSLO, S=OSLO, C=NO" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=OPERA NORWAY AS, L=OSLO, S=OSLO, C=NO" ProductName="OPERA INSTALLER" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="70fd870b-db2b-4ce5-b96c-828997fcbd65" Name="360å®å¨æµè§å¨, from O=BEIJING QIHU TECHNOLOGY CO., LTD., L=BEIJING, S=BEIJING, C=CN" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=BEIJING QIHU TECHNOLOGY CO., LTD., L=BEIJING, S=BEIJING, C=CN" ProductName="360å®å¨æµè§å¨" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="7ad4056c-6707-4669-a271-adad34262b56" Name="GOOGLEUPDATESETUP.EXE, in GOOGLE UPDATE, from O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" ProductName="GOOGLE UPDATE" BinaryName="GOOGLEUPDATESETUP.EXE">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="7f206295-64f3-424f-b526-841364196cdc" Name="FIREFOX.EXE, in FIREFOX, from O=MOZILLA CORPORATION, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=MOZILLA CORPORATION, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" ProductName="FIREFOX" BinaryName="FIREFOX.EXE">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="81f5cc69-8512-4813-a280-ce09181ab03c" Name="VIVALDI, from O=VIVALDI TECHNOLOGIES AS, L=OSLO, S=OSLO, C=NO" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=VIVALDI TECHNOLOGIES AS, L=OSLO, S=OSLO, C=NO" ProductName="VIVALDI" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="98c628f0-6d03-4607-981e-36f931c106d4" Name="VIVALDI INSTALLER, from O=VIVALDI TECHNOLOGIES AS, L=OSLO, S=OSLO, C=NO" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=VIVALDI TECHNOLOGIES AS, L=OSLO, S=OSLO, C=NO" ProductName="VIVALDI INSTALLER" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="bf979a51-5b5f-42ac-a8ad-0f00685b0ad2" Name="TOR BROWSER, from O=THE TOR PROJECT, INC., L=WINCHESTER, S=NEW HAMPSHIRE, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=THE TOR PROJECT, INC., L=WINCHESTER, S=NEW HAMPSHIRE, C=US" ProductName="TOR BROWSER" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="d2af62f9-fd46-4975-9af7-9e536bc6dc10" Name="PUFFINSECUREBROWSER, from O=CLOUDMOSA, INC., L=SARATOGA, S=CALIFORNIA, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=CLOUDMOSA, INC., L=SARATOGA, S=CALIFORNIA, C=US" ProductName="PUFFINSECUREBROWSER" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="e59e3550-2a9c-4e73-9bce-6aec2b564b1b" Name="360å®å¨æµè§å¨, from O=BEIJING QIHU TECHNOLOGY CO., LTD., S=BEIJING, C=CN" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=BEIJING QIHU TECHNOLOGY CO., LTD., S=BEIJING, C=CN" ProductName="360å®å¨æµè§å¨" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="fa19dab2-2852-4342-abd4-6f7835fe5ade" Name="BRAVESOFTWARE UPDATE, from O=BRAVE SOFTWARE, INC., L=SAN FRANCISCO, S=CALIFORNIA, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=BRAVE SOFTWARE, INC., L=SAN FRANCISCO, S=CALIFORNIA, C=US" ProductName="BRAVESOFTWARE UPDATE" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="ff93f32c-2449-41f3-9c1e-b039cd7a3716" Name="PUFFIN SECURE BROWSER, from O=CLOUDMOSA, INC., L=SARATOGA, S=CALIFORNIA, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=CLOUDMOSA, INC., L=SARATOGA, S=CALIFORNIA, C=US" ProductName="PUFFIN SECURE BROWSER" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="ffa1a30b-d6fa-4d45-9725-900b8db2ea2c" Name="YANDEX, from O=YANDEX LLC, L=MOSCOW, S=MOSCOW, C=RU" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=YANDEX LLC, L=MOSCOW, S=MOSCOW, C=RU" ProductName="YANDEX" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default Rule) All files located in the Program Files folder" Description="Allows members of the Everyone group to run applications that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
		<Conditions>
			<FilePathCondition Path="%PROGRAMFILES%\*" />
		</Conditions>
	</FilePathRule>
	<FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default Rule) All files located in the Windows folder" Description="Allows members of the Everyone group to run applications that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
		<Conditions>
			<FilePathCondition Path="%WINDIR%\*" />
		</Conditions>
	</FilePathRule>
	<FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="(Default Rule) All files" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow">
		<Conditions>
			<FilePathCondition Path="*" />
		</Conditions>
	</FilePathRule>
	<FilePublisherRule Id="6a1bb055-19bd-437d-8c8b-54310ef9bf18" Name="UC BROWSER, from O=TAOBAO (CHINA) SOFTWARE CO.,LTD., L=HANGZHOU, S=ZHEJIANG, C=CN" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="O=TAOBAO (CHINA) SOFTWARE CO.,LTD., L=HANGZHOU, S=ZHEJIANG, C=CN" ProductName="UC BROWSER" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
</RuleCollection>
```
OMA-URI: ./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/MicrosoftEdgeManagement2/StoreApps/Policy

```
<RuleCollection Type="Appx" EnforcementMode="Enabled">
	<FilePublisherRule Id="0b9e616b-16b8-44cc-8e97-5149e3dc57d8" Name="24052cubeof11.ReluctantWebBrowser, from cubeof11" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=22BAF22C-B18E-47D6-88FB-D5974752F343" ProductName="24052cubeof11.ReluctantWebBrowser" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="10ba3ea5-6c04-4750-9874-ffb57bf03ff2" Name="16939CMDevelopers.ChromeeLite, from CM Developers" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=48DEE1E3-6D5F-499E-94CF-7E30B10FFC30" ProductName="16939CMDevelopers.ChromeeLite" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="250872b3-713e-4a0a-be7d-4e676b50d077" Name="6382CoalaApps.ChromosomeXSearch, from Coala Apps" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=F854BC6F-3937-4F2A-A22A-168855608793" ProductName="6382CoalaApps.ChromosomeXSearch" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="3e1baffb-7a18-4a8e-986f-8ff81467a613" Name="56869Yu-weiz.NextExplorer, from Yu-weiz" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=DD6BF031-5E0B-4EE9-8D35-879A628BD278" ProductName="56869Yu-weiz.NextExplorer" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="43c4ffcf-71a6-4125-95d7-db544caaa5d2" Name="Mozilla.Firefox, from Mozilla" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=082E9164-EE6C-4EC8-B62C-441FAE7BEFA1" ProductName="Mozilla.Firefox" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="53eb36d8-f192-4ee6-92af-83212744253c" Name="54317MosheNahari.ClientforWhatsapp, from Siduron Apps" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=3A19D3E3-3D60-4138-9B1F-764CD890DF7C" ProductName="54317MosheNahari.ClientforWhatsapp" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="6abce77f-2a93-4800-a5b3-b27123039e22" Name="51675URK96.SEdgeBrowser, from URK96" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=558FBEBE-C1DE-4502-AFA1-2ACF1A20C1EE" ProductName="51675URK96.SEdgeBrowser" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="6d18daf9-4c21-49d4-846a-fe18c636f7de" Name="60516PlexiLabs.LoboBrowser, from XAOS Interactive" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=5310D85C-70AB-4A10-A106-5F919AB6CE5C" ProductName="60516PlexiLabs.LoboBrowser" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="7b882ecb-4087-4a23-aa65-8d0c1f3ebf2a" Name="45740OneNow.KrakenTabBrowser, from OneNow" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=F718D461-F83F-41E7-BD6C-F74C21E77E42" ProductName="45740OneNow.KrakenTabBrowser" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="a334c95e-a554-4386-b949-4d20cc526e61" Name="60191FreshJuice.PhoenixSearch, from FreshJuice" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=9D28CE35-8541-4B9D-A3FD-D3BB9DA54AE3" ProductName="60191FreshJuice.PhoenixSearch" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow">
		<Conditions>
			<FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
				<BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="c0c8b43a-9e7f-470e-80d4-77887f351d58" Name="7756HardAtWork.SimpleExplorer10, from Carlos Rafael Ramirez" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=4F7A24A2-EB07-469A-A810-EE2D901CDD37" ProductName="7756HardAtWork.SimpleExplorer10" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="c32b0f36-b56e-41d7-a5a9-b66bf5ec22cb" Name="6727MontyInc.ChromaticBrowser, from Monty Inc." Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=4987CCC1-D52D-4392-9493-B98F05580569" ProductName="6727MontyInc.ChromaticBrowser" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="f1bfcd65-b216-4c9e-94e5-4cb264a88861" Name="DuckDuckGo.DesktopBrowser, from DuckDuckGo" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=&quot;Duck Duck Go, Inc.&quot;, OU=Engineering, O=&quot;Duck Duck Go, Inc.&quot;, L=Paoli, S=Pennsylvania, C=US, SERIALNUMBER=5019303, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US" ProductName="DuckDuckGo.DesktopBrowser" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
	<FilePublisherRule Id="fa21475c-9ec1-4a2f-b66d-79c8212abc30" Name="GiftCardBal.WebMacroBot, from Aifen App" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
		<Conditions>
			<FilePublisherCondition PublisherName="CN=CAF32E86-4D61-487F-B9B1-3DFD714E3B2E" ProductName="GiftCardBal.WebMacroBot" BinaryName="*">
				<BinaryVersionRange LowSection="*" HighSection="*" />
			</FilePublisherCondition>
		</Conditions>
	</FilePublisherRule>
</RuleCollection>
```

