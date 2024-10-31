Start-Transcript -Path C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Edithostfile_remediate.log -Append
$Records = @(
    "0.0.0.0 jsecoin.com"
    "0.0.0.0 knaben.eu"
    "0.0.0.0 amsi.fail"
    "0.0.0.0 revshells.com"
    "0.0.0.0 bazaar.abuse.ch"
    "0.0.0.0 vx-underground.org"
    "0.0.0.0 morirt.com"
    "0.0.0.0 malshare.com"
    "0.0.0.0 contagiodump.blogspot.com"
    "0.0.0.0 dasmalwerk.eu"
    "0.0.0.0 virusshare.com"
    "0.0.0.0 hide01.ir"
    "0.0.0.0 send.vis.ee"
    "0.0.0.0 xss.is"
    "0.0.0.0 privacy.sexy"
    "0.0.0.0 notepad.plus"
    "0.0.0.0 textbin.net"
    "0.0.0.0 1337xto.to"
    "0.0.0.0 1337xxx.to"
    "0.0.0.0 yts.homes"
    "0.0.0.0 rarbg.tw"
    "0.0.0.0 rargb.to"
    "0.0.0.0 limetorrent.cc"
    "0.0.0.0 torrentz2.netlify.app"
    "0.0.0.0 eztv.unblocked.how"
    "0.0.0.0 tixati.com"
    "0.0.0.0 nicotine-plus.org"
    "0.0.0.0 onionshare.org"
    "0.0.0.0 mediaget.com"
    "0.0.0.0 serveo.net"
    "0.0.0.0 tempfile.io"
    "0.0.0.0 leak.sx"
    "0.0.0.0 bin.sx"
    "0.0.0.0 onionmail.org"
    "0.0.0.0 pastebin.com"
)
Set-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value $Records
Stop-Transcript
