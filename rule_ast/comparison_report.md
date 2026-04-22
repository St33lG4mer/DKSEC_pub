# Sigma vs Elastic — Rule Gap Analysis

## What to do

| Action | Rules | Meaning |
|--------|-------|---------|
| ✅ **Add to SIEM** | **1331** | Sigma rules with no Elastic equivalent — import these |
| ⏭️ **Skip** | **283** | Elastic already covers these — don't import the Sigma version |
| 🔍 Weak overlap | 576 | Partial signal match — probably fine to add the Sigma rule, but worth a glance |
| ❓ Uncompared | 38 | Sigma rules with regex/unparseable conditions — check manually |

All **242** previously-flagged 'Pick one' rules have been auto-decided using three criteria:
1. **Title similarity < 0.12** → different techniques that share generic field values → ADD
2. **Sigma adds only generic noise** (short flags, bare extensions, common proc names) → SKIP
3. **Sigma adds 3+ specific indicators** → ADD

---

## ✅ Add to SIEM (1331 rules)

No meaningful Elastic equivalent found. Import these.
(1090 with no overlap · 241 auto-resolved from the 'pick one' bucket)

### APT / Threat Actor (46)

| Rule | What it detects |
|------|----------------|
| **Query Win Apt Diamond Steel Indicators** | `any where dns.question.name like~ ("*3dkit.org*", "*dersmarketim.com*", "*galerielamy.com*", "*olidhealth.com*")` |
| **Query Win Apt Dprk Malicious Domains** | `any where dns.question.name like~ ("connection.lockscreen.kro.kr", "updating.dothome.co.kr")` |
| **Apt Cozy Bear Phishing Campaign Indicators** | `any where file.path like~ ("*ds7002.lnk*", "*ds7002.pdf*", "*ds7002.zip*")` |
| **Apt Diamond Sleet Indicators** | `any where file.path like~ ("*:\\ProgramData\\4800-84DC-063A6A41C5C", "*:\\ProgramData\\clip.exe", "*:\\ProgramData\\DSRO…` |
| **Apt Forest Blizzard Activity** | `any where ((file.path like~ ("C:\\ProgramData\\Microsoft\\v*", "C:\\ProgramData\\Adobe\\v*", "C:\\ProgramData\\Comms\\v*…` |
| **Apt Forest Blizzard Constrained Js** | `any where file.path:"C:\\Windows\\System32\\DriverStore\\FileRepository\\*" and file.path:"*\\.js"` |
| **Apt Lace Tempest Indicators** | `any where (file.path like~ ("*:\\Program Files\\SysAidServer\\tomcat\\webapps\\usersfiles\\user.exe", "*:\\Program Files…` |
| **Apt Onyx Sleet Indicators** | `any where file.path:"*:\\Windows\\ADFS\\bg\\inetmgr.exe"` |
| **Image Load Apt Cozy Bear Graphical Proton Dlls** | `any where file.path like~ ("*\\AclNumsInvertHost.dll", "*\\AddressResourcesSpec.dll", "*\\BlendMonitorStringBuild.dll", …` |
| **Image Load Apt Diamond Sleet Side Load** | `any where (process.executable:"*:\\ProgramData\\clip.exe" and file.path:"*:\\ProgramData\\Version.dll") or (process.exec…` |
| **Image Load Apt Lazarus Side Load Activity** | `any where (process.executable:"C:\\ProgramShared\\PresentationHost.exe" and file.path:":\\ProgramShared\\mscoree.dll") o…` |
| **Apt Apt10 Cloud Hopper** | `any where (process.executable:"*\\cscript.exe" and process.command_line:"*.vbs /shell *") or (process.command_line:"*csv…` |
| **Apt Apt27 Emissary Panda** | `any where (process.parent.executable:"*\\sllauncher.exe" and process.executable:"*\\svchost.exe") or (process.parent.exe…` |
| **Apt Apt29 Phishing Campaign Indicators** | `any where process.command_line:"*-noni -ep bypass $*" or (process.command_line:"*cyzfc.dat,*" and process.command_line:"…` |
| **Apt Apt31 Judgement Panda** | `any where (process.command_line:"*ldifde*" and process.command_line:"*-f -n*" and process.command_line:"*eprod.ldf*") or…` |
| **Apt Bear Activity Gtr19** | `any where (process.command_line:"*xcopy /S /E /C /Q /H \\\\*" and process.command_line:"*\\sysvol\\*") or (process.comma…` |
| **Apt Diamond Sleet Indicators** | `any where process.command_line:"* uTYNkfKxHiZrx3KJ*"` |
| **Apt Empiremonkey** | `any where process.command_line:"*/e:jscript*" and process.command_line:"*\\Local\\Temp\\Errors.bat*"` |
| **Apt Equationgroup Dll U Load** | `any where process.command_line:"*-export dll_u*" or (process.command_line like~ ("*,dll_u", "* dll_u"))` |
| **Apt Greenbug May20** | `any where (process.executable like~ ("*:\\ProgramData\\adobe\\Adobe.exe", "*:\\ProgramData\\oracle\\local.exe", "*\\revs…` |
| **Apt Hafnium** | `any where (process.command_line:"*attrib*" and process.command_line:"* +h *" and process.command_line:"* +s *" and proce…` |
| **Apt Lazarus Binary Masquerading** | `any where (process.executable like~ ("*\\msdtc.exe", "*\\gpsvc.exe")) and (not (process.executable like~ ("C:\\Windows\\…` |
| **Apt Lazarus Group Activity** | `any where (process.command_line like~ ("*reg.exe save hklm\\sam %temp%\\~reg_sam.save*", "*1q2w3e4r@#$@#$@#$*", "* -hp1q…` |
| **Apt Mercury** | `any where process.command_line:"*-exec bypass -w 1 -enc*" and process.command_line:"*UwB0AGEAcgB0AC0ASgBvAGIAIAAtAFMAYwB…` |
| **Apt Mint Sandstorm Log4J Wstomcat Execution** | `any where process.parent.executable:"*\\ws_tomcatservice.exe" and (not process.executable:"*\\repadmin.exe")` |
| **Apt Mustang Panda Indicators** | `any where (process.command_line:"*copy SolidPDFCreator.dll*" and process.command_line:"*C:\\Users\\Public\\Libraries\\Ph…` |
| **Apt Sourgrum** | `any where (process.executable like~ ("*windows\\system32\\Physmem.sys*", "*Windows\\system32\\ime\\SHARED\\WimBootConfig…` |
| **Apt Ta17 293A Ps** | `any where process.command_line:"*ps.exe -accepteula*" and process.command_line:"*-s cmd /c netstat*"` |
| **Apt Taidoor** | `any where (process.command_line like~ ("*dll,MyStart*", "*dll MyStart*")) or (process.command_line:"* MyStart" and proce…` |
| **Apt Tropictrooper** | `any where process.command_line:"*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*"` |
| **Apt Turla Commands Critical** | `any where process.command_line like~ ("net use \\\\%DomainController%\\C$ \"P@ssw0rd\" *", "dir c:\\*.doc* /s", "dir %TE…` |
| **Apt Winnti Mal Hk Jan20** | `any where ((process.parent.executable like~ ("*C:\\Windows\\Temp*", "*\\hpqhvind.exe*")) and process.executable:"C:\\Pro…` |
| **Apt Winnti Pipemon** | `any where process.command_line:"*setup0.exe -p*" or (process.command_line:"*setup.exe*" and (process.command_line like~ …` |
| **Apt Wocao** | `any where process.command_line like~ ("*checkadmin.exe 127.0.0.1 -all*", "*netsh advfirewall firewall add rule name=powe…` |
| **Apt Zxshell** | `any where process.executable:"*\\rundll32.exe" and (process.command_line like~ ("*zxFunction*", "*RemoteDiskXXXXX*"))` |
| **Hktl Sharp Impersonation** | `any where (process.executable:"*\\SharpImpersonation.exe" or process.pe.original_file_name:"SharpImpersonation.exe") or …` |
| **Registry Event Apt Leviathan** | `any where registry.path:"*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ntkd*"` |
| **Registry Event Apt Oceanlotus Registry** | `any where registry.path:"*\\SOFTWARE\\Classes\\CLSID\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\\Model*" or (registry.path …` |
| **Registry Event Apt Oilrig Mar18** | `any where registry.path like~ ("*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UMe", "*SOFTWARE\\Microsoft\\Windows\\Cur…` |
| **Registry Event Apt Pandemic** | `any where registry.path:"*\\SYSTEM\\CurrentControlSet\\services\\null\\Instance*"` |
| **Registry Set Apt Forest Blizzard Custom Protocol Handler** | `any where registry.path:"*\\PROTOCOLS\\Handler\\rogue\\CLSID*" and winlog.event_data.Details:"{026CC6D7-34B2-33D5-B551-C…` |
| **Registry Set Apt Forest Blizzard Custom Protocol Handler Dll** | `any where registry.path:"*\\CLSID\\{026CC6D7-34B2-33D5-B551-CA31EB6CE345}\\Server*" and winlog.event_data.Details:"*.dll…` |
| **Apt Oilrig Mar18** | `any where winlog.channel:"Security" and (event.code:"4698" and (winlog.event_data.TaskName like~ ("SC Scheduled Scan", "…` |
| **Apt Slingshot** | `any where winlog.channel:"Security" and (event.code:"4701" and winlog.event_data.TaskName:"\\Microsoft\\Windows\\Defrag\…` |
| **Apt Wocao** | `any where winlog.channel:"Security" and (event.code:"4799" and winlog.event_data.TargetUserName:"Administr*" and winlog.…` |
| **Taskscheduler Apt Cozy Bear Graphical Proton Task Names** | `any where winlog.channel:"Microsoft-Windows-TaskScheduler/Operational" and ((event.code like~ ("129", "140", "141")) and…` |

### C2 / Implants (34)

| Rule | What it detects |
|------|----------------|
| **Create Remote Thread Win Hktl Cobaltstrike** | `any where winlog.event_data.StartAddress like~ ("*0B80", "*0C7C", "*0C88")` |
| **Query Win Mal Cobaltstrike** | `any where (dns.question.name like~ ("aaa.stage.*", "post.1*")) or dns.question.name:"*.stage.123456.*"` |
| **Query Win Malware Socgholish Second Stage C2** | `any where process.executable:"*\\wscript.exe" and dns.question.name:"SigmaRegularExpression(regexp=SigmaString(['[a-f0-9…` |
| **Malware 3Cx Compromise Beaconing Activity** | `any where process.executable:"*\\3CXDesktopApp.exe" and (destination.domain like~ ("*akamaicontainer.com*", "*akamaitech…` |
| **Net Dns Apt Equation Group Triangulation C2 Coms** | `any where query like~ ("addatamarket.net", "ans7tv.net", "anstv.net", "backuprabbit.com", "businessvideonews.com", "clou…` |
| **Net Dns Mal Cobaltstrike** | `any where (query like~ ("aaa.stage.*", "post.1*")) or query:"*.stage.123456.*"` |
| **Pipe Created Hktl Cobaltstrike** | `any where (file.name:"*\\MSSE-*" and file.name:"*-server*") or file.name:"\\postex_*" or file.name:"\\status_*" or file.…` |
| **Pipe Created Hktl Cobaltstrike Susp Pipe Patterns** | `any where (((file.name like~ ("\\DserNamePipe*", "\\f4c3*", "\\f53f*", "\\fullduplex_*", "\\mojo.5688.8052.1838949397870…` |
| **Proc Access Win Hktl Littlecorporal Generated Maldoc** | `any where process.executable:"*\\winword.exe" and (winlog.event_data.CallTrace:"*:\\Windows\\Microsoft.NET\\Framework64\…` |
| **Apt Turla Comrat May20** | `any where (process.command_line like~ ("*tracert -h 10 yahoo.com*", "*.WSqmCons))|iex;*", "*Fr`omBa`se6`4Str`ing*")) or …` |
| **Apt Unc2452 Ps** | `any where (process.command_line:"*Invoke-WMIMethod win32_process -name create -argumentlist*" and process.command_line:"…` |
| **Apt Unc2452 Vbscript Pattern** | `any where (process.command_line:"*Execute*" and process.command_line:"*CreateObject*" and process.command_line:"*RegRead…` |
| **Dns Exfiltration Tools Execution** | `any where process.executable like~ ("*\\iodine.exe", "*\\dnscat2*")` |
| **Hktl Cobaltstrike Load By Rundll32** | `any where (process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE" or (process.command_line…` |
| **Hktl Sliver C2 Execution Pattern** | `any where process.command_line:"*-NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8*"` |
| **Lolbin Data Exfiltration By Using Datasvcutil** | `any where (process.command_line like~ ("*/in:*", "*/out:*", "*/uri:*")) and (process.executable:"*\\DataSvcUtil.exe" or …` |
| **Pua Adfind Enumeration** | `any where (process.command_line like~ ("*lockoutduration*", "*lockoutthreshold*", "*lockoutobservationwindow*", "*maxpwd…` |
| **Remote Access Tools Rurat Non Default Location** | `any where ((process.executable like~ ("*\\rutserv.exe", "*\\rfusclient.exe")) or process.pe.product:"Remote Utilities") …` |
| **Renamed Rurat** | `any where process.pe.product:"Remote Utilities" and (not (process.executable like~ ("*\\rutserv.exe", "*\\rfusclient.exe…` |
| **Setspn Spn Enumeration** | `any where (process.executable:"*\\setspn.exe" or process.pe.original_file_name:"setspn.exe" or (process.pe.description:"…` |
| **Susp Data Exfiltration Via Cli** | `any where (((process.executable like~ ("*\\powershell_ise.exe", "*\\powershell.exe", "*\\pwsh.exe", "*\\cmd.exe")) and (…` |
| **Registry Event Narrator Feedback Persistance** | `any where (winlog.event_data.EventType:"DeleteValue" and registry.path:"*\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\…` |
| **Registry Set Disable Administrative Share** | `any where registry.path:"*\\Services\\LanmanServer\\Parameters\\*" and (registry.path like~ ("*\\AutoShareWks", "*\\Auto…` |
| **Registry Set Malware Kapeka Backdoor Configuration** | `any where (registry.path:"*\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\{*" and registry.path:"*\\Seed") and (not win…` |
| **Registry Set Susp Pendingfilerenameoperations** | `any where registry.path:"*\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations*" and (process.exec…` |
| **Client Mal Cobaltstrike** | `any where winlog.channel:"Microsoft-Windows-DNS Client Events/Operational" and (event.code:"3008" and ((dns.question.nam…` |
| **Cobaltstrike Service Installs** | `any where winlog.channel:"Security" and (event.code:"4697" and ((winlog.event_data.ServiceFileName:"*ADMIN$*" and winlog…` |
| **Meterpreter Or Cobaltstrike Getsystem Service Install** | `any where winlog.channel:"Security" and (event.code:"4697" and (((winlog.event_data.ServiceFileName:"*/c*" and winlog.ev…` |
| **Password Policy Enumerated** | `any where winlog.channel:"Security" and (event.code:"4661" and winlog.event_data.AccessList:"*%%5392*" and winlog.event_…` |
| **Scm Database Privileged Operation** | `any where winlog.channel:"Security" and ((event.code:"4674" and winlog.event_data.ObjectType:"SC_MANAGER OBJECT" and win…` |
| **User Added To Local Administrators** | `any where winlog.channel:"Security" and ((event.code:"4732" and (winlog.event_data.TargetUserName:"Administr*" or winlog…` |
| **Vssaudit Secevent Source Registration** | `any where winlog.channel:"Security" and (winlog.event_data.AuditSourceName:"VSSAudit" and (event.code like~ ("4904", "49…` |
| **System Cobaltstrike Service Installs** | `any where winlog.channel:"System" and ((winlog.provider_name:"Service Control Manager" and event.code:"7045") and ((winl…` |
| **System Meterpreter Or Cobaltstrike Getsystem Service Installation** | `any where winlog.channel:"System" and ((winlog.provider_name:"Service Control Manager" and event.code:"7045") and (((win…` |

### Credential Access (33)

| Rule | What it detects |
|------|----------------|
| **Create Remote Thread Win Powershell Lsass** | `any where (process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) and winlog.event_data.TargetImage:"*\\lsass.ex…` |
| **Create Remote Thread Win Susp Password Dumper Lsass** | `any where winlog.event_data.TargetImage:"*\\lsass.exe" and winlog.event_data.StartModule==""` |
| **Hktl Mimikatz Files** | `any where file.path like~ ("*.kirbi", "*mimilsa.log")` |
| **Lsass Default Dump File Names** | `any where (file.path like~ ("*\\Andrew.dmp", "*\\Coredump.dmp", "*\\lsass.dmp", "*\\lsass.rar", "*\\lsass.zip", "*\\NotL…` |
| **Proc Access Win Hktl Handlekatz Lsass Access** | `any where winlog.event_data.TargetImage:"*\\lsass.exe" and winlog.event_data.GrantedAccess:"0x1440" and winlog.event_dat…` |
| **Proc Access Win Lsass Dump Comsvcs Dll** | `any where winlog.event_data.TargetImage:"*\\lsass.exe" and process.executable:"*\\rundll32.exe" and winlog.event_data.Ca…` |
| **Proc Access Win Lsass Dump Keyword Image** | `any where winlog.event_data.TargetImage:"*\\lsass.exe" and process.executable:"*dump*" and (winlog.event_data.GrantedAcc…` |
| **Proc Access Win Lsass Memdump** | `any where (winlog.event_data.TargetImage:"*\\lsass.exe" and (winlog.event_data.GrantedAccess like~ ("*0x1038*", "*0x1438…` |
| **Proc Access Win Lsass Powershell Access** | `any where (process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) and winlog.event_data.TargetImage:"*\\lsass.ex…` |
| **Proc Access Win Lsass Remote Access Trough Winrm** | `any where (winlog.event_data.TargetImage:"*\\lsass.exe" and process.executable:"*:\\Windows\\system32\\wsmprovhost.exe")…` |
| **Proc Access Win Lsass Susp Source Process** | `any where (winlog.event_data.TargetImage:"*\\lsass.exe" and (winlog.event_data.GrantedAccess like~ ("*10", "*30", "*50",…` |
| **Proc Access Win Lsass Whitelisted Process Names** | `any where winlog.event_data.TargetImage:"*\\lsass.exe" and (process.executable like~ ("*\\TrolleyExpress.exe", "*\\Proce…` |
| **Certutil Ntlm Coercion** | `any where (process.executable:"*\\certutil.exe" or process.pe.original_file_name:"CertUtil.exe") and (process.command_li…` |
| **Device Credential Deployment** | `any where process.executable:"*\\DeviceCredentialDeployment.exe"` |
| **Powershell Getprocess Lsass** | `any where process.command_line like~ ("*Get-Process lsas*", "*ps lsas*", "*gps lsas*")` |
| **Reg Credential Access Via Password Filter** | `any where process.command_line:"*HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa*" and process.command_line:"*scecli\\0*" …` |
| **Reg Enumeration For Credentials In Registry** | `any where (process.executable:"*\\reg.exe" and (process.command_line:"* query *" and process.command_line:"*/t *" and pr…` |
| **Rpcping Credential Capture** | `any where ((process.executable:"*\\RpcPing.exe" or process.pe.original_file_name:"\\RpcPing.exe") and process.command_li…` |
| **Sysinternals Procdump Lsass** | `any where (process.command_line like~ ("* -ma *", "* /ma *", "* –ma *", "* —ma *", "* ―ma *") or process.command_line li…` |
| **Registry Event Cve 2021 1675 Mimikatz Printernightmare Drivers** | `any where (registry.path like~ ("*\\Control\\Print\\Environments\\Windows x64\\Drivers\\Version-3\\QMS 810\\*", "*\\Cont…` |
| **Registry Event Disable Wdigest Credential Guard** | `any where registry.path:"*\\IsCredGuardEnabled"` |
| **Registry Event Net Ntlm Downgrade** | `any where (registry.path:"*SYSTEM\\*" and registry.path:"*ControlSet*" and registry.path:"*\\Control\\Lsa*") and ((regis…` |
| **Registry Event Silentprocessexit Lsass** | `any where registry.path:"*Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe*"` |
| **Registry Event Susp Lsass Dll Load** | `any where (registry.path like~ ("*\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPt*", "*\\CurrentControlSet\\S…` |
| **Registry Set Lsass Usermode Dumping** | `any where (registry.path like~ ("*\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\DumpType*", "*\\S…` |
| **Registry Set Wdigest Enable Uselogoncredential** | `any where registry.path:"*WDigest\\UseLogonCredential" and winlog.event_data.Details:"DWORD (0x00000001)"` |
| **Asr Lsass Access** | `any where winlog.channel:"Microsoft-Windows-Windows Defender/Operational" and ((event.code:"1121" and winlog.event_data.…` |
| **Lsass Access Non System Account** | `any where winlog.channel:"Security" and (((event.code like~ ("4663", "4656")) and (winlog.event_data.AccessMask like~ ("…` |
| **Susp Lsass Dump** | `any where winlog.channel:"Security" and (event.code:"4656" and process.executable:"*\\lsass.exe" and winlog.event_data.A…` |
| **Susp Rc4 Kerberos** | `any where winlog.channel:"Security" and ((event.code:"4769" and winlog.event_data.TicketOptions:"0x40810000" and winlog.…` |
| **Ntlm Auth** | `any where winlog.channel:"Microsoft-Windows-NTLM/Operational" and event.code:"8002"` |
| **Ntlm Rdp** | `any where winlog.channel:"Microsoft-Windows-NTLM/Operational" and (event.code:"8001" and winlog.event_data.TargetName:"T…` |
| **System Lsasrv Ntlmv1** | `any where winlog.channel:"System" and (winlog.provider_name:"LsaSrv" and (event.code like~ ("6038", "6039")))` |

### Defense Evasion (60)

| Rule | What it detects |
|------|----------------|
| **Webdav Tmpfile Creation** | `any where file.path:"*\\AppData\\Local\\Temp\\TfsStore\\Tfs_DAV\\*" and (file.path like~ ("*.7z", "*.bat", "*.dat", "*.i…` |
| **Winrm Awl Bypass** | `any where (file.path like~ ("*WsmPty.xsl", "*WsmTxt.xsl")) and (not (file.path like~ ("C:\\Windows\\System32\\*", "C:\\W…` |
| **Image Load Side Load Antivirus** | `any where (file.path:"*\\log.dll" and (not ((file.path like~ ("C:\\Program Files\\Bitdefender Antivirus Free\\*", "C:\\P…` |
| **Cmd Assoc Tamper Exe File Association** | `any where ((process.executable:"*\\cmd.exe" or process.pe.original_file_name:"Cmd.Exe") and (process.command_line:"*asso…` |
| **Hktl Htran Or Natbypass** | `any where (process.executable like~ ("*\\htran.exe", "*\\lcx.exe")) or (process.command_line like~ ("*.exe -tran *", "*.…` |
| **Powershell Defender Disable Feature** | `any where ((process.command_line like~ ("*Add-MpPreference *", "*Set-MpPreference *")) and (process.command_line like~ (…` |
| **Powershell Defender Exclusion** | `any where (process.command_line like~ ("*Add-MpPreference *", "*Set-MpPreference *")) and (process.command_line like~ ("…` |
| **Powershell Disable Ie Features** | `any where (process.command_line:"* -name IEHarden *" and process.command_line:"* -value 0 *") or (process.command_line:"…` |
| **Powershell Remotefxvgpudisablement Abuse** | `any where process.command_line like~ ("*Invoke-ATHRemoteFXvGPUDisablementCommand*", "*Invoke-ATHRemoteFXvGPUDisableme*")` |
| **Pua Defendercheck** | `any where process.executable:"*\\DefenderCheck.exe" or process.pe.description:"DefenderCheck"` |
| **Reg Disable Sec Services** | `any where (process.command_line:"*reg*" and process.command_line:"*add*") and ((process.command_line:"*d 4*" and process…` |
| **Reg Lsa Disable Restricted Admin** | `any where process.command_line:"*\\System\\CurrentControlSet\\Control\\Lsa*" and process.command_line:"*DisableRestricte…` |
| **Reg Volsnap Disable** | `any where process.command_line:"*\\Services\\VSS\\Diag*" and process.command_line:"*/d Disabled*"` |
| **Reg Windows Defender Tamper** | `any where ((process.executable:"*\\reg.exe" or process.pe.original_file_name:"reg.exe") and (process.command_line like~ …` |
| **Reg Write Protect For Storage Disabled** | `any where process.command_line:"*\\System\\CurrentControlSet\\Control*" and process.command_line:"*Write Protection*" an…` |
| **Registry Office Disable Python Security Warnings** | `any where (process.command_line:"*\\Microsoft\\Office\\*" and process.command_line:"*\\Excel\\Security*" and process.com…` |
| **Rundll32 Webdav Client Execution** | `any where process.parent.executable:"*\\svchost.exe" and (process.executable:"*\\rundll32.exe" or process.pe.original_fi…` |
| **Rundll32 Webdav Client Susp Execution** | `any where (process.parent.executable:"*\\svchost.exe" and process.parent.command_line:"*-s WebClient*" and process.execu…` |
| **Susp Service Tamper** | `any where ((process.pe.original_file_name like~ ("net.exe", "net1.exe", "PowerShell_ISE.EXE", "PowerShell.EXE", "psservi…` |
| **Winrm Awl Bypass** | `any where process.command_line:"*winrm*" and ((process.command_line like~ ("*format:pretty*", "*format:\"pretty\"*", "*f…` |
| **Registry Event Bypass Via Wsreset** | `any where registry.path:"*\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command"` |
| **Registry Set Devdrv Disallow Antivirus Filter** | `any where registry.path:"*\\FilterManager\\FltmgrDevDriveAllowAntivirusFilter" and winlog.event_data.Details:"DWORD (0x0…` |
| **Registry Set Deviceguard Hypervisorenforcedcodeintegrity Disabled** | `any where (registry.path like~ ("*\\Control\\DeviceGuard\\HypervisorEnforcedCodeIntegrity", "*\\Control\\DeviceGuard\\Sc…` |
| **Registry Set Deviceguard Hypervisorenforcedpagingtranslation Disabled** | `any where registry.path:"*\\DisableHypervisorEnforcedPagingTranslation" and winlog.event_data.Details:"DWORD (0x00000001…` |
| **Registry Set Disable Defender Firewall** | `any where registry.path:"*\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\*" and registry.path:"*\\EnableFirewall"…` |
| **Registry Set Disable Function User** | `any where ((registry.path like~ ("*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisableCMD", "*SOFT…` |
| **Registry Set Disable Macroruntimescanscope** | `any where (registry.path:"*\\SOFTWARE\\*" and registry.path:"*\\Microsoft\\Office\\*" and registry.path:"*\\Common\\Secu…` |
| **Registry Set Disable Privacy Settings Experience** | `any where registry.path:"*\\SOFTWARE\\Policies\\Microsoft\\Windows\\OOBE\\DisablePrivacyExperience" and winlog.event_dat…` |
| **Registry Set Disable Security Center Notifications** | `any where registry.path:"*Windows\\CurrentVersion\\ImmersiveShell\\UseActionCenterExperience" and winlog.event_data.Deta…` |
| **Registry Set Disable System Restore** | `any where (registry.path like~ ("*\\Policies\\Microsoft\\Windows NT\\SystemRestore*", "*\\Microsoft\\Windows NT\\Current…` |
| **Registry Set Disable Windows Defender Service** | `any where registry.path:"*\\Services\\WinDefend\\Start" and winlog.event_data.Details:"DWORD (0x00000004)"` |
| **Registry Set Disabled Tamper Protection On Microsoft Defender** | `any where (registry.path:"*\\Microsoft\\Windows Defender\\Features\\TamperProtection*" and winlog.event_data.Details:"DW…` |
| **Registry Set Dot Net Etw Tamper** | `any where (registry.path:"*SOFTWARE\\Microsoft\\.NETFramework\\ETWEnabled" and winlog.event_data.Details:"DWORD (0x00000…` |
| **Registry Set Dsrm Tampering** | `any where registry.path:"*\\Control\\Lsa\\DsrmAdminLogonBehavior" and (not winlog.event_data.Details:"DWORD (0x00000000)…` |
| **Registry Set Evtx File Key Tamper** | `any where (registry.path:"*\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\*" and registry.path:"*\\File") and (not win…` |
| **Registry Set Internet Explorer Disable First Run Customize** | `any where (registry.path:"*\\Microsoft\\Internet Explorer\\Main\\DisableFirstRunCustomize" and (winlog.event_data.Detail…` |
| **Registry Set Lsa Disablerestrictedadmin** | `any where registry.path:"*System\\CurrentControlSet\\Control\\Lsa\\DisableRestrictedAdmin"` |
| **Registry Set Office Access Vbom Tamper** | `any where registry.path:"*\\Security\\AccessVBOM" and winlog.event_data.Details:"DWORD (0x00000001)"` |
| **Registry Set Office Disable Protected View Features** | `any where (registry.path:"*\\SOFTWARE\\Microsoft\\Office\\*" and registry.path:"*\\Security\\ProtectedView\\*") and ((wi…` |
| **Registry Set Office Disable Python Security Warnings** | `any where registry.path:"*\\Microsoft\\Office\\*" and registry.path:"*\\Excel\\Security\\PythonFunctionWarnings" and win…` |
| **Registry Set Office Vba Warnings Tamper** | `any where registry.path:"*\\Security\\VBAWarnings" and winlog.event_data.Details:"DWORD (0x00000001)"` |
| **Registry Set Policies Associations Tamper** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations\\*" and ((registry.path…` |
| **Registry Set Policies Attachments Tamper** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\*" and ((registry.path:…` |
| **Registry Set Rpcrt4 Etw Tamper** | `any where registry.path:"*\\Microsoft\\Windows NT\\Rpc\\ExtErrorInformation" and (winlog.event_data.Details like~ ("DWOR…` |
| **Registry Set Sentinelone Shell Context Tampering** | `any where registry.path:"*\\shell\\SentinelOneScan\\command\\*" and (not (((winlog.event_data.Details like~ ("C:\\Progra…` |
| **Registry Set Shell Context Menu Tampering** | `any where registry.path:"*\\Software\\Classes\\*" and registry.path:"*\\shell\\*" and registry.path:"*\\command\\*"` |
| **Registry Set Sophos Av Tamper** | `any where (registry.path like~ ("*\\Sophos Endpoint Defense\\TamperProtection\\Config\\SAVEnabled*", "*\\Sophos Endpoint…` |
| **Registry Set Suppress Defender Notifications** | `any where registry.path:"*SOFTWARE\\Policies\\Microsoft\\Windows Defender\\UX Configuration\\Notification_Suppress" and …` |
| **Registry Set Terminal Server Tampering** | `any where (((registry.path like~ ("*\\Control\\Terminal Server\\*", "*\\Windows NT\\Terminal Services\\*")) and registry…` |
| **Registry Set Winget Admin Settings Tampering** | `any where process.executable:"*\\winget.exe" and registry.path:"\\REGISTRY\\A\\*" and registry.path:"*\\LocalState\\admi…` |
| **Antimalware Platform Expired** | `any where winlog.channel:"Microsoft-Windows-Windows Defender/Operational" and event.code:"5101"` |
| **History Delete** | `any where winlog.channel:"Microsoft-Windows-Windows Defender/Operational" and event.code:"1013"` |
| **Malware And Pua Scan Disabled** | `any where winlog.channel:"Microsoft-Windows-Windows Defender/Operational" and event.code:"5010"` |
| **Real Time Protection Disabled** | `any where winlog.channel:"Microsoft-Windows-Windows Defender/Operational" and event.code:"5001"` |
| **Restored Quarantine File** | `any where winlog.channel:"Microsoft-Windows-Windows Defender/Operational" and event.code:"1009"` |
| **Threat** | `any where winlog.channel:"Microsoft-Windows-Windows Defender/Operational" and (event.code like~ ("1006", "1015", "1116",…` |
| **Virus Scan Disabled** | `any where winlog.channel:"Microsoft-Windows-Windows Defender/Operational" and event.code:"5012"` |
| **Mitigations Defender Load Unsigned Dll** | `any where (winlog.channel like~ ("Microsoft-Windows-Security-Mitigations/Kernel Mode", "Microsoft-Windows-Security-Mitig…` |
| **Windows Defender Exclusions Registry Modified** | `any where winlog.channel:"Security" and (event.code:"4657" and winlog.event_data.ObjectName:"*\\Microsoft\\Windows Defen…` |
| **Windows Defender Exclusions Write Access** | `any where winlog.channel:"Security" and ((winlog.event_data.AccessList like~ ("*%%4417*", "*%%4418*")) and (event.code l…` |

### Defense Evasion / Execution (43)

| Rule | What it detects |
|------|----------------|
| **Create Stream Hash File Sharing Domains Download Susp Extension** | `any where (winlog.event_data.Contents like~ ("*.githubusercontent.com*", "*anonfiles.com*", "*cdn.discordapp.com*", "*dd…` |
| **Create Stream Hash File Sharing Domains Download Unusual Extension** | `any where (winlog.event_data.Contents like~ ("*.githubusercontent.com*", "*anonfiles.com*", "*cdn.discordapp.com*", "*dd…` |
| **Create Stream Hash Zip Tld Download** | `any where winlog.event_data.Contents:"*.zip/*" and (file.path like~ ("*.bat:Zone*", "*.dat:Zone*", "*.dll:Zone*", "*.doc…` |
| **Cscript Wscript Dropper** | `any where (process.executable like~ ("*\\wscript.exe", "*\\cscript.exe")) and (file.path like~ ("C:\\Users\\*", "C:\\Pro…` |
| **Posh Pm Susp Download** | `any where winlog.event_data.ContextInfo:"*System.Net.WebClient*" and (winlog.event_data.ContextInfo like~ ("*.DownloadFi…` |
| **Apt Lace Tempest Cobalt Strike Download** | `any where process.command_line:"*-nop -w hidden -c IEX ((new-object net.webclient).downloadstring(*" and process.command…` |
| **Browsers Inline File Download** | `any where (process.executable like~ ("*\\brave.exe", "*\\chrome.exe", "*\\msedge.exe", "*\\opera.exe", "*\\vivaldi.exe")…` |
| **Certoc Download** | `any where (process.executable:"*\\certoc.exe" or process.pe.original_file_name:"CertOC.exe") and (process.command_line:"…` |
| **Certoc Download Direct Ip** | `any where (process.executable:"*\\certoc.exe" or process.pe.original_file_name:"CertOC.exe") and process.command_line:"S…` |
| **Cmd Curl Download Exec Combo** | `any where process.command_line like~ ("* -c *", "* /c *", "* –c *", "* —c *", "* ―c *") and (process.command_line:"*curl…` |
| **Cmd Type Arbitrary File Download** | `any where (process.command_line:"*type *" and process.command_line:"* > \\\\*") or (process.command_line:"*type \\\\*" a…` |
| **Cmdl32 Arbitrary File Download** | `any where (process.executable:"*\\cmdl32.exe" or process.pe.original_file_name:"CMDL32.EXE") and (process.command_line:"…` |
| **Curl Download** | `any where (process.executable:"*\\curl.exe" or process.pe.product:"The curl executable") and (process.command_line like~…` |
| **Findstr Download** | `any where (process.command_line:"*findstr*" or process.executable:"*findstr.exe" or process.pe.original_file_name:"FINDS…` |
| **Gfxdownloadwrapper Arbitrary File Download** | `any where (process.executable:"*\\GfxDownloadWrapper.exe" and (process.command_line like~ ("*http://*", "*https://*"))) …` |
| **Hktl Invoke Obfuscation Via Compress** | `any where (process.command_line:"*new-object*" and process.command_line:"*text.encoding]::ascii*") and (process.command_…` |
| **Hktl Invoke Obfuscation Via Use Clip** | `any where process.command_line:"SigmaRegularExpression(regexp=SigmaString(['(', <SpecialChars.WILDCARD_SINGLE: 2>, 'i)ec…` |
| **Imewbdld Download** | `any where (process.executable:"*\\IMEWDBLD.exe" or process.pe.original_file_name:"imewdbld.exe") and (process.command_li…` |
| **Msedge Proxy Download** | `any where (process.executable:"*\\msedge_proxy.exe" or process.pe.original_file_name:"msedge_proxy.exe") and (process.co…` |
| **Msohtmed Download** | `any where (process.executable:"*\\MSOHTMED.exe" or process.pe.original_file_name:"MsoHtmEd.exe") and (process.command_li…` |
| **Mspub Download** | `any where (process.executable:"*\\MSPUB.exe" or process.pe.original_file_name:"MSPUB.exe") and (process.command_line lik…` |
| **Nslookup Poweshell Download** | `any where (process.executable:"*\\nslookup.exe*" or process.pe.original_file_name:"\\nslookup.exe") and ((process.parent…` |
| **Powershell Base64 Encoded Cmd** | `any where ((process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) or (process.pe.original_file_name like~ ("Pow…` |
| **Powershell Base64 Encoded Cmd Patterns** | `any where (((process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) or (process.pe.original_file_name like~ ("Po…` |
| **Powershell Base64 Encoded Obfusc** | `any where process.command_line like~ ("*IAAtAGIAeABvAHIAIAAwAHgA*", "*AALQBiAHgAbwByACAAMAB4A*", "*gAC0AYgB4AG8AcgAgADAA…` |
| **Powershell Base64 Frombase64String** | `any where process.command_line like~ ("*OjpGcm9tQmFzZTY0U3RyaW5n*", "*o6RnJvbUJhc2U2NFN0cmluZ*", "*6OkZyb21CYXNlNjRTdHJp…` |
| **Powershell Base64 Iex** | `any where (process.command_line like~ ("*SUVYIChb*", "*lFWCAoW*", "*JRVggKF*") or process.command_line like~ ("*aWV4IChb…` |
| **Powershell Base64 Mppreference** | `any where (process.command_line like~ ("*QWRkLU1wUHJlZmVyZW5jZS*", "*FkZC1NcFByZWZlcmVuY2Ug*", "*BZGQtTXBQcmVmZXJlbmNlI*…` |
| **Powershell Base64 Reflection Assembly Load** | `any where process.command_line like~ ("*WwBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKA*", "*…` |
| **Powershell Base64 Reflection Assembly Load Obfusc** | `any where process.command_line like~ ("*OgA6ACgAIgBMACIAKwAiAG8AYQBkACIAKQ*", "*oAOgAoACIATAAiACsAIgBvAGEAZAAiACkA*", "*…` |
| **Powershell Download Cradle Obfuscated** | `any where process.executable:"*\\powershell.exe" and (process.command_line:"*http://127.0.0.1*" and process.command_line…` |
| **Powershell Frombase64String** | `any where process.command_line:"*::FromBase64String(*"` |
| **Powershell Obfuscation Via Utf8** | `any where process.command_line like~ ("*[char]0x*", "*(WCHAR)0x*")` |
| **Presentationhost Download** | `any where (process.executable:"*\\presentationhost.exe" or process.pe.original_file_name:"PresentationHost.exe") and (pr…` |
| **Protocolhandler Download** | `any where (process.executable:"*\\protocolhandler.exe" or process.pe.original_file_name:"ProtocolHandler.exe") and (proc…` |
| **Rundll32 Advpack Obfuscated Ordinal Call** | `any where (process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE" or process.command_line:…` |
| **Rundll32 Obfuscated Ordinal Call** | `any where (process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE" or process.command_line:…` |
| **Susp Cli Obfuscation Escape Char** | `any where process.command_line like~ ("*h^t^t^p*", "*h\"t\"t\"p*")` |
| **Susp Inline Base64 Mz Header** | `any where process.command_line like~ ("*TVqQAAMAAAAEAAAA*", "*TVpQAAIAAAAEAA8A*", "*TVqAAAEAAAAEABAA*", "*TVoAAAAAAAAAAA…` |
| **Susp Ms Appinstaller Download** | `any where process.command_line:"*ms-appinstaller://?source=*" and process.command_line:"*http*"` |
| **Appxdeployment Server Appx Downloaded From File Sharing Domains** | `any where winlog.channel:"Microsoft-Windows-AppXDeploymentServer/Operational" and (event.code:"854" and (winlog.event_da…` |
| **Invoke Obfuscation Via Use Rundll32 Services Security** | `any where winlog.channel:"Security" and (event.code:"4697" and (winlog.event_data.ServiceFileName:"*&&*" and winlog.even…` |
| **System Invoke Obfuscation Via Use Rundll32 Services** | `any where winlog.channel:"System" and (winlog.provider_name:"Service Control Manager" and event.code:"7045" and (winlog.…` |

### Discovery (18)

| Rule | What it detects |
|------|----------------|
| **Query Win Dns Server Discovery Via Ldap Query** | `any where dns.question.name:"_ldap.*" and (not ((process.executable like~ ("*:\\Program Files\\*", "*:\\Program Files (x…` |
| **Cmdkey Recon** | `any where (process.executable:"*\\cmdkey.exe" or process.pe.original_file_name:"cmdkey.exe") and process.command_line li…` |
| **Dnscmd Discovery** | `any where process.executable:"*\\dnscmd.exe" and (process.command_line like~ ("*/enumrecords*", "*/enumzones*", "*/ZoneP…` |
| **Driverquery Recon** | `any where (process.executable:"*driverquery.exe" or process.pe.original_file_name:"drvqry.exe") and ((process.parent.exe…` |
| **Findstr Password Recon** | `any where (process.executable:"*\\findstr.exe" or process.pe.original_file_name:"FINDSTR.EXE") and (process.command_line…` |
| **Findstr Recon Everyone** | `any where (((process.executable like~ ("*\\find.exe", "*\\findstr.exe")) or (process.pe.original_file_name like~ ("FIND.…` |
| **Findstr Recon Pipe Output** | `any where (process.command_line like~ ("*ipconfig*|*find*", "*net*|*find*", "*netstat*|*find*", "*ping*|*find*", "*syste…` |
| **Findstr Sysmon Discovery Via Default Altitude** | `any where ((process.executable like~ ("*\\find.exe", "*\\findstr.exe")) or (process.pe.original_file_name like~ ("FIND.E…` |
| **Hktl Sharpldapwhoami** | `any where process.executable:"*\\SharpLdapWhoami.exe" or (process.pe.original_file_name:"*SharpLdapWhoami*" or process.p…` |
| **Nltest Recon** | `any where (process.executable:"*\\nltest.exe" or process.pe.original_file_name:"nltestrk.exe") and ((process.command_lin…` |
| **Nslookup Domain Discovery** | `any where process.command_line:"*nslookup*" and process.command_line:"*_ldap._tcp.dc._msdcs.*"` |
| **Powershell Get Localgroup Member Recon** | `any where process.command_line:"*Get-LocalGroupMember *" and (process.command_line like~ ("*domain admins*", "* administ…` |
| **Susp Local System Owner Account Discovery** | `any where ((process.executable:"*\\cmd.exe" and (process.command_line:"* /c*" and process.command_line:"*dir *" and proc…` |
| **Susp Recon** | `any where ((process.executable like~ ("*\\tree.com", "*\\WMIC.exe", "*\\doskey.exe", "*\\sc.exe")) or (process.pe.origin…` |
| **Webshell Recon Commands And Processes** | `any where ((process.parent.executable like~ ("*\\w3wp.exe", "*\\php-cgi.exe", "*\\nginx.exe", "*\\httpd.exe", "*\\caddy.…` |
| **Webshell Tool Recon** | `any where ((process.parent.executable like~ ("*\\caddy.exe", "*\\httpd.exe", "*\\nginx.exe", "*\\php-cgi.exe", "*\\w3wp.…` |
| **Where Browser Data Recon** | `any where (process.executable:"*\\where.exe" or process.pe.original_file_name:"where.exe") and (process.command_line lik…` |
| **Susp Net Recon Activity** | `any where winlog.channel:"Security" and (event.code:"4661" and winlog.event_data.AccessMask:"0x2d" and (winlog.event_dat…` |

### Exfiltration (13)

| Rule | What it detects |
|------|----------------|
| **Query Win Mega Nz** | `any where dns.question.name:"*userstorage.mega.co.nz*"` |
| **Ntds Exfil Tools** | `any where file.path like~ ("*\\All.cab", "*.ntds.cleartext")` |
| **Domain Dropbox Api** | `any where (network.direction:"true" and (destination.domain like~ ("*api.dropboxapi.com", "*content.dropboxapi.com"))) a…` |
| **Domain Mega Nz** | `any where network.direction:"true" and (destination.domain like~ ("*mega.co.nz", "*mega.nz"))` |
| **Curl Fileupload** | `any where ((process.executable:"*\\curl.exe" or process.pe.product:"The curl executable") and ((process.command_line lik…` |
| **Ftp Arbitrary Command Execution** | `any where process.parent.executable:"*\\ftp.exe" or ((process.executable:"*\\ftp.exe" or process.pe.original_file_name:"…` |
| **Lolbin Sftp** | `any where process.executable:"*\\sftp.exe" and (process.command_line like~ ("* -D ..*", "* -D C:\\*"))` |
| **Powershell Email Exfil** | `any where (process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) and (process.command_line:"*Add-PSSnapin*" and…` |
| **Query Session Exfil** | `any where process.executable:"*:\\Windows\\System32\\query.exe" and (process.command_line like~ ("*session >*", "*proces…` |
| **Renamed Megasync** | `any where process.pe.original_file_name:"megasync.exe" and (not process.executable:"*\\megasync.exe")` |
| **Susp Exfil And Tunneling Tool Execution** | `any where process.executable like~ ("*\\httptunnel.exe", "*\\plink.exe", "*\\socat.exe", "*\\stunnel.exe")` |
| **Registry Set Lolbin Onedrivestandaloneupdater** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\OneDrive\\UpdateOfficeConfig\\UpdateRingSettingURLFromOC*"` |
| **Client Mega Nz** | `any where winlog.channel:"Microsoft-Windows-DNS Client Events/Operational" and (event.code:"3008" and dns.question.name:…` |

### Exploit / CVE (51)

| Rule | What it detects |
|------|----------------|
| **Driver Load Win Vuln Drivers Names** | `any where file.path like~ ("*\\panmonfltx64.sys", "*\\dbutil.sys", "*\\fairplaykd.sys", "*\\nvaudio.sys", "*\\superbmc.s…` |
| **Exploit Cve 2021 1675 Print Nightmare** | `any where process.executable:"*\\spoolsv.exe" and file.path:"*C:\\Windows\\System32\\spool\\drivers\\x64\\3\\*"` |
| **Apt Unknown Exploitation Indicators** | `any where (file.path:"*C:\\Windows\\Temp\\ScreenConnect\\*" and file.path:"*\\LB3.exe*") or (file.path like~ ("*C:\\mpyu…` |
| **Cve 2021 26858 Msexchange** | `any where process.executable:"*UMWorkerProcess.exe" and (not (file.path like~ ("*CacheCleanup.bin", "*.txt", "*.LOG", "*…` |
| **Cve 2021 31979 Cve 2021 33771 Exploits** | `any where file.path like~ ("*C:\\Windows\\system32\\physmem.sys*", "*C:\\Windows\\System32\\IME\\IMEJP\\imjpueact.dll*",…` |
| **Cve 2021 41379 Msi Lpe** | `any where process.executable:"*\\msiexec.exe" and file.path:"C:\\Program Files (x86)\\Microsoft\\Edge\\Application*" and…` |
| **Cve 2021 44077 Poc Default Files** | `any where file.path:"*\\ManageEngine\\SupportCenterPlus\\bin\\msiexec.exe"` |
| **Cve 2022 24527 Lpe** | `any where file.path:"*WindowsPowerShell\\Modules\\webAdministration\\webAdministration.psm1" and (not (user.name like~ (…` |
| **Cve 2023 27363 Foxit Rce** | `any where process.executable:"*\\FoxitPDFReader.exe" and file.path:"*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup…` |
| **Exploit Cve 2021 1675 Printspooler** | `any where file.path:"*C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\1\\123*"` |
| **Exploit Cve 2021 40444** | `any where ((process.executable:"*\\winword.exe" and file.path:"*\\Windows\\INetCache*" and file.path:"*.cab") or (proces…` |
| **Exploit Cve 2023 34362 Moveit Transfer** | `any where ((file.path like~ ("*\\MOVEit Transfer\\wwwroot\\*", "*\\MOVEitTransfer\\wwwroot\\*")) and (file.path like~ ("…` |
| **Exploit Cve 2023 36874 Report Creation** | `any where (file.path:"*:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\*" and file.path:"*\\Report.wer") and (no…` |
| **Exploit Cve 2023 36874 Wermgr Creation** | `any where file.path:"*\\wermgr.exe" and (not (file.path like~ ("*:\\$WINDOWS.~BT\\NewOS\\*", "*:\\$WinREAgent\\*", "*:\\…` |
| **Exploit Cve 2023 36884 Office Windows Html Rce File Patterns** | `any where file.path:"C:\\Users\\*" and file.path:"*\\AppData\\Roaming\\Microsoft\\Office\\Recent\\*" and file.path:"*\\f…` |
| **Exploit Cve 2024 1708 Screenconnect** | `any where (process.executable:"*\\ScreenConnect.Service.exe" and (file.path like~ ("*ScreenConnect\\App_Extensions\\*.as…` |
| **Exploit Cve 2024 1709 User Database Modification Screenconnect** | `any where file.path:"*.xml" and (file.path:"*Temp*" and file.path:"*ScreenConnect*") and process.executable:"*\\ScreenCo…` |
| **Apt Fin7 Exploitation Indicators** | `any where (process.parent.executable:"*\\notepad++.exe" and process.executable:"*\\cmd.exe") or (process.parent.executab…` |
| **Exploit Cve 2015 1641** | `any where process.parent.executable:"*\\WINWORD.EXE" and process.executable:"*\\MicroScMgmt.exe"` |
| **Exploit Cve 2017 0261** | `any where process.parent.executable:"*\\WINWORD.EXE" and process.executable:"*\\FLTLDR.exe*"` |
| **Exploit Cve 2017 11882** | `any where process.parent.executable:"*\\EQNEDT32.EXE"` |
| **Exploit Cve 2019 1378** | `any where ((process.parent.command_line:"*\\cmd.exe*" and process.parent.command_line:"*/c*" and process.parent.command_…` |
| **Exploit Cve 2019 1388** | `any where (process.parent.executable:"*\\consent.exe" and process.executable:"*\\iexplore.exe" and process.command_line:…` |
| **Exploit Cve 2020 1472 Zero Poc** | `any where (process.parent.executable:"*\\cmd.exe" and (process.executable like~ ("*\\cool.exe", "*\\zero.exe")) and (pro…` |
| **Exploit Cve 2021 44228 Vmware Horizon Log4J** | `any where process.parent.executable:"*\\ws_TomcatService.exe" and (not (process.executable like~ ("*\\cmd.exe", "*\\powe…` |
| **Exploit Cve 2022 22954 Vmware Workspace One Rce** | `any where process.parent.executable:"*\\prunsrv.exe" and (process.executable:"*\\powershell.exe" or (process.executable:…` |
| **Exploit Cve 2022 26809 Rpcss Child Process Anomaly** | `any where process.parent.executable:"C:\\Windows\\System32\\svchost.exe" and process.parent.command_line:"*-k RPCSS*"` |
| **Exploit Cve 2022 41120 Sysmon Eop** | `any where (process.parent.executable like~ ("*\\Sysmon.exe", "*\\Sysmon64.exe")) and (not ((process.executable:"C:\\User…` |
| **Exploit Cve 2023 22518 Confluence Tomcat Child Proc** | `any where ((process.parent.executable like~ ("*\\tomcat8.exe", "*\\tomcat9.exe", "*\\tomcat10.exe")) and process.parent.…` |
| **Exploit Cve 2023 36874 Fake Wermgr** | `any where (process.pe.original_file_name like~ ("Cmd.Exe", "powershell_ise.EXE", "powershell.exe")) and process.executab…` |
| **Exploit Other Bearlpe** | `any where (process.executable:"*\\schtasks.exe" or process.pe.original_file_name:"schtasks.exe") and (process.command_li…` |
| **Exploit Other Razorinstaller Lpe** | `any where (process.parent.executable:"*\\RazerInstaller.exe" and (winlog.event_data.IntegrityLevel like~ ("System", "S-1…` |
| **Exploit Other Systemnightmare** | `any where process.command_line like~ ("*printnightmare.gentilkiwi.com*", "* /user:gentilguest *", "*Kiwi Legit Printer*"…` |
| **Hwp Exploits** | `any where process.parent.executable:"*\\Hwp.exe" and process.executable:"*\\gbb.exe"` |
| **Registry Delete Exploit Guard Protected Folders** | `any where winlog.event_data.EventType:"DeleteValue" and registry.path:"*SOFTWARE\\Microsoft\\Windows Defender\\Windows D…` |
| **Registry Set Cve 2021 31979 Cve 2021 33771 Exploits** | `any where (registry.path like~ ("*CLSID\\{CF4CC405-E2C5-4DDD-B3CE-5E7582D8C9FA}\\InprocServer32\\(Default)", "*CLSID\\{7…` |
| **Registry Set Exploit Cve 2022 30190 Msdt Follina** | `any where registry.path:"HKCR\\ms-msdt\\*"` |
| **Registry Set Exploit Cve 2023 23397 Outlook Reminder Trigger** | `any where (registry.path:"*\\SOFTWARE\\Microsoft\\Office\\*" and registry.path:"*\\Outlook\\*") and (registry.path like~…` |
| **Registry Set Exploit Guard Susp Allowed Apps** | `any where registry.path:"*SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Acces…` |
| **Application Exploit Cve 2023 40477 Winrar Crash** | `any where winlog.channel:"Application" and ((winlog.provider_name:"Application Error" and event.code:"1000" and winlog.e…` |
| **Cve 2023 21554 Msmq Corrupted Packet** | `any where winlog.channel:"Application" and (winlog.provider_name:"MSMQ" and event.code:"2027" and winlog.event_data.Leve…` |
| **Exploit Cve 2023 36884 Office Windows Html Rce Share Access Pattern** | `any where winlog.channel:"Security" and (event.code:"5140" and ((winlog.event_data.ShareName:"*\\MSHTML_C7\\*" and winlo…` |
| **Exploit Cve 2024 1708 Screenconnect** | `any where winlog.channel:"Security" and ((event.code:"4663" and winlog.event_data.ObjectType:"File" and process.executab…` |
| **Exploit Cve 2024 1709 User Database Modification Screenconnect** | `any where winlog.channel:"Security" and (event.code:"4663" and winlog.event_data.ObjectType:"File" and winlog.event_data…` |
| **Samaccountname Spoofing Cve 2021 42287** | `any where winlog.channel:"Security" and ((event.code:"4781" and winlog.event_data.OldTargetUserName:"*$*") and (not winl…` |
| **System Exploit Cve 2019 0708** | `any where winlog.channel:"System" and ((event.code like~ ("56", "50")) and winlog.provider_name:"TermDD")` |
| **System Exploit Cve 2021 42278** | `any where winlog.channel:"System" and (winlog.provider_name:"Microsoft-Windows-Kerberos-Key-Distribution-Center" and (ev…` |
| **System Exploit Cve 2021 42287** | `any where winlog.channel:"System" and (winlog.provider_name:"Microsoft-Windows-Directory-Services-SAM" and (event.code l…` |
| **System Exploit Cve 2022 21919 Or Cve 2021 34484** | `any where winlog.channel:"Application" and (event.code:"1511" and winlog.provider_name:"Microsoft-Windows-User Profiles …` |
| **System Exploit Cve 2022 37966 Kdcsvc Rc4 Downgrade** | `any where winlog.channel:"System" and (event.code:"42" and (winlog.provider_name like~ ("Kerberos-Key-Distribution-Cente…` |
| **System Vul Cve 2020 1472** | `any where winlog.channel:"System" and (winlog.provider_name:"NetLogon" and event.code:"5829")` |

### Lateral Movement (33)

| Rule | What it detects |
|------|----------------|
| **Dcom Iertutil Dll Hijack** | `any where process.executable:"System" and file.path:"*\\Internet Explorer\\iertutil.dll"` |
| **Sysinternals Psexec Service** | `any where file.path:"*\\PSEXESVC.exe"` |
| **Sysinternals Psexec Service Key** | `any where file.path:"C:\\Windows\\PSEXEC-*" and file.path:"*.key"` |
| **Wmi Persistence Script Event Consumer Write** | `any where process.executable:"C:\\WINDOWS\\system32\\wbem\\scrcons.exe"` |
| **Wmiprvse Wbemcomn Dll Hijack** | `any where process.executable:"System" and file.path:"*\\wbem\\wbemcomn.dll"` |
| **Image Load Scrcons Wmi Scripteventconsumer** | `any where process.executable:"*\\scrcons.exe" and (file.path like~ ("*\\vbscript.dll", "*\\wbemdisp.dll", "*\\wshom.ocx"…` |
| **Image Load Wmi Persistence Commandline Event Consumer** | `any where process.executable:"C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" and file.path:"*\\wbemcons.dll"` |
| **Image Load Wmiprvse Wbemcomn Dll Hijack** | `any where process.executable:"*\\wmiprvse.exe" and file.path:"*\\wbem\\wbemcomn.dll"` |
| **Pipe Created Scrcons Wmi Consumer Namedpipe** | `any where process.executable:"*\\scrcons.exe"` |
| **Pipe Created Sysinternals Psexec Default Pipe** | `any where file.name:"\\PSEXESVC"` |
| **Pipe Created Sysinternals Psexec Default Pipe Susp Location** | `any where file.name:"\\PSEXESVC" and (process.executable like~ ("*:\\Users\\Public\\*", "*:\\Windows\\Temp\\*", "*\\AppD…` |
| **Hktl Impacket Lateral Movement** | `any where ((process.parent.executable like~ ("*\\wmiprvse.exe", "*\\mmc.exe", "*\\explorer.exe", "*\\services.exe")) and…` |
| **Hktl Wmiexec Default Powershell** | `any where process.command_line:"*-NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc*"` |
| **Mstsc Rdp Hijack Shadowing** | `any where process.command_line:"*noconsentprompt*" and process.command_line:"*shadow:*"` |
| **Mstsc Run Local Rdp File** | `any where ((process.executable:"*\\mstsc.exe" or process.pe.original_file_name:"mstsc.exe") and (process.command_line li…` |
| **Netsh Fw Allow Rdp** | `any where (process.executable:"*\\netsh.exe" or process.pe.original_file_name:"netsh.exe") and ((process.command_line:"*…` |
| **Sysinternals Psexec Paexec Escalate System** | `any where (process.command_line like~ ("* -s cmd*", "* /s cmd*", "* –s cmd*", "* —s cmd*", "* ―s cmd*") or process.comma…` |
| **Sysinternals Susp Psexec Paexec Flags** | `any where (process.command_line like~ ("* -s cmd*", "* /s cmd*", "* –s cmd*", "* —s cmd*", "* ―s cmd*") or process.comma…` |
| **Tscon Rdp Redirect** | `any where process.command_line:"* /dest:rdp-tcp#*"` |
| **Tscon Rdp Session Hijacking** | `any where (process.executable:"*\\tscon.exe" or process.pe.original_file_name:"tscon.exe") and (winlog.event_data.Integr…` |
| **Wmi Backdoor Exchange Transport Agent** | `any where process.parent.executable:"*\\EdgeTransport.exe" and (not (process.executable:"C:\\Windows\\System32\\conhost.…` |
| **Wmic Recon System Info** | `any where ((process.pe.description:"WMI Commandline Utility" or process.pe.original_file_name:"wmic.exe" or process.exec…` |
| **Wmic Susp Execution Via Office Process** | `any where (process.parent.executable like~ ("*\\WINWORD.EXE", "*\\EXCEL.EXE", "*\\POWERPNT.exe", "*\\MSPUB.exe", "*\\VIS…` |
| **Wmic Uninstall Security Products** | `any where ((process.command_line:"*wmic*" and process.command_line:"*product where *" and process.command_line:"*call*" …` |
| **Wmiprvse Spawning Process** | `any where process.parent.executable:"*\\WmiPrvSe.exe" and (not ((winlog.event_data.LogonId like~ ("0x3e7", "null")) or (…` |
| **Registry Set Allow Rdp Remote Assistance Feature** | `any where registry.path:"*System\\CurrentControlSet\\Control\\Terminal Server\\fAllowToGetHelp" and winlog.event_data.De…` |
| **Registry Set Bginfo Custom Wmi Query** | `any where registry.path:"*\\Software\\Winternals\\BGInfo\\UserFields\\*" and winlog.event_data.Details:"6*"` |
| **Wmi Susp Encoded Scripts** | `any where process.executable like~ ("*V3JpdGVQcm9jZXNzTWVtb3J5*", "*dyaXRlUHJvY2Vzc01lbW9ye*", "*Xcml0ZVByb2Nlc3NNZW1vcn…` |
| **Wmi Susp Scripting** | `any where (process.executable:"*new-object*" and process.executable:"*net.webclient*" and process.executable:"*.download…` |
| **Asr Psexec Wmi** | `any where winlog.channel:"Microsoft-Windows-Windows Defender/Operational" and (event.code:"1121" and (process.executable…` |
| **Not Allowed Rdp Access** | `any where winlog.channel:"Security" and event.code:"4825"` |
| **System Service Install Sysinternals Psexec** | `any where winlog.channel:"System" and ((winlog.provider_name:"Service Control Manager" and event.code:"7045") and (winlo…` |
| **Terminalservices Rdp Ngrok** | `any where winlog.channel:"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" and (event.code:"21" and w…` |

### Other (866)

| Rule | What it detects |
|------|----------------|
| **Create Remote Thread Win Keepass** | `any where winlog.event_data.TargetImage:"*\\KeePass.exe"` |
| **Create Remote Thread Win Loadlibrary** | `any where winlog.event_data.StartModule:"*\\kernel32.dll" and winlog.event_data.StartFunction:"LoadLibraryA"` |
| **Create Remote Thread Win Malware Bumblebee** | `any where (process.executable like~ ("*\\wabmig.exe", "*\\wab.exe", "*\\ImagingDevices.exe")) and winlog.event_data.Targ…` |
| **Create Remote Thread Win Mstsc Susp Location** | `any where winlog.event_data.TargetImage:"*\\mstsc.exe" and (process.executable like~ ("*:\\Temp\\*", "*:\\Users\\Public\…` |
| **Create Remote Thread Win Susp Relevant Source Image** | `any where (process.executable like~ ("*\\bash.exe", "*\\cscript.exe", "*\\cvtres.exe", "*\\defrag.exe", "*\\dialer.exe",…` |
| **Create Remote Thread Win Susp Target Shell Application** | `any where (winlog.event_data.TargetImage like~ ("*\\cmd.exe", "*\\powershell.exe", "*\\pwsh.exe")) and (not (process.exe…` |
| **Create Remote Thread Win Ttdinjec** | `any where process.executable:"*\\ttdinject.exe"` |
| **Create Stream Hash Creation Internet File** | `any where (winlog.event_data.Contents:"[ZoneTransfer] ZoneId=3*" and file.path:"*:Zone.Identifier" and (file.path like~ …` |
| **Create Stream Hash Regedit Export To Ads** | `any where process.executable:"*\\regedit.exe"` |
| **Create Stream Hash Susp Ip Domains** | `any where winlog.event_data.Contents:"SigmaRegularExpression(regexp=SigmaString(['http[s]', <SpecialChars.WILDCARD_SINGL…` |
| **Create Stream Hash Winget Susp Package Source** | `any where winlog.event_data.Contents:"[ZoneTransfer] ZoneId=3*" and (winlog.event_data.Contents like~ ("*://1*", "*://2*…` |
| **Query Win Anonymfiles Com** | `any where dns.question.name:"*.anonfiles.com*"` |
| **Query Win Appinstaller** | `any where process.executable:"C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_*" and process.executable:"*…` |
| **Query Win Cloudflared Communication** | `any where dns.question.name like~ ("*.v2.argotunnel.com", "*protocol-v2.argotunnel.com", "*trycloudflare.com", "*update.…` |
| **Query Win Devtunnels Communication** | `any where dns.question.name:"*.devtunnels.ms"` |
| **Query Win Hybridconnectionmgr Servicebus** | `any where dns.question.name:"*servicebus.windows.net*" and process.executable:"*HybridConnectionManager*"` |
| **Query Win Malware 3Cx Compromise** | `any where dns.question.name like~ ("*akamaicontainer.com*", "*akamaitechcloudservices.com*", "*azuredeploystore.com*", "…` |
| **Query Win Onelaunch Update Service** | `any where dns.question.name:"update.onelaunch.com" and process.executable:"*\\OneLaunch.exe"` |
| **Query Win Regsvr32 Dns Query** | `any where process.executable:"*\\regsvr32.exe"` |
| **Query Win Teamviewer Domain Query By Uncommon App** | `any where (dns.question.name like~ ("taf.teamviewer.com", "udp.ping.teamviewer.com")) and (not process.executable:"*Team…` |
| **Query Win Tor Onion Domain Query** | `any where dns.question.name like~ ("*.hiddenservice.net", "*.onion.ca", "*.onion.cab", "*.onion.casa", "*.onion.city", "…` |
| **Query Win Ufile Io Query** | `any where dns.question.name:"*ufile.io*"` |
| **Query Win Vscode Tunnel Communication** | `any where dns.question.name:"*.tunnels.api.visualstudio.com"` |
| **Susp Credhist** | `any where file.path:"*\\Microsoft\\Protect\\CREDHIST" and (not ((process.executable like~ ("C:\\Program Files\\*", "C:\\…` |
| **Susp Crypto Currency Wallets** | `any where ((file.path like~ ("*\\AppData\\Roaming\\Ethereum\\keystore\\*", "*\\AppData\\Roaming\\EthereumClassic\\keysto…` |
| **Susp Dpapi Master Key Access** | `any where (file.path like~ ("*\\Microsoft\\Protect\\S-1-5-18\\*", "*\\Microsoft\\Protect\\S-1-5-21-*")) and (not (proces…` |
| **Susp Reg And Hive** | `any where (file.path like~ ("*.hive", "*.reg")) and (not (process.executable like~ ("C:\\Program Files (x86)\\*", "C:\\P…` |
| **Susp Unattend Xml** | `any where file.path:"*\\Panther\\unattend.xml"` |
| **Delete Backup File** | `any where (process.executable like~ ("*\\cmd.exe", "*\\powershell.exe", "*\\pwsh.exe", "*\\wt.exe", "*\\rundll32.exe", "…` |
| **Delete Event Log Files** | `any where file.path:"C:\\Windows\\System32\\winevt\\Logs\\*" and file.path:"*.evtx"` |
| **Delete Iis Access Logs** | `any where file.path:"*\\inetpub\\logs\\LogFiles\\*" and file.path:"*.log"` |
| **Delete Own Image** | `any where file.path:"SigmaFieldReference(field='process.executable', starts_with=False, ends_with=False)"` |
| **Delete Prefetch** | `any where (file.path:"*:\\Windows\\Prefetch\\*" and file.path:"*.pf") and (not (process.executable:"*:\\windows\\system3…` |
| **Delete Teamviewer Logs** | `any where (file.path:"*\\TeamViewer_*" and file.path:"*.log") and (not process.executable:"C:\\Windows\\system32\\svchos…` |
| **Delete Tomcat Logs** | `any where (file.path:"*\\Tomcat*" and file.path:"*\\logs\\*") and (file.path like~ ("*catalina.*", "*_access_log.*", "*l…` |
| **Zone Identifier Ads** | `any where file.path:"*:Zone.Identifier"` |
| **Zone Identifier Ads Uncommon** | `any where file.path:"*:Zone.Identifier" and (not (process.executable like~ ("C:\\Program Files\\PowerShell\\7-preview\\p…` |
| **Advanced Ip Scanner** | `any where file.path:"*\\AppData\\Local\\Temp\\Advanced IP Scanner 2*"` |
| **Anydesk Artefact** | `any where file.path like~ ("*\\AppData\\Roaming\\AnyDesk\\user.conf*", "*\\AppData\\Roaming\\AnyDesk\\system.conf*")` |
| **Anydesk Writing Susp Binaries** | `any where ((process.executable like~ ("*\\AnyDesk.exe", "*\\AnyDeskMSI.exe")) and (file.path like~ ("*.dll", "*.exe"))) …` |
| **Aspnet Temp Files** | `any where process.executable:"*\\aspnet_compiler.exe" and (file.path:"*\\Temporary ASP.NET Files\\*" and file.path:"*\\a…` |
| **Bloodhound Collection** | `any where (file.path like~ ("*BloodHound.zip", "*_computers.json", "*_containers.json", "*_gpos.json", "*_groups.json", …` |
| **Create Evtx Non Common Locations** | `any where file.path:"*.evtx" and (not (file.path:"C:\\Windows\\System32\\winevt\\Logs\\*" or (file.path:"C:\\ProgramData…` |
| **Creation Scr Binary File** | `any where file.path:"*.scr" and (not ((process.executable like~ ("*\\Kindle.exe", "*\\Bin\\ccSvcHst.exe")) or (process.e…` |
| **Creation System Dll Files** | `any where (file.path like~ ("*\\secur32.dll", "*\\tdh.dll")) and (not (file.path like~ ("*C:\\$WINDOWS.~BT\\*", "*C:\\$W…` |
| **Cred Dump Tools Dropped Files** | `any where (file.path like~ ("*\\fgdump-log*", "*\\kirbi*", "*\\pwdump*", "*\\pwhashes*", "*\\wce_ccache*", "*\\wce_krbtk…` |
| **Csexec Service** | `any where file.path:"*\\csexecsvc.exe"` |
| **Csharp Compile Artefact** | `any where file.path:"*.cmdline"` |
| **Dll Sideloading Space Path** | `any where (file.path like~ ("C:\\Windows \\*", "C:\\Program Files \\*", "C:\\Program Files (x86) \\*")) and file.path:"*…` |
| **Exchange Webshell Drop** | `any where (process.executable:"*\\w3wp.exe" and winlog.event_data.CommandLine:"*MSExchange*" and (file.path like~ ("*Fro…` |
| **Hktl Crackmapexec Indicators** | `any where file.path:"C:\\Windows\\Temp\\*" and ((file.path like~ ("*\\temp.ps1", "*\\msol.ps1")) or (file.path like~ ("S…` |
| **Hktl Dumpert** | `any where file.path:"*dumpert.dmp"` |
| **Hktl Hivenightmare File Exports** | `any where (file.path like~ ("*\\hive_sam_*", "*\\SAM-2021-*", "*\\SAM-2022-*", "*\\SAM-2023-*", "*\\SAM-haxx*", "*\\Sam.…` |
| **Hktl Inveigh Artefacts** | `any where file.path like~ ("*\\Inveigh-Log.txt", "*\\Inveigh-Cleartext.txt", "*\\Inveigh-NTLMv1Users.txt", "*\\Inveigh-N…` |
| **Hktl Krbrelay Remote Ioc** | `any where file.path like~ ("*:\\windows\\temp\\sam.tmp", "*:\\windows\\temp\\sec.tmp", "*:\\windows\\temp\\sys.tmp")` |
| **Hktl Nppspy** | `any where file.path like~ ("*\\NPPSpy.txt", "*\\NPPSpy.dll")` |
| **Hktl Powerup Dllhijacking** | `any where (process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) and file.path:"*.bat"` |
| **Hktl Quarkspw Filedump** | `any where file.path:"*\\AppData\\Local\\Temp\\SAM-*" and file.path:"*.dmp*"` |
| **Hktl Remote Cred Dump** | `any where process.executable:"*\\svchost.exe" and file.path:"SigmaRegularExpression(regexp=SigmaString(['\\\\Windows\\\\…` |
| **Hktl Safetykatz** | `any where file.path:"*\\Temp\\debug.bin"` |
| **Install Teamviewer Desktop** | `any where file.path:"*\\TeamViewer_Desktop.exe"` |
| **Iphlpapi Dll Sideloading** | `any where file.path:"*iphlpapi.dll*" and file.path:"*\\AppData\\Local\\Microsoft*"` |
| **Iso File Mount** | `any where ((file.path:"*\\AppData\\Local\\Temp\\*" and file.path:"*.zip\\*") and file.path:"*.iso") or (file.path:"*\\Ap…` |
| **Iso File Recent** | `any where (file.path like~ ("*.iso.lnk", "*.img.lnk", "*.vhd.lnk", "*.vhdx.lnk")) and file.path:"*\\Microsoft\\Windows\\…` |
| **Mal Adwind** | `any where (file.path:"*\\AppData\\Roaming\\Oracle\\bin\\java*" and file.path:"*.exe*") or (file.path:"*\\Retrive*" and f…` |
| **Mal Octopus Scanner** | `any where file.path like~ ("*\\AppData\\Local\\Microsoft\\Cache134.dat", "*\\AppData\\Local\\Microsoft\\ExplorerSync.db"…` |
| **Malware Coldsteel Renamed Cmd** | `any where file.path:"C:\\users\\public\\Documents\\dllhost.exe"` |
| **Malware Darkgate Autoit3 Save Temp** | `any where (file.path:"*:\\temp\\*" and (file.path like~ ("*.au3", "*\\autoit3.exe"))) or (process.executable:"*:\\temp\\…` |
| **Malware Devil Bait Script Drop** | `any where (process.executable like~ ("*\\schtasks.exe", "*\\wscript.exe", "*\\mshta.exe")) and file.path:"*\\AppData\\Ro…` |
| **Malware Goofy Guineapig File Indicators** | `any where file.path like~ ("C:\\ProgramData\\GoogleUpdate\\config.dat", "C:\\ProgramData\\GoogleUpdate\\GoogleUpdate.exe…` |
| **Malware Kapeka Backdoor Indicators** | `any where ((file.path like~ ("*:\\ProgramData\\*", "*\\AppData\\Local\\*")) and file.path:"SigmaRegularExpression(regexp…` |
| **Malware Pingback Backdoor** | `any where process.executable:"*updata.exe" and file.path:"C:\\Windows\\oci.dll"` |
| **Malware Small Sieve Evasion Typo** | `any where (((file.path:"*:\\Users\\*" and file.path:"*\\AppData\\*") and (file.path like~ ("*\\Roaming\\*", "*\\Local\\*…` |
| **Malware Snake Installers Ioc** | `any where file.path like~ ("*\\jpsetup.exe", "*\\jpinst.exe")` |
| **Malware Snake Werfault Creation** | `any where (file.path:"C:\\Windows\\WinSxS\\*" and file.path:"*\\WerFault.exe") and (not (process.executable like~ ("C:\\…` |
| **Moriya Rootkit** | `any where file.path:"C:\\Windows\\System32\\drivers\\MoriyaStreamWatchmen.sys"` |
| **Msdt Susp Directories** | `any where process.executable:"*\\msdt.exe" and (file.path like~ ("*\\Desktop\\*", "*\\Start Menu\\Programs\\Startup\\*",…` |
| **New Files In Uncommon Appdata Folder** | `any where (file.path:"C:\\Users\\*" and file.path:"*\\AppData\\*" and (file.path like~ ("*.bat", "*.cmd", "*.cpl", "*.dl…` |
| **Ntds Dit Creation** | `any where file.path:"*ntds.dit"` |
| **Office Macro Files Created** | `any where file.path like~ ("*.docm", "*.dotm", "*.xlsm", "*.xltm", "*.potm", "*.pptm")` |
| **Office Macro Files From Susp Process** | `any where ((process.executable like~ ("*\\cscript.exe", "*\\mshta.exe", "*\\regsvr32.exe", "*\\rundll32.exe", "*\\wscrip…` |
| **Office Onenote Files In Susp Locations** | `any where ((file.path like~ ("*\\AppData\\Local\\Temp\\*", "*\\Users\\Public\\*", "*\\Windows\\Temp\\*", "*:\\Temp\\*"))…` |
| **Office Onenote Susp Dropped Files** | `any where (process.executable like~ ("*\\onenote.exe", "*\\onenotem.exe", "*\\onenoteim.exe")) and file.path:"*\\AppData…` |
| **Office Outlook Newform** | `any where process.executable:"*\\outlook.exe" and (file.path like~ ("*\\AppData\\Local\\Microsoft\\FORMS\\IPM*", "*\\Loc…` |
| **Office Publisher Files In Susp Locations** | `any where (file.path like~ ("*\\AppData\\Local\\Temp\\*", "*\\Users\\Public\\*", "*\\Windows\\Temp\\*", "*C:\\Temp\\*"))…` |
| **Office Susp File Extension** | `any where ((process.executable like~ ("*\\excel.exe", "*\\msaccess.exe", "*\\mspub.exe", "*\\powerpnt.exe", "*\\visio.ex…` |
| **Perflogs Susp Files** | `any where file.path:"C:\\PerfLogs\\*" and (file.path like~ ("*.7z", "*.bat", "*.bin", "*.chm", "*.dll", "*.exe", "*.hta"…` |
| **Ps Script Policy Test Creation By Uncommon Process** | `any where file.path:"*__PSScriptPolicyTest_*" and (not ((process.executable like~ ("C:\\Program Files\\PowerShell\\7-pre…` |
| **Redmimicry Winnti Filedrop** | `any where file.path like~ ("*\\gthread-3.6.dll", "*\\sigcmm-2.4.dll", "*\\Windows\\Temp\\tmp.bat")` |
| **Regedit Print As Pdf** | `any where process.executable:"*\\regedit.exe" and file.path:"*.pdf"` |
| **Remcom Service** | `any where file.path:"*\\RemComSvc.exe"` |
| **Remote Access Tools Screenconnect Artefact** | `any where file.path:"*\\Bin\\ScreenConnect.*"` |
| **Ripzip Attack** | `any where (file.path:"*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup*" and file.path:"*.lnk.{0AFACED1-E828-11D1-91…` |
| **Sam Dump** | `any where (file.path like~ ("*\\Temp\\sam", "*\\sam.sav", "*\\Intel\\sam", "*\\sam.hive", "*\\Perflogs\\sam", "*\\Progra…` |
| **Shell Write Susp Files Extensions** | `any where (((process.executable like~ ("*\\csrss.exe", "*\\lsass.exe", "*\\RuntimeBroker.exe", "*\\sihost.exe", "*\\smss…` |
| **Susp Colorcpl** | `any where process.executable:"*\\colorcpl.exe" and (not (file.path like~ ("*.icm", "*.gmmp", "*.cdmp", "*.camp")))` |
| **Susp Default Gpo Dir Write** | `any where file.path:"*\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\*" and (file.path like~ ("*.dll", "*.exe"))` |
| **Susp Desktop Txt** | `any where process.executable:"*\\cmd.exe" and (file.path:"*\\Users\\*" and file.path:"*\\Desktop\\*") and file.path:"*.t…` |
| **Susp Diagcab** | `any where file.path:"*.diagcab"` |
| **Susp Double Extension** | `any where (((file.path like~ ("*.exe", "*.iso", "*.rar", "*.svg", "*.zip")) and (file.path like~ ("*.doc.*", "*.docx.*",…` |
| **Susp Dpapi Backup And Cert Export Ioc** | `any where (file.path like~ ("*ntds_capi_*", "*ntds_legacy_*", "*ntds_unknown_*")) and (file.path like~ ("*.cer", "*.key"…` |
| **Susp Exchange Aspx Write** | `any where process.executable:"*\\MSExchangeMailboxReplication.exe" and (file.path like~ ("*.aspx", "*.asp"))` |
| **Susp Executable Creation** | `any where file.path like~ ("*:\\$Recycle.Bin.exe", "*:\\Documents and Settings.exe", "*:\\MSOCache.exe", "*:\\PerfLogs.e…` |
| **Susp Get Variable** | `any where file.path:"*Local\\Microsoft\\WindowsApps\\Get-Variable.exe"` |
| **Susp Hidden Dir Index Allocation** | `any where file.path:"*::$index_allocation*"` |
| **Susp Legitimate App Dropping Archive** | `any where (process.executable like~ ("*\\winword.exe", "*\\excel.exe", "*\\powerpnt.exe", "*\\msaccess.exe", "*\\mspub.e…` |
| **Susp Right To Left Override Extension Spoofing** | `any where (file.path like~ ("*\\u202e*", "*[U+202E]*", "*‮*")) and (file.path like~ ("*3pm.*", "*4pm.*", "*cod.*", "*fdp…` |
| **Susp Spool Drivers Color Drop** | `any where file.path:"C:\\Windows\\System32\\spool\\drivers\\color\\*" and (file.path like~ ("*.dll", "*.exe", "*.sys"))` |
| **Susp Task Write** | `any where file.path:"*\\Windows\\System32\\Tasks*" and (process.executable like~ ("*\\AppData\\*", "*C:\\PerfLogs*", "*\…` |
| **Susp Windows Terminal Profile** | `any where (process.executable like~ ("*\\cmd.exe", "*\\cscript.exe", "*\\mshta.exe", "*\\powershell.exe", "*\\pwsh.exe",…` |
| **Susp Winsxs Binary Creation** | `any where (file.path:"C:\\Windows\\WinSxS\\*" and file.path:"*.exe") and (not (process.executable like~ ("C:\\Windows\\S…` |
| **Sysinternals Livekd Default Dump Name** | `any where file.path:"C:\\Windows\\livekd.dmp"` |
| **Sysinternals Livekd Driver** | `any where file.path:"C:\\Windows\\System32\\drivers\\LiveKdD.SYS" and (process.executable like~ ("*\\livekd.exe", "*\\li…` |
| **Sysinternals Livekd Driver Susp Creation** | `any where file.path:"C:\\Windows\\System32\\drivers\\LiveKdD.SYS" and (not (process.executable like~ ("*\\livekd.exe", "…` |
| **Sysinternals Procexp Driver Susp Creation** | `any where (file.path:"*\\PROCEXP*" and file.path:"*.sys") and (not (process.executable like~ ("*\\procexp.exe", "*\\proc…` |
| **Vscode Tunnel Indicators** | `any where file.path:"*\\code_tunnel.json"` |
| **Vscode Tunnel Remote Creation Artefacts** | `any where process.executable:"*\\servers\\Stable-*" and process.executable:"*\\server\\node.exe" and file.path:"*\\.vsco…` |
| **Webshell Creation Detect** | `any where ((file.path:"*\\inetpub\\wwwroot\\*" and (file.path like~ ("*.ashx*", "*.asp*", "*.ph*", "*.soap*"))) or ((fil…` |
| **Werfault Dll Hijacking** | `any where (file.path like~ ("*\\WerFault.exe", "*\\wer.dll")) and (not (file.path like~ ("C:\\Windows\\SoftwareDistribut…` |
| **Writing Local Admin Share** | `any where file.path:"*\\\\127.0.0*" and file.path:"*\\ADMIN$\\*"` |
| **File Executable Detected Win Susp Embeded Sed File** | `any where file.path:"*.sed"` |
| **Image Load Dll Amsi Suspicious Process** | `any where file.path:"*\\amsi.dll" and (process.executable like~ ("*\\ExtExport.exe", "*\\odbcconf.exe", "*\\rundll32.exe…` |
| **Image Load Dll Amsi Uncommon Process** | `any where file.path:"*\\amsi.dll" and (not ((process.executable like~ ("*:\\Windows\\explorer.exe", "*:\\Windows\\Sysmon…` |
| **Image Load Dll Credui Uncommon Process Load** | `any where ((file.path like~ ("*\\credui.dll", "*\\wincredui.dll")) or (file.pe.original_file_name like~ ("credui.dll", "…` |
| **Image Load Dll Rstrtmgr Uncommon Load** | `any where (file.path:"*\\RstrtMgr.dll" or file.pe.original_file_name:"RstrtMgr.dll") and (not ((process.executable like~…` |
| **Image Load Dll System Drawing Load** | `any where file.path:"*\\System.Drawing.ni.dll"` |
| **Image Load Dll System Management Automation Susp Load** | `any where (file.pe.description:"System.Management.Automation" or file.pe.original_file_name:"System.Management.Automatio…` |
| **Image Load Dll Taskschd By Process In Potentially Suspicious Location** | `any where (file.path:"*\\taskschd.dll" or file.pe.original_file_name:"taskschd.dll") and (process.executable like~ ("*:\…` |
| **Image Load Dll Tttracer Module Load** | `any where file.path like~ ("*\\ttdrecord.dll", "*\\ttdwriter.dll", "*\\ttdloader.dll")` |
| **Image Load Dll Vss Ps Susp Load** | `any where file.path:"*\\vss_ps.dll" and (not ((process.executable:"C:\\Windows\\*" and (process.executable like~ ("*\\cl…` |
| **Image Load Hktl Silenttrinity Stager** | `any where file.pe.description:"*st2stager*"` |
| **Image Load Malware Csharp Streamer Dotnet Load** | `any where file.path:"SigmaRegularExpression(regexp=SigmaString(['\\\\AppData\\\\Local\\\\Temp\\\\dat[0-9A-Z]{4}\\.tmp'])…` |
| **Image Load Malware Foggyweb Nobelium** | `any where file.path:"C:\\Windows\\ADFS\\version.dll"` |
| **Image Load Malware Kapeka Backdoor Wll** | `any where process.executable:"*\\rundll32.exe" and (file.path like~ ("*:\\ProgramData*", "*\\AppData\\Local\\*")) and fi…` |
| **Image Load Malware Pingback Backdoor** | `any where process.executable:"*\\msdtc.exe" and file.path:"C:\\Windows\\oci.dll"` |
| **Image Load Office Excel Xll Load** | `any where process.executable:"*\\excel.exe" and file.path:"*.xll"` |
| **Image Load Office Excel Xll Susp Load** | `any where process.executable:"*\\excel.exe" and (file.path like~ ("*\\Desktop\\*", "*\\Downloads\\*", "*\\Perflogs\\*", …` |
| **Image Load Office Outlook Outlvba Load** | `any where process.executable:"*\\outlook.exe" and file.path:"*\\outlvba.dll"` |
| **Image Load Office Word Wll Load** | `any where process.executable:"*\\winword.exe" and file.path:"*.wll"` |
| **Image Load Rundll32 Remote Share Load** | `any where process.executable:"*\\rundll32.exe" and file.path:"\\\\*"` |
| **Image Load Side Load Abused Dlls Susp Paths** | `any where (file.path like~ ("*\\coreclr.dll", "*\\facesdk.dll", "*\\HPCustPartUI.dll", "*\\libcef.dll", "*\\ZIPDLL.dll")…` |
| **Image Load Side Load Appverifui** | `any where file.path:"*\\appverifUI.dll" and (not ((process.executable like~ ("C:\\Windows\\SysWOW64\\appverif.exe", "C:\…` |
| **Image Load Side Load Aruba Networks Virtual Intranet Access** | `any where (process.executable:"*\\arubanetsvc.exe" and (file.path like~ ("*\\wtsapi32.dll", "*\\msvcr100.dll", "*\\msvcp…` |
| **Image Load Side Load Avkkid** | `any where file.path:"*\\AVKkid.dll" and (not ((process.executable like~ ("*C:\\Program Files (x86)\\G DATA\\*", "*C:\\Pr…` |
| **Image Load Side Load Ccleaner Reactivator** | `any where file.path:"*\\CCleanerReactivator.dll" and (not ((process.executable like~ ("C:\\Program Files\\CCleaner\\*", …` |
| **Image Load Side Load Chrome Frame Helper** | `any where file.path:"*\\chrome_frame_helper.dll" and (not (file.path like~ ("C:\\Program Files\\Google\\Chrome\\Applicat…` |
| **Image Load Side Load Classicexplorer32** | `any where file.path:"*\\ClassicExplorer32.dll" and (not file.path:"C:\\Program Files\\Classic Shell\\*")` |
| **Image Load Side Load Comctl32** | `any where (file.path like~ ("C:\\Windows\\System32\\logonUI.exe.local\\*", "C:\\Windows\\System32\\werFault.exe.local\\*…` |
| **Image Load Side Load Coregen** | `any where process.executable:"*\\coregen.exe" and (not (file.path like~ ("C:\\Program Files (x86)\\Microsoft Silverlight…` |
| **Image Load Side Load Dbgcore** | `any where file.path:"*\\dbgcore.dll" and (not (file.path like~ ("C:\\Program Files (x86)\\*", "C:\\Program Files\\*", "C…` |
| **Image Load Side Load Dbghelp** | `any where file.path:"*\\dbghelp.dll" and (not (file.path like~ ("C:\\Program Files (x86)\\*", "C:\\Program Files\\*", "C…` |
| **Image Load Side Load Dbgmodel** | `any where file.path:"*\\dbgmodel.dll" and (not (file.path like~ ("C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*",…` |
| **Image Load Side Load Eacore** | `any where file.path:"*\\EACore.dll" and (not ((process.executable:"*C:\\Program Files\\Electronic Arts\\EA Desktop\\*" a…` |
| **Image Load Side Load Edputil** | `any where file.path:"*\\edputil.dll" and (not (file.path like~ ("C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*", …` |
| **Image Load Side Load Goopdate** | `any where file.path:"*\\goopdate.dll" and (not (file.path like~ ("C:\\Program Files (x86)\\*", "C:\\Program Files\\*")))…` |
| **Image Load Side Load Gup Libcurl** | `any where (process.executable:"*\\gup.exe" and file.path:"*\\libcurl.dll") and (not process.executable:"*\\Notepad++\\up…` |
| **Image Load Side Load Iviewers** | `any where file.path:"*\\iviewers.dll" and (not (file.path like~ ("C:\\Program Files (x86)\\Windows Kits\\*", "C:\\Progra…` |
| **Image Load Side Load Jsschhlp** | `any where file.path:"*\\JSESPR.dll" and (not file.path:"C:\\Program Files\\Common Files\\Justsystem\\JsSchHlp\\*")` |
| **Image Load Side Load Libvlc** | `any where file.path:"*\\libvlc.dll" and (not (file.path like~ ("C:\\Program Files (x86)\\VideoLAN\\VLC\\*", "C:\\Program…` |
| **Image Load Side Load Mfdetours** | `any where file.path:"*\\mfdetours.dll" and (not file.path:"*:\\Program Files (x86)\\Windows Kits\\10\\bin\\*")` |
| **Image Load Side Load Mfdetours Unsigned** | `any where file.path:"*\\mfdetours.dll" and (not (file.path:"*:\\Program Files (x86)\\Windows Kits\\10\\bin\\*" and file.…` |
| **Image Load Side Load Mpsvc** | `any where file.path:"*\\MpSvc.dll" and (not (file.path like~ ("C:\\Program Files\\Windows Defender\\*", "C:\\ProgramData…` |
| **Image Load Side Load Mscorsvc** | `any where file.path:"*\\mscorsvc.dll" and (not (file.path like~ ("C:\\Windows\\Microsoft.NET\\Framework\\*", "C:\\Window…` |
| **Image Load Side Load Rcdll** | `any where file.path:"*\\rcdll.dll" and (not (file.path like~ ("C:\\Program Files (x86)\\Microsoft Visual Studio\\*", "C:…` |
| **Image Load Side Load Rjvplatform Default Location** | `any where process.executable:"C:\\Windows\\System32\\SystemResetPlatform\\SystemResetPlatform.exe" and file.path:"C:\\$S…` |
| **Image Load Side Load Rjvplatform Non Default Location** | `any where (file.path:"*\\RjvPlatform.dll" and process.executable:"\\SystemResetPlatform.exe") and (not process.executabl…` |
| **Image Load Side Load Robform** | `any where (file.path like~ ("*\\roboform.dll", "*\\roboform-x64.dll")) and (not ((process.executable like~ (" C:\\Progra…` |
| **Image Load Side Load Shell Chrome Api** | `any where file.path:"*\\ShellChromeAPI.dll"` |
| **Image Load Side Load Shelldispatch** | `any where file.path:"*\\ShellDispatch.dll" and (not ((file.path:"*:\\Users\\*" and file.path:"*\\AppData\\Local\\Temp\\*…` |
| **Image Load Side Load Smadhook** | `any where (file.path like~ ("*\\SmadHook32c.dll", "*\\SmadHook64c.dll")) and (not ((process.executable like~ ("C:\\Progr…` |
| **Image Load Side Load Solidpdfcreator** | `any where file.path:"*\\SolidPDFCreator.dll" and (not (process.executable:"*\\SolidPDFCreator.exe" and (file.path like~ …` |
| **Image Load Side Load Third Party** | `any where (file.path:"*\\commfunc.dll" and (not (file.path:"*\\AppData\\local\\Google\\Chrome\\Application\\*" or (file.…` |
| **Image Load Side Load Ualapi** | `any where (process.executable:"*\\fxssvc.exe" and file.path:"*ualapi.dll") and (not file.path:"C:\\Windows\\WinSxS\\*")` |
| **Image Load Side Load Vmware Xfer** | `any where (process.executable:"*\\VMwareXferlogs.exe" and file.path:"*\\glib-2.0.dll") and (not file.path:"C:\\Program F…` |
| **Image Load Side Load Waveedit** | `any where file.path:"*\\waveedit.dll" and (not ((process.executable like~ ("C:\\Program Files (x86)\\Nero\\Nero Apps\\Ne…` |
| **Image Load Side Load Wazuh** | `any where (file.path like~ ("*\\libwazuhshared.dll", "*\\libwinpthread-1.dll")) and (not (file.path like~ ("C:\\Program …` |
| **Image Load Side Load Wwlib** | `any where file.path:"*\\wwlib.dll" and (not ((process.executable like~ ("C:\\Program Files (x86)\\Microsoft Office\\*", …` |
| **Image Load Usp Svchost Clfsw32** | `any where process.executable:"*\\svchost.exe" and file.path:"*\\clfsw32.dll"` |
| **Addinutil Initiated** | `any where network.direction:"true" and process.executable:"*\\addinutil.exe"` |
| **Cmstp Initiated Connection** | `any where (process.executable:"*\\cmstp.exe" and network.direction:"true") and (not (cidrMatch(destination.ip, "127.0.0.…` |
| **Dfsvc Non Local Ip** | `any where (process.executable:"*\\dfsvc.exe" and network.direction:"true") and (not (cidrMatch(destination.ip, "127.0.0.…` |
| **Dialer Initiated Connection** | `any where (process.executable:"*:\\Windows\\System32\\dialer.exe" and network.direction:"true") and (not (cidrMatch(dest…` |
| **Dllhost Non Local Ip** | `any where (process.executable:"*\\dllhost.exe" and network.direction:"true") and (not ((cidrMatch(destination.ip, "::1/1…` |
| **Domain Btunnels** | `any where network.direction:"true" and destination.domain:"*.btunnel.co.in"` |
| **Domain Cloudflared Communication** | `any where network.direction:"true" and (destination.domain like~ ("*.v2.argotunnel.com", "*protocol-v2.argotunnel.com", …` |
| **Domain Crypto Mining Pools** | `any where destination.domain like~ ("alimabi.cn", "ap.luckpool.net", "bcn.pool.minergate.com", "bcn.vip.pool.minergate.c…` |
| **Domain Devtunnels** | `any where network.direction:"true" and destination.domain:"*.devtunnels.ms"` |
| **Domain Localtonet Tunnel** | `any where (destination.domain like~ ("*.localto.net", "*.localtonet.com")) and network.direction:"true"` |
| **Domain Ngrok** | `any where network.direction:"true" and (destination.domain like~ ("*.ngrok-free.app", "*.ngrok-free.dev", "*.ngrok.app",…` |
| **Domain Ngrok Tunnel** | `any where destination.domain like~ ("*tunnel.us.ngrok.com*", "*tunnel.eu.ngrok.com*", "*tunnel.ap.ngrok.com*", "*tunnel.…` |
| **Domain Portmap** | `any where network.direction:"true" and destination.domain:"*.portmap.io"` |
| **Domain Vscode Tunnel Connection** | `any where network.direction:"true" and destination.domain:"*.tunnels.api.visualstudio.com"` |
| **Eqnedt** | `any where process.executable:"*\\eqnedt32.exe"` |
| **Imewdbld** | `any where network.direction:"true" and process.executable:"*\\IMEWDBLD.exe"` |
| **Regasm Network Activity** | `any where (network.direction:"true" and process.executable:"*\\regasm.exe") and (not (cidrMatch(destination.ip, "127.0.0…` |
| **Regsvr32 Network Activity** | `any where network.direction:"true" and process.executable:"*\\regsvr32.exe"` |
| **Susp Azurefd Connection** | `any where destination.domain:"*azurefd.net*" and (not ((process.executable like~ ("*brave.exe", "*chrome.exe", "*chromiu…` |
| **Susp Binary No Cmdline** | `any where (network.direction:"true" and (process.executable like~ ("*\\regsvr32.exe", "*\\rundll32.exe", "*\\dllhost.exe…` |
| **Winlogon Net Connections** | `any where (process.executable:"*\\winlogon.exe" and network.direction:"true") and (not (cidrMatch(destination.ip, "127.0…` |
| **Wscript Cscript Local Connection** | `any where network.direction:"true" and (process.executable like~ ("*\\wscript.exe", "*\\cscript.exe")) and (cidrMatch(de…` |
| **Wscript Cscript Outbound Connection** | `any where (network.direction:"true" and (process.executable like~ ("*\\wscript.exe", "*\\cscript.exe"))) and (not ((cidr…` |
| **Net Dns External Service Interaction Domains** | `any where (query like~ ("*.burpcollaborator.net", "*.canarytokens.com", "*.ceye.io", "*.ddns.1443.eu.org", "*.ddns.bypas…` |
| **Net Dns Pua Cryptocoin Mining Xmr** | `any where query like~ ("*pool.minexmr.com*", "*fr.minexmr.com*", "*de.minexmr.com*", "*sg.minexmr.com*", "*ca.minexmr.co…` |
| **Net Dns Susp B64 Queries** | `any where query:"*==.*"` |
| **Net Dns Susp Telegram Api** | `any where query:"api.telegram.org"` |
| **Net Dns Wannacry Killswitch Domain** | `any where query like~ ("ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.testing", "ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.t…` |
| **Pipe Created Hktl Diagtrack Eop** | `any where file.name:"*thisispipe*"` |
| **Pipe Created Hktl Generic Cred Dump Tools Pipes** | `any where file.name like~ ("*\\cachedump*", "*\\lsadump*", "*\\wceservicepipe*")` |
| **Pipe Created Hktl Koh Default Pipe** | `any where file.name like~ ("*\\imposecost*", "*\\imposingcost*")` |
| **Pipe Created Pua Csexec Default Pipe** | `any where file.name:"*\\csexecsvc*"` |
| **Pipe Created Pua Paexec Default Pipe** | `any where file.name:"\\PAExec*"` |
| **Pipe Created Pua Remcom Default Pipe** | `any where file.name:"*\\RemCom*"` |
| **Pipe Created Susp Malicious Namedpipes** | `any where file.name like~ ("\\46a676ab7f179e511e30dd2dc41bd388", "\\583da945-62af-10e8-4902-a8f205c72b2e", "\\6e7645c4-3…` |
| **Proc Access Win Cmstp Execution By Access** | `any where winlog.event_data.CallTrace:"*cmlua.dll*"` |
| **Proc Access Win Hktl Generic Access** | `any where (process.executable like~ ("*\\Akagi.exe", "*\\Akagi64.exe", "*\\atexec_windows.exe", "*\\Certify.exe", "*\\Ce…` |
| **Proc Access Win Hktl Sysmonente** | `any where (((winlog.event_data.TargetImage like~ ("*:\\Windows\\Sysmon.exe*", "*:\\Windows\\Sysmon64.exe*")) and winlog.…` |
| **Proc Access Win Svchost Susp Access Request** | `any where (winlog.event_data.TargetImage:"*:\\Windows\\System32\\svchost.exe" and winlog.event_data.GrantedAccess:"0x1F3…` |
| **Acccheckconsole Execution** | `any where (process.executable:"*\\AccCheckConsole.exe" or process.pe.original_file_name:"AccCheckConsole.exe") and (proc…` |
| **Addinutil Suspicious Cmdline** | `any where (process.executable:"*\\addinutil.exe" or process.pe.original_file_name:"AddInUtil.exe") and (((process.comman…` |
| **Addinutil Uncommon Child Process** | `any where process.parent.executable:"*\\addinutil.exe" and (not (process.executable like~ ("*:\\Windows\\System32\\conho…` |
| **Addinutil Uncommon Cmdline** | `any where ((process.executable:"*\\addinutil.exe" or process.pe.original_file_name:"AddInUtil.exe") and (process.command…` |
| **Addinutil Uncommon Dir Exec** | `any where (process.executable:"*\\addinutil.exe" or process.pe.original_file_name:"AddInUtil.exe") and (not (process.exe…` |
| **Agentexecutor Susp Usage** | `any where ((process.executable:"*\\AgentExecutor.exe" or process.pe.original_file_name:"AgentExecutor.exe") and (process…` |
| **Appvlp Uncommon Child Process** | `any where process.parent.executable:"*\\appvlp.exe" and (not (process.executable like~ ("*:\\Windows\\SysWOW64\\rundll32…` |
| **Aspnet Compiler Exectuion** | `any where (process.executable like~ ("*:\\Windows\\Microsoft.NET\\Framework\\*", "*:\\Windows\\Microsoft.NET\\Framework6…` |
| **Aspnet Compiler Susp Child Process** | `any where process.parent.executable:"*\\aspnet_compiler.exe" and ((process.executable like~ ("*\\calc.exe", "*\\notepad.…` |
| **Aspnet Compiler Susp Paths** | `any where (process.executable like~ ("*:\\Windows\\Microsoft.NET\\Framework\\*", "*:\\Windows\\Microsoft.NET\\Framework6…` |
| **At Interactive Execution** | `any where process.executable:"*\\at.exe" and process.command_line:"*interactive*"` |
| **Atbroker Uncommon Ats Execution** | `any where ((process.executable:"*\\AtBroker.exe" or process.pe.original_file_name:"AtBroker.exe") and process.command_li…` |
| **Auditpol Nt Resource Kit Usage** | `any where process.command_line like~ ("*/logon:none*", "*/system:none*", "*/sam:none*", "*/privilege:none*", "*/object:n…` |
| **Bcp Export Data** | `any where (process.executable:"*\\bcp.exe" or process.pe.original_file_name:"BCP.exe") and (process.command_line like~ (…` |
| **Bginfo Suspicious Child Process** | `any where (process.parent.executable like~ ("*\\bginfo.exe", "*\\bginfo64.exe")) and ((process.executable like~ ("*\\cal…` |
| **Bginfo Uncommon Child Process** | `any where process.parent.executable like~ ("*\\bginfo.exe", "*\\bginfo64.exe")` |
| **Bitlockertogo Execution** | `any where process.executable:"*\\BitLockerToGo.exe"` |
| **Boinc Execution** | `any where process.pe.description:"University of California, Berkeley"` |
| **Browsers Chromium Load Extension** | `any where (process.executable like~ ("*\\brave.exe", "*\\chrome.exe", "*\\msedge.exe", "*\\opera.exe", "*\\vivaldi.exe")…` |
| **Browsers Chromium Susp Load Extension** | `any where (process.parent.executable like~ ("*\\cmd.exe", "*\\cscript.exe", "*\\mshta.exe", "*\\powershell.exe", "*\\pws…` |
| **Calc Uncommon Exec** | `any where process.command_line:"*\\calc.exe *" or (process.executable:"*\\calc.exe" and (not (process.executable like~ (…` |
| **Certmgr Certificate Installation** | `any where (process.executable:"*\\CertMgr.exe" or process.pe.original_file_name:"CERTMGT.EXE") and (process.command_line…` |
| **Certoc Load Dll** | `any where (process.executable:"*\\certoc.exe" or process.pe.original_file_name:"CertOC.exe") and process.command_line li…` |
| **Chcp Codepage Lookup** | `any where process.parent.executable:"*\\cmd.exe" and (process.parent.command_line like~ ("* -c *", "* /c *", "* –c *", "…` |
| **Chcp Codepage Switch** | `any where process.executable:"*\\chcp.com" and (process.command_line like~ ("* 936", "* 1258"))` |
| **Cipher Overwrite Deleted Data** | `any where (process.pe.original_file_name:"CIPHER.EXE" or process.executable:"*\\cipher.exe") and process.command_line:"*…` |
| **Citrix Trolleyexpress Procdump** | `any where (process.command_line like~ ("*\\TrolleyExpress 7*", "*\\TrolleyExpress 8*", "*\\TrolleyExpress 9*", "*\\Troll…` |
| **Clip Execution** | `any where process.executable:"*\\clip.exe" or process.pe.original_file_name:"clip.exe"` |
| **Cloudflared Portable Execution** | `any where process.executable:"*\\cloudflared.exe" and (not (process.executable like~ ("*:\\Program Files (x86)\\cloudfla…` |
| **Cloudflared Tunnel Cleanup** | `any where (process.command_line:"* tunnel *" and process.command_line:"*cleanup *") and (process.command_line like~ ("*-…` |
| **Cmd Assoc Execution** | `any where (process.executable:"*\\cmd.exe" or process.pe.original_file_name:"Cmd.Exe") and process.command_line:"*assoc*…` |
| **Cmd Copy Dmp From Share** | `any where (process.executable:"*\\cmd.exe" or process.pe.original_file_name:"Cmd.Exe") and ((process.command_line:"*copy…` |
| **Cmd Dir Execution** | `any where (process.executable:"*\\cmd.exe" or process.pe.original_file_name:"Cmd.Exe") and process.command_line like~ ("…` |
| **Cmd Dosfuscation** | `any where process.command_line like~ ("*^^*", "*^|^*", "*,;,*", "*;;;;*", "*;; ;;*", "*(,(,*", "*%COMSPEC:~*", "* c^m^d*…` |
| **Cmd Http Appdata** | `any where process.executable:"*\\cmd.exe" and (process.command_line:"*http*" and process.command_line:"*://*" and proces…` |
| **Cmd Net Use And Exec Combo** | `any where (process.executable:"*\\cmd.exe*" or process.pe.original_file_name:"Cmd.EXE") and (process.command_line:"* net…` |
| **Cmd No Space Execution** | `any where ((process.command_line like~ ("*cmd.exe/c*", "*\\cmd/c*", "*\"cmd/c*", "*cmd.exe/k*", "*\\cmd/k*", "*\"cmd/k*"…` |
| **Cmd Ntdllpipe Redirect** | `any where process.command_line like~ ("*type %windir%\\system32\\ntdll.dll*", "*type %systemroot%\\system32\\ntdll.dll*"…` |
| **Cmd Path Traversal** | `any where ((process.parent.executable:"*\\cmd.exe" or process.executable:"*\\cmd.exe" or process.pe.original_file_name:"…` |
| **Cmd Ping Del Combined Execution** | `any where process.command_line like~ ("* -n *", "* /n *", "* –n *", "* —n *", "* ―n *") and process.command_line:"*Nul*"…` |
| **Cmd Redirect** | `any where ((process.pe.original_file_name:"Cmd.Exe" or process.executable:"*\\cmd.exe") and process.command_line:"*>*") …` |
| **Cmd Redirection Susp Folder** | `any where (process.executable:"*\\cmd.exe" or process.pe.original_file_name:"Cmd.Exe") and ((process.command_line like~ …` |
| **Cmd Rmdir Execution** | `any where (process.executable:"*\\cmd.exe" or process.pe.original_file_name:"Cmd.Exe") and process.command_line:"*rmdir*…` |
| **Cmd Set Prompt Abuse** | `any where (process.executable:"*\\cmd.exe" or process.pe.original_file_name:"Cmd.Exe") and (process.command_line like~ (…` |
| **Cmd Stdin Redirect** | `any where (process.pe.original_file_name:"Cmd.Exe" or process.executable:"*\\cmd.exe") and process.command_line:"*<*"` |
| **Cmd Sticky Key Like Backdoor Execution** | `any where process.parent.executable:"*\\winlogon.exe" and (process.executable like~ ("*\\cmd.exe", "*\\cscript.exe", "*\…` |
| **Cmd Sticky Keys Replace** | `any where process.command_line:"*copy *" and process.command_line:"*/y *" and process.command_line:"*C:\\windows\\system…` |
| **Cmdkey Adding Generic Creds** | `any where (process.executable:"*\\cmdkey.exe" or process.pe.original_file_name:"cmdkey.exe") and process.command_line li…` |
| **Cmstp Execution By Creation** | `any where process.parent.executable:"*\\cmstp.exe"` |
| **Conhost Headless Execution** | `any where process.parent.executable:"*\\conhost.exe" and process.parent.command_line:"*--headless*"` |
| **Conhost Legacy Option** | `any where (winlog.event_data.IntegrityLevel like~ ("High", "S-1-16-12288")) and (process.command_line:"*conhost.exe*" an…` |
| **Conhost Path Traversal** | `any where process.parent.command_line:"*conhost*" and process.command_line:"*/../../*"` |
| **Conhost Susp Child Process** | `any where process.parent.executable:"*\\conhost.exe" and (not (process.executable:"*:\\Windows\\System32\\conhost.exe" o…` |
| **Csc Susp Parent** | `any where (process.executable:"*\\csc.exe" or process.pe.original_file_name:"csc.exe") and ((process.parent.executable l…` |
| **Csi Execution** | `any where ((process.executable like~ ("*\\csi.exe", "*\\rcsi.exe")) or (process.pe.original_file_name like~ ("csi.exe", …` |
| **Csvde Export** | `any where ((process.executable:"*\\csvde.exe" or process.pe.original_file_name:"csvde.exe") and process.command_line:"* …` |
| **Curl Cookie Hijacking** | `any where (process.executable:"*\\curl.exe" or process.pe.original_file_name:"curl.exe") and (process.command_line like~…` |
| **Curl Custom User Agent** | `any where (process.executable:"*\\curl.exe" or process.pe.original_file_name:"curl.exe") and (process.command_line like~…` |
| **Curl Execution** | `any where process.executable:"*\\curl.exe" or process.pe.product:"The curl executable"` |
| **Curl Insecure Connection** | `any where (process.executable:"*\\curl.exe" or process.pe.original_file_name:"curl.exe") and (process.command_line like~…` |
| **Curl Insecure Proxy Or Doh** | `any where (process.executable:"*\\curl.exe" or process.pe.original_file_name:"curl.exe") and (process.command_line like~…` |
| **Curl Local File Read** | `any where (process.executable:"*\\curl.exe" or process.pe.original_file_name:"curl.exe") and process.command_line:"*file…` |
| **Curl Useragent** | `any where (process.executable:"*\\curl.exe" or process.pe.product:"The curl executable") and (process.command_line like~…` |
| **Customshellhost Susp Exec** | `any where process.parent.executable:"*\\CustomShellHost.exe" and (not process.executable:"C:\\Windows\\explorer.exe")` |
| **Defaultpack Uncommon Child Process** | `any where process.parent.executable:"*\\DefaultPack.exe"` |
| **Deviceenroller Dll Sideloading** | `any where (process.executable:"*\\deviceenroller.exe" or process.pe.original_file_name:"deviceenroller.exe") and process…` |
| **Devinit Lolbin Usage** | `any where process.command_line:"* -t msi-install *" and process.command_line:"* -i http*"` |
| **Dirlister Execution** | `any where process.pe.original_file_name:"DirLister.exe" or process.executable:"*\\DirLister.exe"` |
| **Dism Remove** | `any where (process.executable:"*\\DismHost.exe" and (process.parent.command_line:"*/Online*" and process.parent.command_…` |
| **Dll Sideload Vmware Xfer** | `any where process.executable:"*\\VMwareXferlogs.exe" and (not process.executable:"C:\\Program Files\\VMware\\*")` |
| **Dnscmd Install New Server Level Plugin Dll** | `any where process.executable:"*\\dnscmd.exe" and (process.command_line:"*/config*" and process.command_line:"*/serverlev…` |
| **Dnx Execute Csharp Code** | `any where process.executable:"*\\dnx.exe"` |
| **Dotnet Trace Lolbin Execution** | `any where (process.executable:"*\\dotnet-trace.exe" or process.pe.original_file_name:"dotnet-trace.dll") and (process.co…` |
| **Driverquery Usage** | `any where (process.executable:"*driverquery.exe" or process.pe.original_file_name:"drvqry.exe") and (not ((process.paren…` |
| **Dsacls Abuse Permissions** | `any where (process.executable:"*\\dsacls.exe" or process.pe.original_file_name:"DSACLS.EXE") and process.command_line:"*…` |
| **Dsacls Password Spray** | `any where (process.executable:"*\\dsacls.exe" or process.pe.original_file_name:"DSACLS.EXE") and (process.command_line:"…` |
| **Dtrace Kernel Dump** | `any where (process.executable:"*\\dtrace.exe" and process.command_line:"*lkd(0)*") or (process.command_line:"*syscall:::…` |
| **Dumpminitool Execution** | `any where ((process.executable like~ ("*\\DumpMinitool.exe", "*\\DumpMinitool.x86.exe", "*\\DumpMinitool.arm64.exe")) or…` |
| **Dumpminitool Susp Execution** | `any where ((process.executable like~ ("*\\DumpMinitool.exe", "*\\DumpMinitool.x86.exe", "*\\DumpMinitool.arm64.exe")) or…` |
| **Dxcap Arbitrary Binary Execution** | `any where (process.executable:"*\\DXCap.exe" or process.pe.original_file_name:"DXCap.exe") and process.command_line:"* -…` |
| **Esentutl Sensitive File Copy** | `any where ((process.executable:"*\\esentutl.exe" or process.pe.original_file_name:"\\esentutl.exe") and (process.command…` |
| **Esentutl Webcache** | `any where (process.executable:"*\\esentutl.exe" or process.pe.original_file_name:"esentutl.exe") and process.command_lin…` |
| **Explorer Break Process Tree** | `any where process.command_line:"*/factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b}*" or (process.command_line:"*explorer.e…` |
| **Explorer Folder Shortcut Via Shell Binary** | `any where (process.parent.executable like~ ("*\\cmd.exe", "*\\powershell.exe", "*\\pwsh.exe")) and process.executable:"*…` |
| **Extexport Execution** | `any where process.executable:"*\\Extexport.exe" or process.pe.original_file_name:"extexport.exe"` |
| **Findstr Gpp Passwords** | `any where ((process.executable like~ ("*\\find.exe", "*\\findstr.exe")) or (process.pe.original_file_name like~ ("FIND.E…` |
| **Findstr Security Keyword Lookup** | `any where ((process.executable like~ ("*\\find.exe", "*\\findstr.exe")) or (process.pe.original_file_name like~ ("FIND.E…` |
| **Findstr Subfolder Search** | `any where (process.command_line:"*findstr*" or process.executable:"*findstr.exe" or process.pe.original_file_name:"FINDS…` |
| **Finger Execution** | `any where process.pe.original_file_name:"finger.exe" or process.executable:"*\\finger.exe"` |
| **Fltmc Unload Driver** | `any where ((process.executable:"*\\fltMC.exe" or process.pe.original_file_name:"fltMC.exe") and process.command_line:"*u…` |
| **Format Uncommon Filesystem Load** | `any where (process.executable:"*\\format.com" and process.command_line:"*/fs:*") and (not (process.command_line like~ ("…` |
| **Git Susp Clone** | `any where ((process.executable like~ ("*\\git.exe", "*\\git-remote-https.exe")) or process.pe.original_file_name:"git.ex…` |
| **Github Self Hosted Runner** | `any where ((process.executable:"*\\Runner.Worker.exe" or process.pe.original_file_name:"Runner.Worker.dll") and process.…` |
| **Gpg4Win Portable Execution** | `any where ((process.executable like~ ("*\\gpg.exe", "*\\gpg2.exe")) or process.pe.original_file_name:"gpg.exe" or proces…` |
| **Gpg4Win Susp Location** | `any where ((process.executable like~ ("*\\gpg.exe", "*\\gpg2.exe")) or process.pe.product:"GNU Privacy Guard (GnuPG)" or…` |
| **Gpresult Execution** | `any where process.executable:"*\\gpresult.exe" and (process.command_line like~ ("*/z*", "*/v*"))` |
| **Gup Arbitrary Binary Execution** | `any where (process.parent.executable:"*\\gup.exe" and process.executable:"*\\explorer.exe") and (not ((process.executabl…` |
| **Gup Suspicious Execution** | `any where process.executable:"*\\GUP.exe" and (not ((process.executable like~ ("*\\Program Files\\Notepad++\\updater\\GU…` |
| **Hktl Adcspwn** | `any where process.command_line:"* --adcs *" and process.command_line:"* --port *"` |
| **Hktl Bloodhound Sharphound** | `any where (process.pe.product:"*SharpHound*" or process.pe.description:"*SharpHound*" or (process.pe.company like~ ("*Sp…` |
| **Hktl C3 Rundll32 Pattern** | `any where process.command_line:"*rundll32.exe*" and process.command_line:"*.dll*" and process.command_line:"*StartNodeRe…` |
| **Hktl Certify** | `any where (process.executable:"*\\Certify.exe" or process.pe.original_file_name:"Certify.exe" or process.pe.description:…` |
| **Hktl Certipy** | `any where (process.executable:"*\\Certipy.exe" or process.pe.original_file_name:"Certipy.exe" or process.pe.description:…` |
| **Hktl Crackmapexec Execution Patterns** | `any where process.command_line like~ ("*cmd.exe /Q /c * 1> \\\\*\\*\\* 2>&1*", "*cmd.exe /C * > \\\\*\\*\\* 2>&1*", "*cm…` |
| **Hktl Dinjector** | `any where process.command_line:"* /am51*" and process.command_line:"* /password*"` |
| **Hktl Edrsilencer** | `any where process.executable:"*\\EDRSilencer.exe" or process.pe.original_file_name:"EDRSilencer.exe" or process.pe.descr…` |
| **Hktl Evil Winrm** | `any where process.executable:"*\\ruby.exe" and (process.command_line:"*-i *" and process.command_line:"*-u *" and proces…` |
| **Hktl Execution Via Pe Metadata** | `any where process.pe.company:"Cube0x0"` |
| **Hktl Hashcat** | `any where process.executable:"*\\hashcat.exe" or (process.command_line:"*-a *" and process.command_line:"*-m 1000 *" and…` |
| **Hktl Hydra** | `any where (process.command_line:"*-u *" and process.command_line:"*-p *") and (process.command_line like~ ("*^USER^*", "…` |
| **Hktl Impacket Tools** | `any where (process.executable like~ ("*\\goldenPac*", "*\\karmaSMB*", "*\\kintercept*", "*\\ntlmrelayx*", "*\\rpcdump*",…` |
| **Hktl Inveigh** | `any where process.executable:"*\\Inveigh.exe" or (process.pe.original_file_name like~ ("\\Inveigh.exe", "\\Inveigh.dll")…` |
| **Hktl Krbrelay Remote** | `any where (process.executable:"*\\RemoteKrbRelay.exe" or process.pe.original_file_name:"RemoteKrbRelay.exe") or (process…` |
| **Hktl Powertool** | `any where (process.executable like~ ("*\\PowerTool.exe", "*\\PowerTool64.exe")) or process.pe.original_file_name:"PowerT…` |
| **Hktl Purplesharp Indicators** | `any where (process.executable:"*\\purplesharp*" or process.pe.original_file_name:"PurpleSharp.exe") or (process.command_…` |
| **Hktl Quarks Pwdump** | `any where process.executable:"*\\QuarksPwDump.exe" or (process.command_line like~ (" -dhl", " --dump-hash-local", " -dhd…` |
| **Hktl Redmimicry Winnti Playbook** | `any where (process.executable like~ ("*\\rundll32.exe", "*\\cmd.exe")) and (process.command_line like~ ("*gthread-3.6.dl…` |
| **Hktl Relay Attacks Tools** | `any where ((process.executable like~ ("*PetitPotam*", "*RottenPotato*", "*HotPotato*", "*JuicyPotato*", "*\\just_dce_*",…` |
| **Hktl Rubeus** | `any where process.executable:"*\\Rubeus.exe" or process.pe.original_file_name:"Rubeus.exe" or process.pe.description:"Ru…` |
| **Hktl Safetykatz** | `any where process.executable:"*\\SafetyKatz.exe" or process.pe.original_file_name:"SafetyKatz.exe" or process.pe.descrip…` |
| **Hktl Secutyxploded** | `any where process.pe.company:"SecurityXploded" or process.executable:"*PasswordDump.exe" or process.pe.original_file_nam…` |
| **Hktl Sharp Chisel** | `any where process.executable:"*\\SharpChisel.exe" or process.pe.product:"SharpChisel"` |
| **Hktl Sharp Dpapi Execution** | `any where (process.executable:"*\\SharpDPAPI.exe" or process.pe.original_file_name:"SharpDPAPI.exe") or ((process.comman…` |
| **Hktl Sharp Ldap Monitor** | `any where (process.executable:"*\\SharpLDAPmonitor.exe" or process.pe.original_file_name:"SharpLDAPmonitor.exe") or (pro…` |
| **Hktl Sharpevtmute** | `any where process.executable:"*\\SharpEvtMute.exe" or process.pe.description:"SharpEvtMute" or (process.command_line lik…` |
| **Hktl Sharpmove** | `any where (process.executable:"*\\SharpMove.exe" or process.pe.original_file_name:"SharpMove.exe") or (process.command_l…` |
| **Hktl Sharpup** | `any where process.executable:"*\\SharpUp.exe" or process.pe.description:"SharpUp" or (process.command_line like~ ("*Hija…` |
| **Hktl Sharpview** | `any where process.pe.original_file_name:"SharpView.exe" or process.executable:"*\\SharpView.exe" or (process.command_lin…` |
| **Hktl Silenttrinity Stager** | `any where process.pe.description:"*st2stager*"` |
| **Hktl Trufflesnout** | `any where process.pe.original_file_name:"TruffleSnout.exe" or process.executable:"*\\TruffleSnout.exe"` |
| **Hktl Winpeas** | `any where (process.pe.original_file_name:"winPEAS.exe" or (process.executable like~ ("*\\winPEASany_ofs.exe", "*\\winPEA…` |
| **Hktl Winpwn** | `any where process.command_line like~ ("*Offline_Winpwn*", "*WinPwn *", "*WinPwn.exe*", "*WinPwn.ps1*")` |
| **Hktl Xordump** | `any where process.executable:"*\\xordump.exe" or (process.command_line like~ ("* -process lsass.exe *", "* -m comsvcs *"…` |
| **Hostname Execution** | `any where process.executable:"*\\HOSTNAME.EXE"` |
| **Hxtsr Masquerading** | `any where process.executable:"*\\hxtsr.exe" and (not (process.executable:"*:\\program files\\windowsapps\\microsoft.wind…` |
| **Icacls Deny** | `any where (process.pe.original_file_name:"iCACLS.EXE" or process.executable:"*\\icacls.exe") and (process.command_line:"…` |
| **Iexpress Execution** | `any where (process.parent.executable:"*\\iexpress.exe" and (process.executable:"*\\makecab.exe" or process.pe.original_f…` |
| **Imagingdevices Unusual Parents** | `any where ((process.parent.executable like~ ("*\\WmiPrvSE.exe", "*\\svchost.exe", "*\\dllhost.exe")) and process.executa…` |
| **Instalutil No Log Execution** | `any where process.executable:"*\\InstallUtil.exe" and process.executable:"*Microsoft.NET\\Framework*" and (process.comma…` |
| **Java Remote Debugging** | `any where (process.command_line:"*transport=dt_socket,address=*" and (process.command_line like~ ("*jre1.*", "*jdk1.*"))…` |
| **Java Susp Child Process 2** | `any where (process.parent.executable:"*\\java.exe" and (process.executable like~ ("*\\bash.exe", "*\\cmd.exe", "*\\power…` |
| **Java Sysaidserver Susp Child Process** | `any where (process.parent.executable like~ ("*\\java.exe", "*\\javaw.exe")) and process.parent.command_line:"*SysAidServ…` |
| **Jsc Execution** | `any where process.executable:"*\\jsc.exe" or process.pe.original_file_name:"jsc.exe"` |
| **Kavremover Uncommon Execution** | `any where process.command_line:"* run run-cmd *" and (not (process.parent.executable like~ ("*\\cleanapi.exe", "*\\kavre…` |
| **Kd Execution** | `any where process.executable:"*\\kd.exe" or process.pe.original_file_name:"kd.exe"` |
| **Ksetup Password Change Computer** | `any where (process.executable:"*\\ksetup.exe" or process.pe.original_file_name:"ksetup.exe") and process.command_line:"*…` |
| **Ksetup Password Change User** | `any where (process.executable:"*\\ksetup.exe" or process.pe.original_file_name:"ksetup.exe") and process.command_line:"*…` |
| **Ldifde Export** | `any where ((process.executable:"*\\ldifde.exe" or process.pe.original_file_name:"ldifde.exe") and process.command_line:"…` |
| **Ldifde File Load** | `any where (process.executable:"*\\ldifde.exe" or process.pe.original_file_name:"ldifde.exe") and (process.command_line:"…` |
| **Link Uncommon Parent Process** | `any where (process.executable:"*\\link.exe" and process.command_line:"*LINK /*") and (not ((process.parent.executable li…` |
| **Lolbin Devtoolslauncher** | `any where process.executable:"*\\devtoolslauncher.exe" and process.command_line:"*LaunchForDeploy*"` |
| **Lolbin Diantz Ads** | `any where (process.command_line:"*diantz.exe*" and process.command_line:"*.cab*") and process.command_line:"SigmaRegular…` |
| **Lolbin Diantz Remote Cab** | `any where process.command_line:"*diantz.exe*" and process.command_line:"* \\\\*" and process.command_line:"*.cab*"` |
| **Lolbin Extrac32** | `any where (process.command_line:"*extrac32.exe*" or process.executable:"*\\extrac32.exe" or process.pe.original_file_nam…` |
| **Lolbin Extrac32 Ads** | `any where (process.command_line:"*extrac32.exe*" and process.command_line:"*.cab*") and process.command_line:"SigmaRegul…` |
| **Lolbin Gather Network Info** | `any where ((process.executable like~ ("*\\cscript.exe", "*\\wscript.exe")) or (process.pe.original_file_name like~ ("csc…` |
| **Lolbin Gpscript** | `any where ((process.executable:"*\\gpscript.exe" or process.pe.original_file_name:"GPSCRIPT.EXE") and (process.command_l…` |
| **Lolbin Ie4Uinit** | `any where (process.executable:"*\\ie4uinit.exe" or process.pe.original_file_name:"IE4UINIT.EXE") and (not ((process.work…` |
| **Lolbin Launch Vsdevshell** | `any where process.command_line:"*Launch-VsDevShell.ps1*" and (process.command_line like~ ("*VsWherePath *", "*VsInstalla…` |
| **Lolbin Manage Bde** | `any where ((process.executable:"*\\wscript.exe" or process.pe.original_file_name:"wscript.exe") and process.command_line…` |
| **Lolbin Mavinject Process Injection** | `any where process.command_line:"* /INJECTRUNNING *" and (not process.parent.executable:"C:\\Windows\\System32\\AppVClien…` |
| **Lolbin Msdeploy** | `any where (process.command_line:"*verb:sync*" and process.command_line:"*-source:RunCommand*" and process.command_line:"…` |
| **Lolbin Openconsole** | `any where (process.pe.original_file_name:"OpenConsole.exe" or process.executable:"*\\OpenConsole.exe") and (not process.…` |
| **Lolbin Openwith** | `any where process.executable:"*\\OpenWith.exe" and process.command_line:"*/c*"` |
| **Lolbin Pcalua** | `any where process.executable:"*\\pcalua.exe" and process.command_line:"* -a*"` |
| **Lolbin Pcwrun** | `any where process.parent.executable:"*\\pcwrun.exe"` |
| **Lolbin Pcwrun Follina** | `any where process.executable:"*\\pcwrun.exe" and process.command_line:"*../*"` |
| **Lolbin Pcwutl** | `any where (process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE") and (process.command_li…` |
| **Lolbin Pester** | `any where ((process.parent.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) and process.parent.command_line:"*\\Wi…` |
| **Lolbin Pubprn** | `any where process.command_line:"*\\pubprn.vbs*" and process.command_line:"*script:*"` |
| **Lolbin Rasautou Dll Execution** | `any where (process.executable:"*\\rasautou.exe" or process.pe.original_file_name:"rasdlui.exe") and (process.command_lin…` |
| **Lolbin Register App** | `any where process.command_line:"*\\register_app.vbs*" and process.command_line:"*-register*"` |
| **Lolbin Remote** | `any where process.executable:"*\\remote.exe" or process.pe.original_file_name:"remote.exe"` |
| **Lolbin Replace** | `any where process.executable:"*\\replace.exe" and process.command_line like~ ("*-a*", "*/a*", "*–a*", "*—a*", "*―a*")` |
| **Lolbin Runexehelper** | `any where process.parent.executable:"*\\runexehelper.exe"` |
| **Lolbin Runscripthelper** | `any where process.executable:"*\\Runscripthelper.exe" and process.command_line:"*surfacecheck*"` |
| **Lolbin Scriptrunner** | `any where (process.executable:"*\\ScriptRunner.exe" or process.pe.original_file_name:"ScriptRunner.exe") and process.com…` |
| **Lolbin Settingsynchost** | `any where (not (process.executable like~ ("C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*"))) and (process.parent.…` |
| **Lolbin Susp Grpconv** | `any where process.command_line like~ ("*grpconv.exe -o*", "*grpconv -o*")` |
| **Lolbin Syncappvpublishingserver Execute Psh** | `any where (process.executable:"*\\SyncAppvPublishingServer.exe" or process.pe.original_file_name:"syncappvpublishingserv…` |
| **Lolbin Syncappvpublishingserver Vbs Execute Psh** | `any where process.command_line:"*\\SyncAppvPublishingServer.vbs*" and process.command_line:"*;*"` |
| **Lolbin Tracker** | `any where ((process.executable:"*\\tracker.exe" or process.pe.description:"Tracker") and (process.command_line like~ ("*…` |
| **Lolbin Ttdinject** | `any where process.executable:"*ttdinject.exe" or process.pe.original_file_name:"TTDInject.EXE"` |
| **Lolbin Tttracer Mod Load** | `any where process.parent.executable:"*\\tttracer.exe"` |
| **Lolbin Unregmp2** | `any where (process.executable:"*\\unregmp2.exe" or process.pe.original_file_name:"unregmp2.exe") and process.command_lin…` |
| **Lolbin Utilityfunctions** | `any where process.command_line like~ ("*UtilityFunctions.ps1*", "*RegSnapin *")` |
| **Lolbin Visual Basic Compiler** | `any where process.parent.executable:"*\\vbc.exe" and process.executable:"*\\cvtres.exe"` |
| **Lolbin Visualuiaverifynative** | `any where process.executable:"*\\VisualUiaVerifyNative.exe" or process.pe.original_file_name:"VisualUiaVerifyNative.exe"` |
| **Lolbin Vsiisexelauncher** | `any where (process.executable:"*\\VSIISExeLauncher.exe" or process.pe.original_file_name:"VSIISExeLauncher.exe") and (pr…` |
| **Lolscript Register App** | `any where ((process.executable like~ ("*\\cscript.exe", "*\\wscript.exe")) or (process.pe.original_file_name like~ ("csc…` |
| **Malware 3Cx Compromise Susp Children** | `any where process.parent.executable:"*\\3CXDesktopApp.exe" and (process.executable like~ ("*\\cmd.exe", "*\\cscript.exe"…` |
| **Malware 3Cx Compromise Susp Update** | `any where process.executable:"*\\3CXDesktopApp\\app\\update.exe" and (process.command_line:"*--update*" and process.comm…` |
| **Malware Blue Mockingbird** | `any where (process.executable:"*\\cmd.exe" and (process.command_line:"*sc config*" and process.command_line:"*wercplsupp…` |
| **Malware Coldsteel Anonymous Process** | `any where (process.parent.executable like~ ("*\\Windows\\System32\\*", "*\\AppData\\*")) and user.name:"*ANONYMOUS*"` |
| **Malware Coldsteel Cleanup** | `any where process.parent.executable:"*\\svchost.exe" and (process.parent.command_line like~ ("* -k msupdate*", "* -k msu…` |
| **Malware Conti** | `any where process.command_line:"*vssadmin list shadows*" and process.command_line:"*log.txt*"` |
| **Malware Conti 7Zip** | `any where process.command_line:"*7za.exe*" and process.command_line:"*\\C$\\temp\\log.zip*"` |
| **Malware Darkgate Autoit3 From Susp Parent And Location** | `any where ((process.executable:"*\\Autoit3.exe" or process.pe.original_file_name:"AutoIt3.exe") and (process.parent.exec…` |
| **Malware Devil Bait Output Redirect** | `any where (process.parent.executable:"*\\wscript.exe" and process.executable:"*\\cmd.exe" and process.command_line:"*>>%…` |
| **Malware Dtrack** | `any where process.command_line:"SigmaRegularExpression(regexp=SigmaString(['ping\\s+-n.{6,64}echo EEEE\\s', <SpecialChar…` |
| **Malware Elise** | `any where (process.executable:"*\\Microsoft\\Network\\svchost.exe" or (process.command_line:"*\\Windows\\Caches\\NavShEx…` |
| **Malware Emotet** | `any where (process.command_line like~ ("* -e* PAA*", "*JABlAG4AdgA6AHUAcwBlAHIAcAByAG8AZgBpAGwAZQ*", "*QAZQBuAHYAOgB1AHM…` |
| **Malware Emotet Rundll32 Execution** | `any where ((process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE") and (process.command_l…` |
| **Malware Fireball** | `any where process.command_line:"*rundll32.exe*" and process.command_line:"*InstallArcherSvc*"` |
| **Malware Goofy Guineapig Broken Cmd** | `any where process.command_line:"*choice /t %d /d y /n >nul*"` |
| **Malware Griffon Patterns** | `any where process.command_line:"*\\local\\temp\\*" and process.command_line:"*//b /e:jscript*" and process.command_line:…` |
| **Malware Hermetic Wiper Activity** | `any where process.executable:"*\\policydefinitions\\postgresql.exe" or ((process.command_line like~ ("*CSIDL_SYSTEM_DRIV…` |
| **Malware Icedid Rundll32 Dllregisterserver** | `any where process.executable:"*\\rundll32.exe" and (process.command_line like~ ("*\\1.dll, DllRegisterServer", "* 1.dll,…` |
| **Malware Ke3Chang Tidepool** | `any where process.command_line like~ ("*-Property DWORD -name DisableFirstRunCustomize -value 2 -Force*", "*-Property St…` |
| **Malware Pikabot Combined Commands Execution** | `any where (process.command_line:"*cmd*" and process.command_line:"*/c*") and (process.command_line like~ ("* & *", "* ||…` |
| **Malware Plugx Susp Exe Locations** | `any where (process.executable:"*\\CamMute.exe" and (not (process.executable like~ ("*\\Lenovo\\Communication Utility\\*"…` |
| **Malware Qakbot Regsvr32 Calc Pattern** | `any where process.executable:"*\\regsvr32.exe" and process.command_line like~ ("* -s*", "* /s*", "* –s*", "* —s*", "* ―s…` |
| **Malware Qakbot Rundll32 Execution** | `any where ((process.parent.executable like~ ("*\\cmd.exe", "*\\cscript.exe", "*\\curl.exe", "*\\mshta.exe", "*\\powershe…` |
| **Malware Qakbot Rundll32 Exports** | `any where ((process.parent.executable like~ ("*\\cmd.exe", "*\\cscript.exe", "*\\curl.exe", "*\\mshta.exe", "*\\powershe…` |
| **Malware Qakbot Rundll32 Fake Dll Execution** | `any where ((process.parent.executable like~ ("*\\cmd.exe", "*\\cscript.exe", "*\\curl.exe", "*\\mshta.exe", "*\\powershe…` |
| **Malware Qbot** | `any where (process.parent.executable:"*\\WinRAR.exe" and process.executable:"*\\wscript.exe") or process.command_line:"*…` |
| **Malware Raspberry Robin External Drive Exec** | `any where (process.parent.executable:"*\\cmd.exe" and process.parent.command_line:"*/r*" and (process.parent.command_lin…` |
| **Malware Raspberry Robin Rundll32 Shell32 Cpl Exection** | `any where (process.parent.executable like~ ("*\\rundll32.exe", "*\\control.exe")) and (process.executable:"*\\rundll32.e…` |
| **Malware Rhadamanthys Stealer Dll Launch** | `any where (process.pe.original_file_name:"RUNDLL32.EXE" or process.executable:"*\\rundll32.exe") and process.command_lin…` |
| **Malware Small Sieve Cli Arg** | `any where process.command_line:"*.exe Platypus"` |
| **Malware Snake Installer Cli Args** | `any where process.command_line:"SigmaRegularExpression(regexp=SigmaString(['\\s[a-fA-F0-9]{64}\\s[a-fA-F0-9]{16}']), fla…` |
| **Malware Snake Installer Exec** | `any where (process.executable like~ ("*\\jpsetup.exe", "*\\jpinst.exe")) and (not ((process.command_line like~ ("jpinst.…` |
| **Malware Socgholish Fakeupdates Activity** | `any where process.parent.executable:"*\\wscript.exe" and (process.parent.command_line:"*\\AppData\\Local\\Temp*" and pro…` |
| **Malware Wannacry** | `any where ((process.executable like~ ("*\\tasksche.exe", "*\\mssecsvc.exe", "*\\taskdl.exe", "*\\taskhsvc.exe", "*\\task…` |
| **Mftrace Child Process** | `any where process.parent.executable:"*\\mftrace.exe"` |
| **Msdt Answer File Exec** | `any where (process.executable:"*\\msdt.exe" and process.command_line:"*\\WINDOWS\\diagnostics\\index\\PCWDiagnostic.xml*…` |
| **Msdt Susp Cab Options** | `any where (process.executable:"*\\msdt.exe" or process.pe.original_file_name:"msdt.exe") and process.command_line like~ …` |
| **Mshta Http** | `any where (process.executable:"*\\mshta.exe" or process.pe.original_file_name:"MSHTA.EXE") and (process.command_line lik…` |
| **Mshta Inline Vbscript** | `any where process.command_line:"*Wscript.*" and process.command_line:"*.Shell*" and process.command_line:"*.Run*"` |
| **Mshta Javascript** | `any where (process.executable:"*\\mshta.exe" or process.pe.original_file_name:"MSHTA.EXE") and process.command_line:"*ja…` |
| **Mshta Lethalhta Technique** | `any where process.parent.executable:"*\\svchost.exe" and process.executable:"*\\mshta.exe"` |
| **Msiexec Dll** | `any where (process.executable:"*\\msiexec.exe" or process.pe.original_file_name:"\\msiexec.exe") and process.command_lin…` |
| **Msiexec Embedding** | `any where ((process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe", "*\\cmd.exe")) and (process.parent.command_lin…` |
| **Msiexec Install Remote** | `any where ((process.executable:"*\\msiexec.exe" or process.pe.original_file_name:"msiexec.exe") and (process.command_lin…` |
| **Msiexec Masquerading** | `any where (process.executable:"*\\msiexec.exe" or process.pe.original_file_name:"\\msiexec.exe") and (not (process.execu…` |
| **Msra Process Injection** | `any where process.parent.executable:"*\\msra.exe" and process.parent.command_line:"*msra.exe" and (process.executable li…` |
| **Mssql Sqlps Susp Execution** | `any where process.parent.executable:"*\\sqlps.exe" or ((process.executable:"*\\sqlps.exe" or process.pe.original_file_na…` |
| **Msxsl Execution** | `any where process.executable:"*\\msxsl.exe"` |
| **Net Start Service** | `any where ((process.executable like~ ("*\\net.exe", "*\\net1.exe")) or (process.pe.original_file_name like~ ("net.exe", …` |
| **Net Stop Service** | `any where ((process.pe.original_file_name like~ ("net.exe", "net1.exe")) or (process.executable like~ ("*\\net.exe", "*\…` |
| **Netsh Fw Delete Rule** | `any where ((process.executable:"*\\netsh.exe" or process.pe.original_file_name:"netsh.exe") and (process.command_line:"*…` |
| **Netsh Packet Capture** | `any where (process.executable:"*\\netsh.exe" or process.pe.original_file_name:"netsh.exe") and (process.command_line:"*t…` |
| **Netsh Port Forwarding 3389** | `any where (process.executable:"*\\netsh.exe" or process.pe.original_file_name:"netsh.exe") and (process.command_line:"* …` |
| **Nltest Execution** | `any where process.executable:"*\\nltest.exe" or process.pe.original_file_name:"nltestrk.exe"` |
| **Node Adobe Creative Cloud Abuse** | `any where process.executable:"*\\Adobe Creative Cloud Experience\\libs\\node.exe" and (not process.command_line:"*Adobe …` |
| **Ntdsutil Susp Usage** | `any where (process.executable:"*\\ntdsutil.exe" or process.pe.original_file_name:"ntdsutil.exe") and ((process.command_l…` |
| **Ntdsutil Usage** | `any where process.executable:"*\\ntdsutil.exe"` |
| **Odbcconf Uncommon Child Process** | `any where process.parent.executable:"*\\odbcconf.exe"` |
| **Office Exec From Trusted Locations** | `any where ((process.parent.executable like~ ("*\\explorer.exe", "*\\dopus.exe")) and ((process.executable like~ ("*\\EXC…` |
| **Office Onenote Susp Child Processes** | `any where process.parent.executable:"*\\onenote.exe" and (((process.pe.original_file_name like~ ("bitsadmin.exe", "CertO…` |
| **Office Outlook Enable Unsafe Client Mail Rules** | `any where process.command_line:"*\\Outlook\\Security\\EnableUnsafeClientMailRules*"` |
| **Offlinescannershell Mpclient Sideloading** | `any where (process.executable:"*\\OfflineScannerShell.exe" or process.pe.original_file_name:"OfflineScannerShell.exe") a…` |
| **Pdqdeploy Execution** | `any where process.pe.description:"PDQ Deploy Console" or process.pe.product:"PDQ Deploy" or process.pe.company:"PDQ.com"…` |
| **Perl Inline Command Execution** | `any where (process.executable:"*\\perl.exe" or process.pe.original_file_name:"perl.exe") and process.command_line:"* -e*…` |
| **Php Inline Command Execution** | `any where (process.executable:"*\\php.exe" or process.pe.original_file_name:"php.exe") and process.command_line:"* -r*"` |
| **Pktmon Execution** | `any where process.executable:"*\\pktmon.exe" or process.pe.original_file_name:"PktMon.exe"` |
| **Powercfg Execution** | `any where (process.executable:"*\\powercfg.exe" or process.pe.original_file_name:"PowerCfg.exe") and ((process.command_l…` |
| **Presentationhost Uncommon Location Exec** | `any where ((process.executable:"*\\presentationhost.exe" or process.pe.original_file_name:"PresentationHost.exe") and pr…` |
| **Pressanykey Lolbin Execution** | `any where process.parent.executable:"*\\Microsoft.NodejsTools.PressAnyKey.exe"` |
| **Provlaunch Potential Abuse** | `any where process.parent.executable:"*\\provlaunch.exe" and (not ((process.executable like~ ("*\\calc.exe", "*\\cmd.exe"…` |
| **Provlaunch Susp Child Process** | `any where process.parent.executable:"*\\provlaunch.exe" and ((process.executable like~ ("*\\calc.exe", "*\\cmd.exe", "*\…` |
| **Psr Capture Screenshots** | `any where process.executable:"*\\Psr.exe" and (process.command_line like~ ("*/start*", "*-start*"))` |
| **Pua 3Proxy Execution** | `any where process.executable:"*\\3proxy.exe" or process.pe.description:"3proxy - tiny proxy server" or process.command_l…` |
| **Pua Adfind Susp Usage** | `any where process.command_line like~ ("*domainlist*", "*trustdmp*", "*dcmodes*", "*adinfo*", "*-sc dclist*", "*computer_…` |
| **Pua Advanced Ip Scanner** | `any where (process.executable:"*\\advanced_ip_scanner*" or process.pe.original_file_name:"*advanced_ip_scanner*" or proc…` |
| **Pua Advanced Port Scanner** | `any where (process.executable:"*\\advanced_port_scanner*" or process.pe.original_file_name:"*advanced_port_scanner*" or …` |
| **Pua Advancedrun** | `any where process.pe.original_file_name:"AdvancedRun.exe" or (process.command_line:"* /EXEFilename *" and process.comman…` |
| **Pua Advancedrun Priv User** | `any where (process.command_line like~ ("*/EXEFilename*", "*/CommandLine*")) and ((process.command_line like~ ("* /RunAs …` |
| **Pua Chisel** | `any where process.executable:"*\\chisel.exe" or ((process.command_line like~ ("*exe client *", "*exe server *")) and (pr…` |
| **Pua Crassus** | `any where process.executable:"*\\Crassus.exe" or process.pe.original_file_name:"Crassus.exe" or process.pe.description:"…` |
| **Pua Csexec** | `any where process.executable:"*\\csexec.exe" or process.pe.description:"csexec"` |
| **Pua Ditsnap** | `any where process.executable:"*\\ditsnap.exe" or process.command_line:"*ditsnap.exe*"` |
| **Pua Mouselock Execution** | `any where process.pe.product:"*Mouse Lock*" or process.pe.company:"*Misc314*" or process.command_line:"*Mouse Lock_*"` |
| **Pua Netcat** | `any where (process.executable like~ ("*\\nc.exe", "*\\ncat.exe", "*\\netcat.exe")) or (process.command_line like~ ("* -l…` |
| **Pua Netscan** | `any where process.executable:"*\\netscan.exe" or process.pe.product:"Network Scanner" or process.pe.description:"Applica…` |
| **Pua Ngrok** | `any where (process.command_line like~ ("* tcp 139*", "* tcp 445*", "* tcp 3389*", "* tcp 5985*", "* tcp 5986*")) or (pro…` |
| **Pua Nircmd As System** | `any where process.command_line:"* runassystem *"` |
| **Pua Nmap Zenmap** | `any where (process.executable like~ ("*\\nmap.exe", "*\\zennmap.exe")) or (process.pe.original_file_name like~ ("nmap.ex…` |
| **Pua Nsudo** | `any where ((process.executable like~ ("*\\NSudo.exe", "*\\NSudoLC.exe", "*\\NSudoLG.exe")) or (process.pe.original_file_…` |
| **Pua Pingcastle Script Parent** | `any where ((process.parent.command_line like~ ("*.bat*", "*.chm*", "*.cmd*", "*.hta*", "*.htm*", "*.html*", "*.js*", "*.…` |
| **Pua Radmin** | `any where process.pe.description:"Radmin Viewer" or process.pe.product:"Radmin Viewer" or process.pe.original_file_name:…` |
| **Pua Rcedit Execution** | `any where ((process.executable like~ ("*\\rcedit-x64.exe", "*\\rcedit-x86.exe")) or process.pe.description:"Edit resourc…` |
| **Pua Runxcmd** | `any where (process.command_line like~ ("* /account=system *", "* /account=ti *")) and process.command_line:"*/exec=*"` |
| **Pua Seatbelt** | `any where (process.executable:"*\\Seatbelt.exe" or process.pe.original_file_name:"Seatbelt.exe" or process.pe.descriptio…` |
| **Pua Webbrowserpassview** | `any where process.pe.description:"Web Browser Password Viewer" or process.executable:"*\\WebBrowserPassView.exe"` |
| **Pua Wsudo Susp Execution** | `any where (process.executable:"*\\wsudo.exe" or process.pe.original_file_name:"wsudo.exe" or process.pe.description:"Win…` |
| **Rar Compress Data** | `any where process.executable:"*\\rar.exe" and process.command_line:"* a *"` |
| **Rar Compression With Password** | `any where process.command_line:"* -hp*" and (process.command_line like~ ("* -m*", "* a *"))` |
| **Rasdial Execution** | `any where process.executable:"*rasdial.exe"` |
| **Reg Delete Safeboot** | `any where (process.executable:"*reg.exe" or process.pe.original_file_name:"reg.exe") and (process.command_line:"* delete…` |
| **Reg Delete Services** | `any where (process.executable:"*reg.exe" or process.pe.original_file_name:"reg.exe") and process.command_line:"* delete …` |
| **Reg Dumping Sensitive Hives** | `any where (process.executable:"*\\reg.exe" or process.pe.original_file_name:"reg.exe") and (process.command_line like~ (…` |
| **Reg Nolmhash** | `any where process.command_line:"*\\System\\CurrentControlSet\\Control\\Lsa*" and process.command_line:"*NoLMHash*" and p…` |
| **Regasm Regsvcs Uncommon Extension Execution** | `any where ((process.executable like~ ("*\\Regsvcs.exe", "*\\Regasm.exe")) or (process.pe.original_file_name like~ ("RegS…` |
| **Regedit Trustedinstaller** | `any where process.executable:"*\\regedit.exe" and (process.parent.executable like~ ("*\\TrustedInstaller.exe", "*\\Proce…` |
| **Regini Ads** | `any where (process.executable:"*\\regini.exe" or process.pe.original_file_name:"REGINI.EXE") and process.command_line:"S…` |
| **Regini Execution** | `any where (process.executable:"*\\regini.exe" or process.pe.original_file_name:"REGINI.EXE") and (not process.command_li…` |
| **Registry Cimprovider Dll Load** | `any where process.executable:"*\\register-cimprovider.exe" and (process.command_line:"*-path*" and process.command_line:…` |
| **Registry Ie Security Zone Protocol Defaults Downgrade** | `any where process.command_line:"*\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\ProtocolDefaults*" an…` |
| **Registry Install Reg Debugger Backdoor** | `any where process.command_line:"*\\CurrentVersion\\Image File Execution Options\\*" and (process.command_line like~ ("*s…` |
| **Registry Logon Script** | `any where process.command_line:"*UserInitMprLogonScript*"` |
| **Regsvr32 Dllregisterserver Exec** | `any where ((process.executable:"*\\regsvr32.exe" or process.pe.original_file_name:"REGSVR32.EXE") and (process.command_l…` |
| **Regsvr32 Http Ip Pattern** | `any where (process.executable:"*\\regsvr32.exe" or process.pe.original_file_name:"REGSVR32.EXE") and (process.command_li…` |
| **Regsvr32 Network Pattern** | `any where (process.executable:"*\\regsvr32.exe" or process.pe.original_file_name:"REGSVR32.EXE") and (process.command_li…` |
| **Regsvr32 Remote Share** | `any where (process.executable:"*\\regsvr32.exe" or process.pe.original_file_name:"\\REGSVR32.EXE") and process.command_l…` |
| **Regsvr32 Susp Exec Path 1** | `any where (process.executable:"*\\regsvr32.exe" or process.pe.original_file_name:"REGSVR32.EXE") and (process.command_li…` |
| **Regsvr32 Susp Exec Path 2** | `any where (process.executable:"*\\regsvr32.exe" or process.pe.original_file_name:"REGSVR32.EXE") and ((process.command_l…` |
| **Regsvr32 Susp Extensions** | `any where (process.executable:"*\\regsvr32.exe" or process.pe.original_file_name:"REGSVR32.EXE") and (process.command_li…` |
| **Regsvr32 Susp Parent** | `any where ((process.parent.executable like~ ("*\\cmd.exe", "*\\cscript.exe", "*\\mshta.exe", "*\\powershell_ise.exe", "*…` |
| **Regsvr32 Uncommon Extension** | `any where (process.executable:"*\\regsvr32.exe" or process.pe.original_file_name:"REGSVR32.EXE") and (not ((process.comm…` |
| **Remote Access Tools Action1 Code Exec And Remote Sessions** | `any where (process.parent.executable:"*\\action1_agent.exe" and process.executable:"*\\Windows\\Action1\\package_downloa…` |
| **Remote Access Tools Ammyy Admin Execution** | `any where process.executable:"*\\rundll32.exe" and process.command_line:"*AMMYY\\aa_nts.dll\",run*"` |
| **Remote Access Tools Anydesk** | `any where (process.executable like~ ("*\\AnyDesk.exe", "*\\AnyDeskMSI.exe")) or process.pe.description:"AnyDesk" or proc…` |
| **Remote Access Tools Anydesk Piped Password Via Cli** | `any where process.command_line:"*/c *" and process.command_line:"*echo *" and process.command_line:"*.exe --set-password…` |
| **Remote Access Tools Anydesk Silent Install** | `any where process.command_line:"*--install*" and process.command_line:"*--start-with-win*" and process.command_line:"*--…` |
| **Remote Access Tools Anydesk Susp Exec** | `any where ((process.executable like~ ("*\\AnyDesk.exe", "*\\AnyDeskMSI.exe")) or process.pe.description:"AnyDesk" or pro…` |
| **Remote Access Tools Anyviewer Shell Exec** | `any where process.parent.executable:"*\\AVCore.exe" and process.parent.command_line:"*AVCore.exe\" -d*" and process.exec…` |
| **Remote Access Tools Gotoopener** | `any where process.pe.description:"GoTo Opener" or process.pe.product:"GoTo Opener" or process.pe.company:"LogMeIn, Inc."` |
| **Remote Access Tools Logmein** | `any where process.pe.description:"LMIGuardianSvc" or process.pe.product:"LMIGuardianSvc" or process.pe.company:"LogMeIn,…` |
| **Remote Access Tools Meshagent Exec** | `any where process.parent.executable:"*\\meshagent.exe" and (process.executable like~ ("*\\cmd.exe", "*\\powershell.exe",…` |
| **Remote Access Tools Netsupport** | `any where process.pe.description:"NetSupport Client Configurator" or process.pe.product:"NetSupport Remote Control" or p…` |
| **Remote Access Tools Screenconnect** | `any where process.pe.description:"ScreenConnect Service" or process.pe.product:"ScreenConnect" or process.pe.company:"Sc…` |
| **Remote Access Tools Screenconnect Child Proc** | `any where process.parent.executable:"*\\ScreenConnect.ClientService.exe"` |
| **Remote Access Tools Screenconnect Installation Cli Param** | `any where process.command_line:"*e=Access&*" and process.command_line:"*y=Guest&*" and process.command_line:"*&p=*" and …` |
| **Remote Access Tools Simple Help** | `any where (process.executable like~ ("*\\JWrapper-Remote Access\\*", "*\\JWrapper-Remote Support\\*")) and process.execu…` |
| **Remote Access Tools Teamviewer Incoming Connection** | `any where process.executable:"TeamViewer_Desktop.exe" and process.parent.executable:"TeamViewer_Service.exe" and process…` |
| **Remote Access Tools Ultraviewer** | `any where process.pe.product:"UltraViewer" or process.pe.company:"DucFabulous Co,ltd" or process.pe.original_file_name:"…` |
| **Renamed Autohotkey** | `any where (process.pe.product:"*AutoHotkey*" or process.pe.description:"*AutoHotkey*" or (process.pe.original_file_name …` |
| **Renamed Binary** | `any where (process.pe.original_file_name like~ ("Cmd.Exe", "CONHOST.EXE", "7z.exe", "7za.exe", "WinRAR.exe", "wevtutil.e…` |
| **Renamed Boinc** | `any where process.pe.original_file_name:"BOINC.exe" and (not process.executable:"*\\BOINC.exe")` |
| **Renamed Browsercore** | `any where process.pe.original_file_name:"BrowserCore.exe" and (not process.executable:"*\\BrowserCore.exe")` |
| **Renamed Gpg4Win** | `any where process.pe.original_file_name:"gpg.exe" and (not (process.executable like~ ("*\\gpg.exe", "*\\gpg2.exe")))` |
| **Renamed Jusched** | `any where (process.pe.description like~ ("Java Update Scheduler", "Java(TM) Update Scheduler")) and (not process.executa…` |
| **Renamed Mavinject** | `any where (process.pe.original_file_name like~ ("mavinject32.exe", "mavinject64.exe")) and (not (process.executable like…` |
| **Renamed Nircmd** | `any where process.pe.original_file_name:"NirCmd.exe" and (not (process.executable like~ ("*\\nircmd.exe", "*\\nircmdc.ex…` |
| **Renamed Office Processes** | `any where ((process.pe.original_file_name like~ ("Excel.exe", "MSACCESS.EXE", "MSPUB.EXE", "OneNote.exe", "OneNoteM.exe"…` |
| **Renamed Pingcastle** | `any where ((process.pe.original_file_name like~ ("PingCastleReporting.exe", "PingCastleCloud.exe", "PingCastle.exe")) or…` |
| **Renamed Pressanykey** | `any where process.pe.original_file_name:"Microsoft.NodejsTools.PressAnyKey.exe" and (not process.executable:"*\\Microsof…` |
| **Renamed Rundll32 Dllregisterserver** | `any where process.command_line:"*DllRegisterServer*" and (not process.executable:"*\\rundll32.exe")` |
| **Renamed Sysinternals Debugview** | `any where process.pe.product:"Sysinternals DebugView" and (not (process.pe.original_file_name:"Dbgview.exe" and process.…` |
| **Renamed Sysinternals Procdump** | `any where (process.pe.original_file_name:"procdump" or ((process.command_line like~ ("* -ma *", "* /ma *", "* –ma *", "*…` |
| **Renamed Sysinternals Sdelete** | `any where process.pe.original_file_name:"sdelete.exe" and (not (process.executable like~ ("*\\sdelete.exe", "*\\sdelete6…` |
| **Renamed Vmnat** | `any where process.pe.original_file_name:"vmnat.exe" and (not process.executable:"*vmnat.exe")` |
| **Ruby Inline Command Execution** | `any where (process.executable:"*\\ruby.exe" or process.pe.original_file_name:"ruby.exe") and process.command_line:"* -e*…` |
| **Rundll32 Ads Stored Dll Execution** | `any where (process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE") and process.command_lin…` |
| **Rundll32 By Ordinal** | `any where ((process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE") and (process.command_l…` |
| **Rundll32 Dllregisterserver** | `any where ((process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE") and process.command_li…` |
| **Rundll32 Inline Vbs** | `any where process.command_line:"*rundll32.exe*" and process.command_line:"*Execute*" and process.command_line:"*RegRead*…` |
| **Rundll32 Installscreensaver** | `any where (process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE") and process.command_lin…` |
| **Rundll32 Keymgr** | `any where (process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE") and (process.command_li…` |
| **Rundll32 Mshtml Runhtmlapplication** | `any where (process.command_line:"*\\..\\*" and process.command_line:"*mshtml*") and (process.command_line like~ ("*#135*…` |
| **Rundll32 No Params** | `any where (process.command_line like~ ("*\\rundll32.exe", "*\\rundll32.exe\"", "*\\rundll32")) and (not (process.parent.…` |
| **Rundll32 Parent Explorer** | `any where (process.parent.executable:"*\\explorer.exe" and (process.executable:"*\\rundll32.exe" or process.pe.original_…` |
| **Rundll32 Process Dump Via Comsvcs** | `any where ((process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE" or process.command_line…` |
| **Rundll32 Registered Com Objects** | `any where (process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE") and ((process.command_l…` |
| **Rundll32 Setupapi Installhinfsection** | `any where process.executable:"*\\runonce.exe" and process.parent.executable:"*\\rundll32.exe" and (process.parent.comman…` |
| **Rundll32 Shell32 Susp Execution** | `any where (process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE") and ((process.command_l…` |
| **Rundll32 Shelldispatch Potential Abuse** | `any where (process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE") and process.command_lin…` |
| **Rundll32 Spawn Explorer** | `any where (process.parent.executable:"*\\rundll32.exe" and process.executable:"*\\explorer.exe") and (not process.parent…` |
| **Rundll32 Susp Activity** | `any where ((process.command_line:"*javascript:*" and process.command_line:"*.RegisterXLL*") or (process.command_line:"*u…` |
| **Rundll32 Susp Control Dll Load** | `any where (process.parent.executable:"*\\System32\\control.exe" and (process.executable:"*\\rundll32.exe" or process.pe.…` |
| **Rundll32 Susp Shellexec Execution** | `any where process.command_line:"*ShellExec_RunDLL*" and (process.command_line like~ ("*\\Desktop\\*", "*\\Temp\\*", "*\\…` |
| **Rundll32 Susp Shimcache Flush** | `any where ((process.command_line:"*rundll32*" and process.command_line:"*apphelp.dll*") and (process.command_line like~ …` |
| **Rundll32 Sys** | `any where process.command_line:"*rundll32.exe*" and (process.command_line like~ ("*.sys,*", "*.sys *"))` |
| **Rundll32 Udl Exec** | `any where process.parent.executable:"*\\explorer.exe" and (process.executable:"*\\rundll32.exe" or process.pe.original_f…` |
| **Rundll32 Unc Path** | `any where (process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE" or process.command_line:…` |
| **Rundll32 Uncommon Dll Extension** | `any where (process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE") and (not ((?process.com…` |
| **Rundll32 User32 Dll** | `any where (process.executable:"*\\rundll32.exe" or process.pe.original_file_name:"RUNDLL32.EXE") and process.parent.exec…` |
| **Rundll32 Without Parameters** | `any where process.command_line like~ ("rundll32.exe", "rundll32")` |
| **Runonce Execution** | `any where (process.executable:"*\\runonce.exe" or process.pe.description:"Run Once Wrapper") and (process.command_line l…` |
| **Sc New Kernel Driver** | `any where (process.executable:"*\\sc.exe" and (process.command_line like~ ("*create*", "*config*")) and (process.command…` |
| **Schtasks Change** | `any where (process.executable:"*\\schtasks.exe" and (process.command_line:"* /Change *" and process.command_line:"* /TN …` |
| **Schtasks Schedule Via Masqueraded Xml File** | `any where ((process.executable:"*\\schtasks.exe" or process.pe.original_file_name:"schtasks.exe") and (process.command_l…` |
| **Sdbinst Susp Extension** | `any where (process.executable:"*\\sdbinst.exe" or process.pe.original_file_name:"sdbinst.exe") and (not (process.command…` |
| **Sdclt Child Process** | `any where process.parent.executable:"*\\sdclt.exe"` |
| **Secedit Execution** | `any where (process.executable:"*\\secedit.exe" or process.pe.original_file_name:"SeCEdit") and ((process.command_line:"*…` |
| **Setres Uncommon Child Process** | `any where (process.parent.executable:"*\\setres.exe" and process.executable:"*\\choice*") and (not (process.executable l…` |
| **Setup16 Custom Lst Execution** | `any where (process.parent.executable:"C:\\Windows\\SysWOW64\\setup16.exe" and process.parent.command_line:"* -m *") and …` |
| **Shutdown Execution** | `any where process.executable:"*\\shutdown.exe" and (process.command_line like~ ("*/r *", "*/s *"))` |
| **Shutdown Logoff** | `any where process.executable:"*\\shutdown.exe" and process.command_line:"*/l*"` |
| **Soundrecorder Audio Capture** | `any where process.executable:"*\\SoundRecorder.exe" and process.command_line:"*/FILE*"` |
| **Sqlite Firefox Gecko Profile Data** | `any where (process.pe.product:"SQLite" or (process.executable like~ ("*\\sqlite.exe", "*\\sqlite3.exe"))) and (process.c…` |
| **Squirrel Proxy Execution** | `any where ((process.executable like~ ("*\\squirrel.exe", "*\\update.exe")) and (process.command_line like~ ("*--processS…` |
| **Ssh Port Forward** | `any where process.executable:"*\\ssh.exe" and process.command_line like~ ("* -R *", "* /R *", "* –R *", "* —R *", "* ―R …` |
| **Ssm Agent Abuse** | `any where process.executable:"*\\amazon-ssm-agent.exe" and (process.command_line:"*-register *" and process.command_line…` |
| **Stordiag Susp Child Process** | `any where (process.parent.executable:"*\\stordiag.exe" and (process.executable like~ ("*\\schtasks.exe", "*\\systeminfo.…` |
| **Susp 16Bit Application** | `any where process.executable like~ ("*\\ntvdm.exe", "*\\csrstub.exe")` |
| **Susp Add User Remote Desktop Group** | `any where ((process.command_line:"*localgroup *" and process.command_line:"* /add*") or (process.command_line:"*Add-Loca…` |
| **Susp Always Install Elevated Windows Installer** | `any where (((process.executable:"*\\Windows\\Installer\\*" and process.executable:"*msi*") and process.executable:"*tmp"…` |
| **Susp Arbitrary Shell Execution Via Settingcontent** | `any where process.command_line:"*.SettingContent-ms*" and (not process.command_line:"*immersivecontrolpanel*")` |
| **Susp Archiver Iso Phishing** | `any where (process.parent.executable like~ ("*\\Winrar.exe", "*\\7zFM.exe", "*\\peazip.exe")) and (process.executable li…` |
| **Susp Automated Collection** | `any where (process.command_line like~ ("*.doc*", "*.docx*", "*.xls*", "*.xlsx*", "*.ppt*", "*.pptx*", "*.rtf*", "*.pdf*"…` |
| **Susp Bad Opsec Sacrificial Processes** | `any where ((process.executable:"*\\WerFault.exe" and process.command_line:"*WerFault.exe") or (process.executable:"*\\ru…` |
| **Susp Browser Launch From Document Reader Process** | `any where ((process.parent.executable like~ ("*Acrobat Reader*", "*Microsoft Office*", "*PDF Reader*")) and (process.exe…` |
| **Susp Child Process As System ** | `any where ((winlog.event_data.ParentUser like~ ("*AUTHORI*", "*AUTORI*")) and (winlog.event_data.ParentUser like~ ("*\\N…` |
| **Susp Compression Params** | `any where ((process.pe.original_file_name like~ ("7z*.exe", "*rar.exe", "*Command*Line*RAR*")) and (process.command_line…` |
| **Susp Copy Browser Data** | `any where ((process.command_line like~ ("*copy-item*", "*copy *", "*cpi *", "* cp *", "*move *", "*move-item*", "* mi *"…` |
| **Susp Copy System Dir Lolbin** | `any where ((process.executable:"*\\cmd.exe" and process.command_line:"*copy *") or ((process.executable like~ ("*\\power…` |
| **Susp Crypto Mining Monero** | `any where (process.command_line like~ ("* --cpu-priority=*", "*--donate-level=0*", "* -o pool.*", "* --nicehash*", "* --…` |
| **Susp Double Extension** | `any where (process.executable like~ ("*   .exe", "*______.exe", "*.doc.exe", "*.doc.js", "*.docx.exe", "*.docx.js", "*.g…` |
| **Susp Double Extension Parent** | `any where (process.parent.executable like~ ("*.doc.lnk", "*.docx.lnk", "*.xls.lnk", "*.xlsx.lnk", "*.ppt.lnk", "*.pptx.l…` |
| **Susp Dumpstack Log Evasion** | `any where process.executable:"*\\DumpStack.log" or process.command_line:"* -o DumpStack.log*"` |
| **Susp Electron App Children** | `any where (process.parent.executable like~ ("*\\chrome.exe", "*\\discord.exe", "*\\GitHubDesktop.exe", "*\\keybase.exe",…` |
| **Susp Emoji Usage In Cli 1** | `any where process.command_line like~ ("*😀*", "*😃*", "*😄*", "*😁*", "*😆*", "*😅*", "*😂*", "*🤣*", "*🥲*", "*🥹*", "*☺️*", "*😊*…` |
| **Susp Emoji Usage In Cli 2** | `any where process.command_line like~ ("*🤷🏼*", "*🤷🏼‍♂️*", "*🙎🏼‍♀️*", "*🙎🏼*", "*🙎🏼‍♂️*", "*🙍🏼‍♀️*", "*🙍🏼*", "*🙍🏼‍♂️*", "*💇…` |
| **Susp Emoji Usage In Cli 3** | `any where process.command_line like~ ("*🦆*", "*🦅*", "*🦉*", "*🦇*", "*🐺*", "*🐗*", "*🐴*", "*🦄*", "*🐝*", "*🪱*", "*🐛*", "*🦋*"…` |
| **Susp Emoji Usage In Cli 4** | `any where process.command_line like~ ("*🔸*", "*🔹*", "*🔶*", "*🔷*", "*🔳*", "*🔲*", "*▪️*", "*▫️*", "*◾️*", "*◽️*", "*◼️*", …` |
| **Susp Etw Modification Cmdline** | `any where process.command_line like~ ("*COMPlus_ETWEnabled*", "*COMPlus_ETWFlags*")` |
| **Susp Etw Trace Evasion** | `any where (process.command_line:"*cl*" and process.command_line:"*/Trace*") or (process.command_line:"*clear-log*" and p…` |
| **Susp Execution From Guid Folder Names** | `any where ((process.command_line like~ ("*\\AppData\\Roaming\\*", "*\\AppData\\Local\\Temp\\*")) and (process.command_li…` |
| **Susp Execution Path Webserver** | `any where (process.executable like~ ("*\\wwwroot\\*", "*\\wmpub\\*", "*\\htdocs\\*")) and (not ((process.executable like…` |
| **Susp File Permission Modifications** | `any where (((process.executable like~ ("*\\cacls.exe", "*\\icacls.exe", "*\\net.exe", "*\\net1.exe")) and (process.comma…` |
| **Susp Gather Network Info Execution** | `any where process.command_line:"*gatherNetworkInfo.vbs*" and (not (process.executable like~ ("*\\cscript.exe", "*\\wscri…` |
| **Susp Hidden Dir Index Allocation** | `any where process.command_line:"*::$index_allocation*"` |
| **Susp Image Missing** | `any where (not process.executable:"*\\*") and (not ((?process.executable == null) or (process.executable like~ ("-", "")…` |
| **Susp Inline Win Api Access** | `any where (process.command_line like~ ("*AddSecurityPackage*", "*AdjustTokenPrivileges*", "*Advapi32*", "*CloseHandle*",…` |
| **Susp Network Sniffing** | `any where (process.executable:"*\\tshark.exe" and process.command_line:"*-i*") or process.executable:"*\\windump.exe"` |
| **Susp No Image Name** | `any where process.executable:"*\\.exe"` |
| **Susp Ntds** | `any where (((process.executable like~ ("*\\NTDSDump.exe", "*\\NTDSDumpEx.exe")) or (process.command_line:"*ntds.dit*" an…` |
| **Susp Nteventlogfile Usage** | `any where process.command_line:"*Win32_NTEventlogFile*" and (process.command_line like~ ("*.BackupEventlog(*", "*.Change…` |
| **Susp Ntfs Short Name Path Use Cli** | `any where (process.command_line like~ ("*~1\\*", "*~2\\*")) and (not ((process.parent.executable like~ ("C:\\Windows\\Sy…` |
| **Susp Ntfs Short Name Path Use Image** | `any where (process.executable like~ ("*~1\\*", "*~2\\*")) and (not ((process.parent.executable like~ ("C:\\Windows\\Syst…` |
| **Susp Ntfs Short Name Use Cli** | `any where (process.command_line like~ ("*~1.exe*", "*~1.bat*", "*~1.msi*", "*~1.vbe*", "*~1.vbs*", "*~1.dll*", "*~1.ps1*…` |
| **Susp Ntfs Short Name Use Image** | `any where (process.executable like~ ("*~1.bat*", "*~1.dll*", "*~1.exe*", "*~1.hta*", "*~1.js*", "*~1.msi*", "*~1.ps1*", …` |
| **Susp Parents** | `any where (process.parent.executable like~ ("*\\minesweeper.exe", "*\\winver.exe", "*\\bitsadmin.exe")) or ((process.par…` |
| **Susp Progname** | `any where ((process.executable like~ ("*\\CVE-202*", "*\\CVE202*")) or (process.executable like~ ("*\\poc.exe", "*\\arti…` |
| **Susp Right To Left Override** | `any where process.command_line like~ ("*\\u202e*", "*[U+202E]*", "*‮*")` |
| **Susp Use Of Te Bin** | `any where process.executable:"*\\te.exe" or process.parent.executable:"*\\te.exe" or process.pe.original_file_name:"\\te…` |
| **Susp Use Of Vsjitdebugger Bin** | `any where process.parent.executable:"*\\vsjitdebugger.exe" and (not (process.executable like~ ("*\\vsimmersiveactivatehe…` |
| **Susp Weak Or Abused Passwords** | `any where process.command_line like~ ("*123456789*", "*123123qwE*", "*Asd123.aaaa*", "*Decryptme*", "*P@ssw0rd!*", "*Pas…` |
| **Svchost Execution With No Cli Flags** | `any where (process.command_line:"*svchost.exe" and process.executable:"*\\svchost.exe") and (not ((process.parent.execut…` |
| **Svchost Masqueraded Execution** | `any where process.executable:"*\\svchost.exe" and (not ((process.executable like~ ("C:\\Windows\\System32\\svchost.exe",…` |
| **Sysinternals Accesschk Check Permissions** | `any where (process.pe.product:"*AccessChk" or process.pe.description:"*Reports effective permissions*" or (process.execu…` |
| **Sysinternals Eula Accepted** | `any where process.command_line like~ ("* -accepteula*", "* /accepteula*", "* –accepteula*", "* —accepteula*", "* ―accept…` |
| **Sysinternals Livekd Execution** | `any where (process.executable like~ ("*\\livekd.exe", "*\\livekd64.exe")) or process.pe.original_file_name:"livekd.exe"` |
| **Sysinternals Livekd Kernel Memory Dump** | `any where ((process.executable like~ ("*\\livekd.exe", "*\\livekd64.exe")) or process.pe.original_file_name:"livekd.exe"…` |
| **Sysinternals Psexesvc As System** | `any where process.parent.executable:"C:\\Windows\\PSEXESVC.exe" and (user.name like~ ("*AUTHORI*", "*AUTORI*"))` |
| **Sysinternals Psservice** | `any where process.pe.original_file_name:"psservice.exe" or (process.executable like~ ("*\\PsService.exe", "*\\PsService6…` |
| **Sysinternals Pssuspend Execution** | `any where process.pe.original_file_name:"pssuspend.exe" or (process.executable like~ ("*\\pssuspend.exe", "*\\pssuspend6…` |
| **Sysinternals Pssuspend Susp Execution** | `any where (process.pe.original_file_name:"pssuspend.exe" or (process.executable like~ ("*\\pssuspend.exe", "*\\pssuspend…` |
| **Sysinternals Sysmon Config Update** | `any where ((process.executable like~ ("*\\Sysmon64.exe", "*\\Sysmon.exe")) or process.pe.description:"System activity mo…` |
| **Sysinternals Sysmon Uninstall** | `any where ((process.executable like~ ("*\\Sysmon64.exe", "*\\Sysmon.exe")) or process.pe.description:"System activity mo…` |
| **Sysinternals Tools Masquerading** | `any where ((process.executable like~ ("*\\accesschk.exe", "*\\accesschk64.exe", "*\\AccessEnum.exe", "*\\ADExplorer.exe"…` |
| **Sysprep Appdata** | `any where process.executable:"*\\sysprep.exe" and process.command_line:"*\\AppData\\*"` |
| **Systemsettingsadminflows Turn On Dev Features** | `any where (process.executable:"*\\SystemSettingsAdminFlows.exe" or process.pe.original_file_name:"SystemSettingsAdminFlo…` |
| **Takeown Recursive Own** | `any where process.executable:"*\\takeown.exe" and (process.command_line:"*/f *" and process.command_line:"*/r*")` |
| **Tapinstall Execution** | `any where process.executable:"*\\tapinstall.exe" and (not ((process.executable like~ ("*:\\Program Files\\Avast Software…` |
| **Tar Compression** | `any where (process.executable:"*\\tar.exe" or process.pe.original_file_name:"bsdtar") and (process.command_line like~ ("…` |
| **Tar Extraction** | `any where (process.executable:"*\\tar.exe" or process.pe.original_file_name:"bsdtar") and process.command_line:"*-x*"` |
| **Tasklist Basic Execution** | `any where process.command_line:"*tasklist*" or process.executable:"*\\tasklist.exe" or process.pe.original_file_name:"ta…` |
| **Taskmgr Localsystem** | `any where (user.name like~ ("*AUTHORI*", "*AUTORI*")) and process.executable:"*\\taskmgr.exe"` |
| **Taskmgr Susp Child Process** | `any where process.parent.executable:"*\\taskmgr.exe" and (not (process.executable like~ ("*:\\Windows\\System32\\mmc.exe…` |
| **Tpmvscmgr Add Virtual Smartcard** | `any where (process.executable:"*\\tpmvscmgr.exe" and process.pe.original_file_name:"TpmVscMgr.exe") and process.command_…` |
| **Tscon Localsystem** | `any where (user.name like~ ("*AUTHORI*", "*AUTORI*")) and process.executable:"*\\tscon.exe"` |
| **Ultravnc** | `any where process.pe.description:"VNCViewer" or process.pe.product:"UltraVNC VNCViewer" or process.pe.company:"UltraVNC"…` |
| **Ultravnc Susp Execution** | `any where process.command_line:"*-autoreconnect *" and process.command_line:"*-connect *" and process.command_line:"*-id…` |
| **Uninstall Crowdstrike Falcon** | `any where process.command_line:"*\\WindowsSensor.exe*" and process.command_line:"* /uninstall*" and process.command_line…` |
| **Virtualbox Execution** | `any where (process.command_line like~ ("*VBoxRT.dll,RTR3Init*", "*VBoxC.dll*", "*VBoxDrv.sys*")) or (process.command_lin…` |
| **Virtualbox Vboxdrvinst Execution** | `any where process.executable:"*\\VBoxDrvInst.exe" and (process.command_line:"*driver*" and process.command_line:"*execut…` |
| **Vmware Vmtoolsd Susp Child Process** | `any where (process.parent.executable:"*\\vmtoolsd.exe" and ((process.executable like~ ("*\\cmd.exe", "*\\cscript.exe", "…` |
| **Vscode Child Processes Anomalies** | `any where process.parent.executable:"*\\code.exe" and ((process.executable like~ ("*\\calc.exe", "*\\regsvr32.exe", "*\\…` |
| **Vscode Tunnel Renamed Execution** | `any where ((((?process.pe.original_file_name == null) and process.command_line:"*.exe tunnel") or (process.command_line:…` |
| **Vslsagent Agentextensionpath Load** | `any where (process.executable:"*\\vsls-agent.exe" and process.command_line:"*--agentExtensionPath*") and (not process.co…` |
| **W32Tm** | `any where (process.executable:"*\\w32tm.exe" or process.pe.original_file_name:"w32time.dll") and (process.command_line:"…` |
| **Wab Execution From Non Default Location** | `any where (process.executable like~ ("*\\wab.exe", "*\\wabmig.exe")) and (not (process.executable like~ ("C:\\Windows\\W…` |
| **Wermgr Susp Exec Location** | `any where process.executable:"*\\wermgr.exe" and (not (process.executable like~ ("C:\\Windows\\System32\\*", "C:\\Window…` |
| **Windows Terminal Susp Children** | `any where ((process.parent.executable like~ ("*\\WindowsTerminal.exe", "*\\wt.exe")) and ((process.executable like~ ("*\…` |
| **Winrm Execution Via Scripting Api Winrm Vbs** | `any where (process.executable:"*\\cscript.exe" or process.pe.original_file_name:"cscript.exe") and (process.command_line…` |
| **Winzip Password Compression** | `any where (process.command_line like~ ("*winzip.exe*", "*winzip64.exe*")) and process.command_line:"*-s\"*" and (process…` |
| **Wscript Cscript Susp Child Processes** | `any where (process.parent.executable like~ ("*\\wscript.exe", "*\\cscript.exe")) and (process.executable:"*\\rundll32.ex…` |
| **Wscript Cscript Uncommon Extension Exec** | `any where ((process.pe.original_file_name like~ ("wscript.exe", "cscript.exe")) or (process.executable like~ ("*\\wscrip…` |
| **Wsl Arbitrary Command Execution** | `any where ((process.executable:"*\\wsl.exe" or process.pe.original_file_name:"wsl.exe") and (process.command_line like~ …` |
| **Wsl Windows Binaries Execution** | `any where process.executable:"SigmaRegularExpression(regexp=SigmaString(['[a-zA-Z]:\\\\']), flags=set())" and process.wo…` |
| **Wuauclt Dll Loading** | `any where ((process.executable:"*\\wuauclt.exe" or process.pe.original_file_name:"wuauclt.exe") and (process.command_lin…` |
| **Wusa Cab Files Extraction** | `any where process.executable:"*\\wusa.exe" and process.command_line:"*/extract:*"` |
| **Wusa Cab Files Extraction From Susp Paths** | `any where (process.executable:"*\\wusa.exe" and process.command_line:"*/extract:*") and (process.command_line like~ ("*:…` |
| **Wusa Susp Parent Execution** | `any where process.executable:"*\\wusa.exe" and ((process.parent.executable like~ ("*:\\Perflogs\\*", "*:\\Users\\Public\…` |
| **Registry Add Malware Netwire** | `any where registry.path:"*\\software\\NetWire*"` |
| **Registry Add Malware Ursnif** | `any where registry.path:"*\\Software\\AppDataLow\\Software\\Microsoft\\3A861D62-51E0-7C9D-AB0E-15700F2219A4"` |
| **Registry Delete Enable Windows Recall** | `any where winlog.event_data.EventType:"DeleteValue" and registry.path:"*\\Microsoft\\Windows\\WindowsAI\\DisableAIDataAn…` |
| **Registry Delete Mstsc History Cleared** | `any where (winlog.event_data.EventType:"DeleteValue" and registry.path:"*\\Microsoft\\Terminal Server Client\\Default\\M…` |
| **Registry Delete Removal Amsi Registry Key** | `any where (registry.path like~ ("*{2781761E-28E0-4109-99FE-B9D127C57AFE}", "*{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}")) a…` |
| **Registry Delete Schtasks Hide Task Via Index Value Removal** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\*" and registry.…` |
| **Registry Delete Schtasks Hide Task Via Sd Value Removal** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\*" and registry.…` |
| **Registry Event Cmstp Execution By Registry** | `any where registry.path:"*\\cmmgr32.exe*"` |
| **Registry Event Hack Wce Reg** | `any where registry.path:"*Services\\WCESERVICE\\Start*"` |
| **Registry Event Hybridconnectionmgr Svc Installation** | `any where registry.path:"*\\Services\\HybridConnectionManager*" or (winlog.event_data.EventType:"SetValue" and winlog.ev…` |
| **Registry Event Mal Azorult** | `any where (event.code like~ ("12", "13")) and registry.path:"*SYSTEM\\*" and registry.path:"*\\services\\localNETService…` |
| **Registry Event Malware Flowcloud Markers** | `any where registry.path like~ ("*\\HARDWARE\\{2DB80286-1784-48b5-A751-B6ED1F490303}*", "*\\HARDWARE\\{804423C2-F490-4ac3…` |
| **Registry Event Malware Qakbot Registry** | `any where registry.path:"*\\Software\\firm\\soft\\Name"` |
| **Registry Event Malware Snake Covert Store Key** | `any where registry.path:"*SECURITY\\Policy\\Secrets\\n"` |
| **Registry Event Modify Screensaver Binary Path** | `any where registry.path:"*\\Control Panel\\Desktop\\SCRNSAVE.EXE" and (not (process.executable like~ ("*\\rundll32.exe",…` |
| **Registry Event Office Trust Record Modification** | `any where registry.path:"*\\Security\\Trusted Documents\\TrustRecords*"` |
| **Registry Event Portproxy Registry Key** | `any where registry.path:"*\\Services\\PortProxy\\v4tov4\\tcp\\*"` |
| **Registry Event Redmimicry Winnti Reg** | `any where registry.path:"*HKLM\\SOFTWARE\\Microsoft\\HTMLHelp\\data*"` |
| **Registry Event Runkey Winekey** | `any where registry.path:"*Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backup Mgr"` |
| **Registry Event Ssp Added Lsa Config** | `any where (registry.path like~ ("*\\Control\\Lsa\\Security Packages", "*\\Control\\Lsa\\OSConfig\\Security Packages")) a…` |
| **Registry Event Stickykey Like Backdoor** | `any where registry.path like~ ("*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.…` |
| **Registry Set Add Load Service In Safe Mode** | `any where ((registry.path like~ ("*\\Control\\SafeBoot\\Minimal\\*", "*\\Control\\SafeBoot\\Network\\*")) and registry.p…` |
| **Registry Set Amsi Com Hijack** | `any where registry.path:"*\\CLSID\\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\\InProcServer32\\(Default)" and (not winlog.ev…` |
| **Registry Set Asep Reg Keys Modification Common** | `any where (registry.path like~ ("*\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows CE Services\\AutoStart*", "*\\Software\\Wo…` |
| **Registry Set Asep Reg Keys Modification Currentversion** | `any where (registry.path:"*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion*" and (registry.path like~ ("*\\ShellServiceOb…` |
| **Registry Set Asep Reg Keys Modification Currentversion Nt** | `any where (registry.path:"*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion*" and (registry.path like~ ("*\\Winlogon\\V…` |
| **Registry Set Asep Reg Keys Modification Internet Explorer** | `any where (registry.path like~ ("*\\Software\\Wow6432Node\\Microsoft\\Internet Explorer*", "*\\Software\\Microsoft\\Inte…` |
| **Registry Set Asep Reg Keys Modification Office** | `any where ((registry.path like~ ("*\\Software\\Wow6432Node\\Microsoft\\Office*", "*\\Software\\Microsoft\\Office*")) and…` |
| **Registry Set Asep Reg Keys Modification Wow6432Node** | `any where (registry.path:"*\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion*" and (registry.path like~ ("*\\S…` |
| **Registry Set Asep Reg Keys Modification Wow6432Node Classes** | `any where registry.path:"*\\Software\\Wow6432Node\\Classes*" and (registry.path like~ ("*\\Folder\\ShellEx\\ExtShellFold…` |
| **Registry Set Bginfo Custom Db** | `any where registry.path:"*\\Software\\Winternals\\BGInfo\\Database"` |
| **Registry Set Bginfo Custom Vbscript** | `any where registry.path:"*\\Software\\Winternals\\BGInfo\\UserFields\\*" and winlog.event_data.Details:"4*"` |
| **Registry Set Change Security Zones** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\*" and (n…` |
| **Registry Set Change Sysmon Driver Altitude** | `any where registry.path:"*\\Services\\*" and registry.path:"*\\Instances\\Sysmon Instance\\Altitude"` |
| **Registry Set Change Winevt Channelaccess** | `any where (registry.path:"*\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\*" and registry.path:"*\\ChannelAcces…` |
| **Registry Set Chrome Extension** | `any where (registry.path:"*Software\\Wow6432Node\\Google\\Chrome\\Extensions*" and registry.path:"*update_url") and (reg…` |
| **Registry Set Clickonce Trust Prompt** | `any where registry.path:"*\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel\\*" and (registry…` |
| **Registry Set Comhijack Sdclt** | `any where registry.path:"*\\Software\\Classes\\Folder\\shell\\open\\command\\DelegateExecute*"` |
| **Registry Set Desktop Background Change** | `any where (registry.path like~ ("*Control Panel\\Desktop*", "*CurrentVersion\\Policies\\ActiveDesktop*", "*CurrentVersio…` |
| **Registry Set Dhcp Calloutdll** | `any where registry.path like~ ("*\\Services\\DHCPServer\\Parameters\\CalloutDlls", "*\\Services\\DHCPServer\\Parameters\…` |
| **Registry Set Disallowrun Execution** | `any where registry.path:"*Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun" and winlog.even…` |
| **Registry Set Dns Server Level Plugin Dll** | `any where registry.path:"*\\services\\DNS\\Parameters\\ServerLevelPluginDll"` |
| **Registry Set Enable Anonymous Connection** | `any where registry.path:"*\\Microsoft\\WBEM\\CIMOM\\AllowAnonymousCallback*" and winlog.event_data.Details:"DWORD (0x000…` |
| **Registry Set Enable Periodic Backup** | `any where registry.path:"*\\Control\\Session Manager\\Configuration Manager\\EnablePeriodicBackup" and winlog.event_data…` |
| **Registry Set Enable Windows Recall** | `any where registry.path:"*\\Software\\Policies\\Microsoft\\Windows\\WindowsAI\\DisableAIDataAnalysis" and winlog.event_d…` |
| **Registry Set Enabling Cor Profiler Env Variables** | `any where (registry.path like~ ("*\\COR_ENABLE_PROFILING", "*\\COR_PROFILER", "*\\CORECLR_ENABLE_PROFILING")) or registr…` |
| **Registry Set Enabling Turnoffcheck** | `any where registry.path:"*\\Policies\\Microsoft\\Windows\\ScriptedDiagnostics\\TurnOffCheck" and winlog.event_data.Detai…` |
| **Registry Set Fax Change Service User** | `any where registry.path:"HKLM\\System\\CurrentControlSet\\Services\\Fax\\ObjectName" and (not winlog.event_data.Details:…` |
| **Registry Set File Association Exefile** | `any where registry.path:"*Classes\\.*" and winlog.event_data.Details:"exefile"` |
| **Registry Set Hidden Extention** | `any where (registry.path:"*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\HideFileExt" and winlog.e…` |
| **Registry Set Hide Function User** | `any where ((registry.path like~ ("*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideClock", "*SOFTW…` |
| **Registry Set Hvci Disallowed Images** | `any where registry.path:"*\\Control\\CI\\*" and registry.path:"*\\HVCIDisallowedImages*"` |
| **Registry Set Ie Security Zone Protocol Defaults Downgrade** | `any where registry.path:"*\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\ProtocolDefaults*" and (regi…` |
| **Registry Set Ime Non Default Extension** | `any where (registry.path:"*\\Control\\Keyboard Layouts\\*" and registry.path:"*Ime File*") and (not winlog.event_data.De…` |
| **Registry Set Ime Suspicious Paths** | `any where (registry.path:"*\\Control\\Keyboard Layouts\\*" and registry.path:"*Ime File*") and ((winlog.event_data.Detai…` |
| **Registry Set Install Root Or Ca Certificat** | `any where (registry.path like~ ("*\\SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates\\*", "*\\SOFTWARE\\Polic…` |
| **Registry Set Legalnotice Susp Message** | `any where (registry.path like~ ("*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption*"…` |
| **Registry Set Mal Blue Mockingbird** | `any where registry.path:"*\\CurrentControlSet\\Services\\wercplsupport\\Parameters\\ServiceDll"` |
| **Registry Set Malware Coldsteel Created Users** | `any where (registry.path:"*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-*" and registry.path…` |
| **Registry Set Malware Small Sieve Evasion Typo** | `any where registry.path:"*\\Microsoft\\Windows\\CurrentVersion\\Run\\*" and (registry.path:"*Microsift*" or winlog.event…` |
| **Registry Set Net Cli Ngenassemblyusagelog** | `any where registry.path:"*SOFTWARE\\Microsoft\\.NETFramework\\NGenAssemblyUsageLog"` |
| **Registry Set New Application Appcompat** | `any where registry.path:"*\\AppCompatFlags\\Compatibility Assistant\\Store\\*"` |
| **Registry Set Odbc Driver Registered** | `any where (registry.path:"*\\SOFTWARE\\ODBC\\ODBCINST.INI\\*" and registry.path:"*\\Driver") and (not (registry.path:"*\…` |
| **Registry Set Odbc Driver Registered Susp** | `any where registry.path:"*\\SOFTWARE\\ODBC\\ODBCINST.INI\\*" and (registry.path like~ ("*\\Driver", "*\\Setup")) and (wi…` |
| **Registry Set Office Outlook Enable Unsafe Client Mail Rules** | `any where registry.path:"*\\Outlook\\Security\\EnableUnsafeClientMailRules" and winlog.event_data.Details:"DWORD (0x0000…` |
| **Registry Set Office Trust Record Susp Location** | `any where registry.path:"*\\Security\\Trusted Documents\\TrustRecords*" and (registry.path like~ ("*/AppData/Local/Micro…` |
| **Registry Set Office Trusted Location** | `any where (registry.path:"*Security\\Trusted Locations\\Location*" and registry.path:"*\\Path") and (not ((process.execu…` |
| **Registry Set Office Trusted Location Uncommon** | `any where (registry.path:"*Security\\Trusted Locations\\Location*" and registry.path:"*\\Path") and (not ((process.execu…` |
| **Registry Set Optimize File Sharing Network** | `any where registry.path:"*\\Services\\LanmanServer\\Parameters\\MaxMpxCt"` |
| **Registry Set Provisioning Command Abuse** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\Provisioning\\Commands\\*"` |
| **Registry Set Pua Sysinternals Execution Via Eula** | `any where registry.path:"*\\EulaAccepted"` |
| **Registry Set Pua Sysinternals Renamed Execution Via Eula** | `any where ((registry.path like~ ("*\\Active Directory Explorer*", "*\\Handle*", "*\\LiveKd*", "*\\ProcDump*", "*\\Proces…` |
| **Registry Set Pua Sysinternals Susp Execution Via Eula** | `any where (registry.path like~ ("*\\Active Directory Explorer*", "*\\Handle*", "*\\LiveKd*", "*\\Process Explorer*", "*\…` |
| **Registry Set Runmru Command Execution** | `any where registry.path:"*\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU*" and (not registry.path:"*\\MRUList") …` |
| **Registry Set Runmru Susp Command Execution** | `any where registry.path:"*\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU*" and (((winlog.event_data.Details like…` |
| **Registry Set Scr File Executed By Rundll32** | `any where process.executable:"*\\rundll32.exe" and (registry.path:"*\\Control Panel\\Desktop\\SCRNSAVE.EXE*" and winlog.…` |
| **Registry Set Service Image Path User Controlled Folder** | `any where ((registry.path:"*ControlSet*" and registry.path:"*\\Services\\*") and registry.path:"*\\ImagePath" and (winlo…` |
| **Registry Set Set Nopolicies User** | `any where (registry.path like~ ("*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoLogOff", "*SOFTWAR…` |
| **Registry Set Special Accounts** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList*" and w…` |
| **Registry Set Susp Keyboard Layout Load** | `any where (registry.path like~ ("*\\Keyboard Layout\\Preload\\*", "*\\Keyboard Layout\\Substitutes\\*")) and (winlog.eve…` |
| **Registry Set Susp User Shell Folders** | `any where ((registry.path like~ ("*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders*", "*SOFTW…` |
| **Registry Set Suspicious Env Variables** | `any where registry.path:"*\\Environment\\*" and ((winlog.event_data.Details like~ ("powershell", "pwsh")) or (winlog.eve…` |
| **Registry Set System Lsa Nolmhash** | `any where registry.path:"*System\\CurrentControlSet\\Control\\Lsa\\NoLMHash" and winlog.event_data.Details:"DWORD (0x000…` |
| **Registry Set Terminal Server Suspicious** | `any where (registry.path like~ ("*\\fDenyTSConnections", "*\\fSingleSessionPerUser", "*\\UserAuthentication")) and winlo…` |
| **Registry Set Turn On Dev Features** | `any where (registry.path like~ ("*\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock*", "*\\Policies\\Microsoft\\Windo…` |
| **Registry Set Vbs Payload Stored** | `any where (registry.path:"*Software\\Microsoft\\Windows\\CurrentVersion*" and (winlog.event_data.Details like~ ("*vbscri…` |
| **Malware Blackbyte Privesc Registry** | `any where (registry.path like~ ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LocalAccountToken…` |
| **Registry Set Winget Enable Local Manifest** | `any where registry.path:"*\\AppInstaller\\EnableLocalManifestFiles" and winlog.event_data.Details:"DWORD (0x00000001)"` |
| **Registry Set Winlogon Allow Multiple Tssessions** | `any where registry.path:"*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AllowMultipleTSSessions" and winlog.event_d…` |
| **Registry Set Winlogon Notify Key** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\logon" and winlog.event_d…` |
| **Config Modification** | `any where winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:"16"` |
| **Config Modification Error** | `any where (winlog.event_data.Description like~ ("*Failed to open service configuration with error*", "*Failed to connect…` |
| **File Block Shredding** | `any where winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:"28"` |
| **Applocker Application Was Prevented From Running** | `any where (winlog.channel like~ ("Microsoft-Windows-AppLocker/MSI and Script", "Microsoft-Windows-AppLocker/EXE and DLL"…` |
| **Appxdeployment Server Applocker Block** | `any where winlog.channel:"Microsoft-Windows-AppXDeploymentServer/Operational" and event.code:"412"` |
| **Appxdeployment Server Appx Package Deployment Failed Signing Requirements** | `any where winlog.channel:"Microsoft-Windows-AppXDeploymentServer/Operational" and (event.code:"401" and winlog.event_dat…` |
| **Appxdeployment Server Appx Package In Staging Directory** | `any where winlog.channel:"Microsoft-Windows-AppXDeploymentServer/Operational" and (event.code:"854" and ((winlog.event_d…` |
| **Appxdeployment Server Mal Appx Names** | `any where winlog.channel:"Microsoft-Windows-AppXDeploymentServer/Operational" and ((event.code like~ ("400", "401")) and…` |
| **Appxdeployment Server Policy Block** | `any where winlog.channel:"Microsoft-Windows-AppXDeploymentServer/Operational" and (event.code like~ ("441", "442", "453"…` |
| **Appxdeployment Server Uncommon Package Locations** | `any where winlog.channel:"Microsoft-Windows-AppXDeploymentServer/Operational" and (event.code:"854" and (not ((winlog.ev…` |
| **Remove Application** | `any where winlog.channel:"Application" and (winlog.provider_name:"MsiInstaller" and (event.code like~ ("1034", "11724"))…` |
| **Capi2 Acquire Certificate Private Key** | `any where winlog.channel:"Microsoft-Windows-CAPI2/Operational" and event.code:"70"` |
| **Certificateservicesclient Lifecycle System Cert Exported** | `any where winlog.channel:"Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" and event.code:"1007…` |
| **Codeintegrity Blocked Protected Process File** | `any where winlog.channel:"Microsoft-Windows-CodeIntegrity/Operational" and event.code:"3104"` |
| **Codeintegrity Enforced Policy Block** | `any where winlog.channel:"Microsoft-Windows-CodeIntegrity/Operational" and event.code:"3077"` |
| **Codeintegrity Revoked Driver Blocked** | `any where winlog.channel:"Microsoft-Windows-CodeIntegrity/Operational" and event.code:"3023"` |
| **Codeintegrity Revoked Image Blocked** | `any where winlog.channel:"Microsoft-Windows-CodeIntegrity/Operational" and event.code:"3036"` |
| **Codeintegrity Revoked Image Loaded** | `any where winlog.channel:"Microsoft-Windows-CodeIntegrity/Operational" and (event.code like~ ("3032", "3035"))` |
| **Client Anonymfiles Com** | `any where winlog.channel:"Microsoft-Windows-DNS Client Events/Operational" and (event.code:"3008" and dns.question.name:…` |
| **Client Put Io** | `any where winlog.channel:"Microsoft-Windows-DNS Client Events/Operational" and (event.code:"3008" and (dns.question.name…` |
| **Client Tor Onion** | `any where winlog.channel:"Microsoft-Windows-DNS Client Events/Operational" and (event.code:"3008" and (dns.question.name…` |
| **Client Ufile Io** | `any where winlog.channel:"Microsoft-Windows-DNS Client Events/Operational" and (event.code:"3008" and dns.question.name:…` |
| **Server Failed Dns Zone Transfer** | `any where winlog.channel:"DNS Server" and event.code:"6004"` |
| **Server Susp Server Level Plugin Dll** | `any where winlog.channel:"DNS Server" and (event.code like~ ("150", "770", "771"))` |
| **As Failed Load Gpo** | `any where winlog.channel:"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" and event.code:"2009"` |
| **As Reset Config** | `any where winlog.channel:"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" and (event.code like~ ("20…` |
| **As Setting Change** | `any where winlog.channel:"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" and (event.code like~ ("20…` |
| **Iis Module Removed** | `any where event.code:"29" and winlog.event_data.Configuration:"*/system.webServer/modules/remove*"` |
| **Mssql Sp Maggie** | `any where winlog.channel:"Application" and (winlog.provider_name:"MSSQLSERVER" and event.code:"8128" and winlog.event_da…` |
| **Add Remove Computer** | `any where winlog.channel:"Security" and (event.code like~ ("4741", "4743"))` |
| **Admin Share Access** | `any where winlog.channel:"Security" and ((event.code:"5140" and winlog.event_data.ShareName:"Admin$") and (not user.name…` |
| **Alert Active Directory User Control** | `any where winlog.channel:"Security" and (event.code:"4704" and winlog.event_data.PrivilegeList:"*SeEnableDelegationPrivi…` |
| **Audit Log Cleared** | `any where winlog.channel:"Security" and ((event.code:"517" and winlog.provider_name:"Security") or (event.code:"1102" an…` |
| **Camera Microphone Access** | `any where winlog.channel:"Security" and ((event.code like~ ("4657", "4656", "4663")) and (winlog.event_data.ObjectName l…` |
| **Codeintegrity Check Failure** | `any where winlog.channel:"Security" and ((event.code like~ ("5038", "6281")) and (not ((winlog.event_data.param1 like~ (…` |
| **Device Installation Blocked** | `any where winlog.channel:"Security" and event.code:"6423"` |
| **Dpapi Domain Masterkey Backup Attempt** | `any where winlog.channel:"Security" and event.code:"4692"` |
| **Hktl Edr Silencer** | `any where winlog.channel:"Security" and ((event.code like~ ("5441", "5447")) and winlog.event_data.FilterName:"*Custom O…` |
| **Hktl Nofilter** | `any where winlog.channel:"Security" and ((event.code:"5447" and winlog.event_data.FilterName:"*RonPolicy*") or (event.co…` |
| **Iso Mount** | `any where winlog.channel:"Security" and ((event.code:"4663" and winlog.event_data.ObjectServer:"Security" and winlog.eve…` |
| **Kerberoasting Activity** | `any where winlog.channel:"Security" and ((event.code:"4769" and winlog.event_data.Status:"0x0" and winlog.event_data.Tic…` |
| **Mal Wceaux Dll** | `any where winlog.channel:"Security" and ((event.code like~ ("4656", "4663")) and winlog.event_data.ObjectName:"*\\wceaux…` |
| **Member Removed Security Enabled Global Group** | `any where winlog.channel:"Security" and (event.code like~ ("633", "4729"))` |
| **Net Share Obj Susp Desktop Ini** | `any where winlog.channel:"Security" and (event.code:"5145" and winlog.event_data.ObjectType:"File" and winlog.event_data…` |
| **New Or Renamed User Account With Dollar Sign** | `any where winlog.channel:"Security" and (((event.code:"4720" and winlog.event_data.SamAccountName:"*$*") or (event.code:…` |
| **Register New Logon Process By Rubeus** | `any where winlog.channel:"Security" and (event.code:"4611" and winlog.event_data.LogonProcessName:"User32LogonProcesss")` |
| **Registry Permissions Weakness Check** | `any where winlog.channel:"Security" and (event.code:"4663" and (winlog.event_data.ObjectName:"*\\SYSTEM\\*" and winlog.e…` |
| **Replay Attack Detected** | `any where winlog.channel:"Security" and event.code:"4649"` |
| **Sam Registry Hive Handle Request** | `any where winlog.channel:"Security" and (event.code:"4656" and winlog.event_data.ObjectType:"Key" and winlog.event_data.…` |
| **Scm Database Handle Failure** | `any where winlog.channel:"Security" and ((event.code:"4656" and winlog.event_data.ObjectType:"SC_MANAGER OBJECT" and win…` |
| **Sdelete Potential Secure Deletion** | `any where winlog.channel:"Security" and ((event.code like~ ("4656", "4663", "4658")) and (winlog.event_data.ObjectName l…` |
| **Security Enabled Global Group Deleted** | `any where winlog.channel:"Security" and (event.code like~ ("4730", "634"))` |
| **Susp Add Domain Trust** | `any where winlog.channel:"Security" and event.code:"4706"` |
| **Susp Add Sid History** | `any where winlog.channel:"Security" and ((event.code like~ ("4765", "4766")) or (event.code:"4738" and (not (winlog.even…` |
| **Susp Computer Name** | `any where winlog.channel:"Security" and ((winlog.event_data.SamAccountName:"SAMTHEADMIN-*" and winlog.event_data.SamAcco…` |
| **Susp Dsrm Password Change** | `any where winlog.channel:"Security" and event.code:"4794"` |
| **Susp Local Anon Logon Created** | `any where winlog.channel:"Security" and (event.code:"4720" and (winlog.event_data.SamAccountName:"*ANONYMOUS*" and winlo…` |
| **Syskey Registry Access** | `any where winlog.channel:"Security" and ((event.code like~ ("4656", "4663")) and winlog.event_data.ObjectType:"key" and …` |
| **Transf Files With Cred Data Via Network Shares** | `any where winlog.channel:"Security" and (event.code:"5145" and ((winlog.event_data.RelativeTargetName like~ ("*\\mimidrv…` |
| **User Logoff** | `any where winlog.channel:"Security" and (event.code like~ ("4634", "4647"))` |
| **Workstation Was Locked** | `any where winlog.channel:"Security" and event.code:"4800"` |
| **Atera Rmm Agent Install** | `any where winlog.channel:"Application" and (event.code:"1033" and winlog.provider_name:"MsiInstaller" and winlog.event_d…` |
| **Restriction Policies Block** | `any where winlog.channel:"Application" and (winlog.provider_name:"Microsoft-Windows-SoftwareRestrictionPolicies" and (ev…` |
| **Backup Delete** | `any where winlog.channel:"Application" and (event.code:"524" and winlog.provider_name:"Microsoft-Windows-Backup")` |
| **System Adcs Enrollment Request Denied** | `any where winlog.channel:"System" and (winlog.provider_name:"Microsoft-Windows-CertificationAuthority" and event.code:"5…` |
| **System Application Sysmon Crash** | `any where winlog.channel:"System" and (winlog.provider_name:"Application Popup" and event.code:"26" and (winlog.event_da…` |
| **System Eventlog Cleared** | `any where winlog.channel:"System" and ((event.code:"104" and winlog.provider_name:"Microsoft-Windows-Eventlog") and (not…` |
| **System Kdcsvc Cert Use No Strong Mapping** | `any where winlog.channel:"System" and ((winlog.provider_name like~ ("Kerberos-Key-Distribution-Center", "Microsoft-Windo…` |
| **System Lpe Indicators Tabtip** | `any where winlog.channel:"System" and (winlog.provider_name:"Microsoft-Windows-DistributedCOM" and event.code:"10001" an…` |
| **System Service Terminated Error Generic** | `any where winlog.channel:"System" and (winlog.provider_name:"Service Control Manager" and event.code:"7023")` |
| **System Service Terminated Error Important** | `any where winlog.channel:"System" and ((winlog.provider_name:"Service Control Manager" and event.code:"7023") and ((winl…` |
| **System Susp Critical Hive Location Access Bits Cleared** | `any where winlog.channel:"System" and (event.code:"16" and winlog.provider_name:"Microsoft-Windows-Kernel-General" and (…` |
| **System Susp Dhcp Config** | `any where winlog.channel:"System" and (event.code:"1033" and winlog.provider_name:"Microsoft-Windows-DHCP-Server")` |
| **System Susp Dhcp Config Failed** | `any where winlog.channel:"System" and ((event.code like~ ("1031", "1032", "1034")) and winlog.provider_name:"Microsoft-W…` |
| **System Susp Eventlog Cleared** | `any where winlog.channel:"System" and (event.code:"104" and winlog.provider_name:"Microsoft-Windows-Eventlog" and (winlo…` |
| **System Susp System Update Error** | `any where winlog.channel:"System" and (winlog.provider_name:"Microsoft-Windows-WindowsUpdateClient" and (event.code like…` |
| **Taskscheduler Execution From Susp Locations** | `any where winlog.channel:"Microsoft-Windows-TaskScheduler/Operational" and (event.code:"129" and (winlog.event_data.Path…` |
| **Taskscheduler Lolbin Execution Via Task Scheduler** | `any where winlog.channel:"Microsoft-Windows-TaskScheduler/Operational" and (event.code:"129" and (winlog.event_data.Path…` |
| **Taskscheduler Susp Schtasks Delete** | `any where winlog.channel:"Microsoft-Windows-TaskScheduler/Operational" and ((event.code:"141" and (winlog.event_data.Tas…` |
| **Usb Device Plugged** | `any where winlog.channel:"Microsoft-Windows-DriverFrameworks-UserMode/Operational" and (event.code like~ ("2003", "2100"…` |
| **Dns Nkn** | `any where query:"*seed*" and query:"*.nkn.org*"` |
| **Dns Torproxy** | `any where query like~ ("*.hiddenservice.net", "*.onion.ca", "*.onion.cab", "*.onion.casa", "*.onion.city", "*.onion.dire…` |

### Persistence (40)

| Rule | What it detects |
|------|----------------|
| **Errorhandler Persistence** | `any where file.path:"*\\WINDOWS\\Setup\\Scripts\\ErrorHandler.cmd"` |
| **Powershell Startup Shortcuts** | `any where (process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) and file.path:"*\\start menu\\programs\\startu…` |
| **Startup Folder File Write** | `any where file.path:"*\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp*" and (not ((process.executable like~ ("C:\\Wi…` |
| **Susp Lnk Double Extension** | `any where (file.path:"*.lnk" and (file.path like~ ("*.doc.*", "*.docx.*", "*.jpg.*", "*.pdf.*", "*.ppt.*", "*.pptx.*", "…` |
| **Tsclient Filewrite Startup** | `any where process.executable:"*\\mstsc.exe" and file.path:"*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*"` |
| **Wpbbin Persistence** | `any where file.path:"C:\\Windows\\System32\\wpbbin.exe"` |
| **Image Load Malware Coldsteel Persistence Service Dll** | `any where process.executable:"*\\svchost.exe" and file.path:"*\\AppData\\Roaming\\newdev.dll"` |
| **Apt Actinium Persistence** | `any where process.command_line:"*schtasks*" and process.command_line:"*create*" and process.command_line:"*wscript*" and…` |
| **Bitsadmin Potential Persistence** | `any where (process.executable:"*\\bitsadmin.exe" or process.pe.original_file_name:"bitsadmin.exe") and ((process.command…` |
| **Findstr Lnk** | `any where ((process.executable like~ ("*\\find.exe", "*\\findstr.exe")) or (process.pe.original_file_name like~ ("FIND.E…` |
| **Hktl Sharpersist** | `any where (process.executable:"*\\SharPersist.exe" or process.pe.product:"SharPersist") or (process.command_line like~ (…` |
| **Malware Coldsteel Service Persistence** | `any where process.executable:"*\\svchost.exe" and (process.command_line like~ ("* -k msupdate", "* -k msupdate2", "* -k …` |
| **Malware Kapeka Backdoor Persistence** | `any where (((process.executable:"*\\schtasks.exe" or process.pe.original_file_name:"schtasks.exe") and (process.command_…` |
| **Netsh Helper Dll Persistence** | `any where (process.pe.original_file_name:"netsh.exe" or process.executable:"*\\netsh.exe") and (process.command_line:"*a…` |
| **Schtasks Persistence Windows Telemetry** | `any where (process.executable:"*\\schtasks.exe" or process.pe.original_file_name:"schtasks.exe") and (process.command_li…` |
| **Sdbinst Shim Persistence** | `any where ((process.executable:"*\\sdbinst.exe" or process.pe.original_file_name:"sdbinst.exe") and process.command_line…` |
| **Vmware Toolbox Cmd Persistence** | `any where (process.executable:"*\\VMwareToolBoxCmd.exe" or process.pe.original_file_name:"toolbox-cmd.exe") and (process…` |
| **Vscode Tunnel Service Install** | `any where process.command_line:"*tunnel *" and process.command_line:"*service*" and process.command_line:"*internal-run*…` |
| **Webdav Lnk Execution** | `any where process.parent.executable:"*\\explorer.exe" and (process.executable like~ ("*\\cmd.exe", "*\\cscript.exe", "*\…` |
| **Registry Add Persistence Disk Cleanup Handler Entry** | `any where (winlog.event_data.EventType:"CreateKey" and registry.path:"*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\E…` |
| **Registry Event Susp Download Run Key** | `any where (process.executable like~ ("*\\AppData\\Local\\Packages\\Microsoft.Outlook_*", "*\\AppData\\Local\\Microsoft\\…` |
| **Registry Set Aedebug Persistence** | `any where (registry.path:"*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\Debugger*" and winlog.event_data.…` |
| **Registry Set Disk Cleanup Handler Autorun Persistence** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches\\*" and ((registry.path…` |
| **Registry Set Fax Dll Persistance** | `any where (registry.path:"*\\Software\\Microsoft\\Fax\\Device Providers\\*" and registry.path:"*\\ImageName*") and (not …` |
| **Registry Set Hide Scheduled Task Via Index Tamper** | `any where (registry.path:"*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\*" and registry…` |
| **Registry Set Malware Kamikakabot Winlogon Persistence** | `any where registry.path:"*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" and (winlog.event_data.Details:"*-no…` |
| **Registry Set Malware Kapeka Backdoor Autorun Persistence** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*" and (registry.path like~ ("*\\Sens Api",…` |
| **Registry Set Netsh Help Dll Persistence Susp Location** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\NetSh*" and ((winlog.event_data.Details like~ ("*:\\Perflogs\\*", "*:\\…` |
| **Registry Set Persistence App Cpmpat Layer Registerapprestart** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers\\*" and winlog.event…` |
| **Registry Set Persistence Custom Protocol Handler** | `any where (registry.path:"HKCR\\*" and winlog.event_data.Details:"URL:*") and (not (winlog.event_data.Details:"URL:ms-*"…` |
| **Registry Set Persistence Logon Scripts Userinitmprlogonscript** | `any where registry.path:"*UserInitMprLogonScript*"` |
| **Registry Set Persistence Shim Database** | `any where (registry.path like~ ("*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB\\*", "…` |
| **Registry Set Persistence Shim Database Susp Application** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\*" and (registry.pa…` |
| **Registry Set Powershell In Run Keys** | `any where (registry.path like~ ("*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*", "*\\Software\\WOW6432Node\\Micr…` |
| **Registry Set Susp Reg Persist Explorer Run** | `any where registry.path:"*\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" and (winlog.event_data.Details …` |
| **Registry Set Susp Service Installed** | `any where (registry.path like~ ("HKLM\\System\\CurrentControlSet\\Services\\NalDrv\\ImagePath", "HKLM\\System\\CurrentCo…` |
| **Apt Cozy Bear Scheduled Tasks Name** | `any where winlog.channel:"Security" and ((event.code like~ ("4698", "4699", "4702")) and (winlog.event_data.TaskName lik…` |
| **System Malware Snake Persistence Service** | `any where winlog.channel:"System" and (winlog.provider_name:"Service Control Manager" and event.code:"7045" and winlog.e…` |
| **System Service Install Netsupport Manager** | `any where winlog.channel:"System" and ((winlog.provider_name:"Service Control Manager" and event.code:"7045") and (winlo…` |
| **System Service Install Remote Access Software** | `any where winlog.channel:"System" and (winlog.provider_name:"Service Control Manager" and (event.code like~ ("7045", "70…` |

### PowerShell (48)

| Rule | What it detects |
|------|----------------|
| **Create Remote Thread Win Powershell Susp Targets** | `any where (process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) and (winlog.event_data.TargetImage like~ ("*\\…` |
| **Delete Exchange Powershell Logs** | `any where file.path:"\\Logging\\CmdletInfra\\LocalPowerShell\\Cmdlet\\*" and file.path:"*_Cmdlet_*"` |
| **Delete Powershell Command History** | `any where file.path:"*\\PSReadLine\\ConsoleHost_history.txt"` |
| **Apt Fin7 Powershell Scripts Naming Convention** | `any where file.path like~ ("*_64refl.ps1", "host_ip.ps1")` |
| **Powershell Drop Powershell** | `any where ((process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) and file.path:"*.ps1") and (not (file.path:"*…` |
| **Powershell Exploit Scripts** | `any where (file.path like~ ("*\\Add-ConstrainedDelegationBackdoor.ps1", "*\\Add-Exfiltration.ps1", "*\\Add-Persistence.p…` |
| **Powershell Module Uncommon Creation** | `any where (file.path like~ ("*\\WindowsPowerShell\\Modules\\*", "*\\PowerShell\\7\\Modules\\*")) and (not ((process.exec…` |
| **Susp System Interactive Powershell** | `any where file.path like~ ("C:\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Windows\\PowerShe…` |
| **Pipe Created Powershell Alternate Host Pipe** | `any where file.name:"\\PSHost*" and (not (((process.executable like~ ("*:\\Program Files\\PowerShell\\7-preview\\pwsh.ex…` |
| **Pipe Created Powershell Execution Pipe** | `any where file.name:"\\PSHost*"` |
| **Posh Pm Exploit Scripts** | `any where (winlog.event_data.ContextInfo like~ ("*Add-ConstrainedDelegationBackdoor.ps1*", "*Add-Exfiltration.ps1*", "*A…` |
| **Posh Pm Remote Powershell Session** | `any where (winlog.event_data.ContextInfo:"* = ServerRemoteHost *" and winlog.event_data.ContextInfo:"*wsmprovhost.exe*")…` |
| **Posh Pm Susp Get Nettcpconnection** | `any where winlog.event_data.ContextInfo:"*Get-NetTCPConnection*"` |
| **Posh Pm Susp Invocation Generic** | `any where (winlog.event_data.ContextInfo like~ ("* -enc *", "* -EncodedCommand *", "* -ec *")) and (winlog.event_data.Co…` |
| **Posh Pm Susp Invocation Specific** | `any where ((winlog.event_data.ContextInfo:"*-nop*" and winlog.event_data.ContextInfo:"* -w *" and winlog.event_data.Cont…` |
| **Posh Pm Susp Reset Computermachinepassword** | `any where winlog.event_data.ContextInfo:"*Reset-ComputerMachinePassword*"` |
| **Posh Pm Susp Zip Compress** | `any where winlog.event_data.ContextInfo:"*Compress-Archive -Path*-DestinationPath $env:TEMP*" and winlog.event_data.Cont…` |
| **Posh Pm Syncappvpublishingserver Exe** | `any where winlog.event_data.ContextInfo:"*SyncAppvPublishingServer.exe*"` |
| **Hktl Empire Powershell Launch** | `any where process.command_line like~ ("* -NoP -sta -NonI -W Hidden -Enc *", "* -noP -sta -w 1 -enc *", "* -NoP -NonI -W …` |
| **Powershell Aadinternals Cmdlets Execution** | `any where ((process.executable like~ ("*\\powershell.exe", "*\\powershell_ise.exe", "*\\pwsh.exe")) or (process.pe.origi…` |
| **Powershell Cl Invocation** | `any where process.command_line:"*SyncInvoke *"` |
| **Powershell Cl Loadassembly** | `any where process.command_line like~ ("*LoadAssemblyFromPath *", "*LoadAssemblyFromNS *")` |
| **Powershell Cl Mutexverifiers** | `any where ((process.parent.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) and process.executable:"*\\powershell.…` |
| **Powershell Create Service** | `any where process.command_line:"*New-Service*" and process.command_line:"*-BinaryPathName*"` |
| **Powershell Dsinternals Cmdlets** | `any where process.command_line like~ ("*Add-ADDBSidHistory*", "*Add-ADNgcKey*", "*Add-ADReplNgcKey*", "*ConvertFrom-ADMa…` |
| **Powershell Encoding Patterns** | `any where ((process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) or (process.pe.original_file_name like~ ("Pow…` |
| **Powershell Get Clipboard** | `any where process.command_line:"*Get-Clipboard*"` |
| **Powershell Iex Patterns** | `any where (((process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) and (process.command_line like~ ("* | iex;*"…` |
| **Powershell Import Cert Susp Locations** | `any where (process.command_line:"*Import-Certificate*" and process.command_line:"* -FilePath *" and process.command_line…` |
| **Powershell Invocation Specific** | `any where ((process.command_line:"*-nop*" and process.command_line:"* -w *" and process.command_line:"*hidden*" and proc…` |
| **Powershell Malicious Cmdlets** | `any where process.command_line like~ ("*Add-Exfiltration*", "*Add-Persistence*", "*Add-RegBackdoor*", "*Add-RemoteRegBac…` |
| **Powershell Msexchange Transport Agent** | `any where process.command_line:"*Install-TransportAgent*"` |
| **Powershell Non Interactive Execution** | `any where ((process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) or (process.pe.original_file_name like~ ("Pow…` |
| **Powershell Public Folder** | `any where (process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) and (process.command_line like~ ("*-f C:\\User…` |
| **Powershell Remove Mppreference** | `any where process.command_line:"*Remove-MpPreference*" and (process.command_line like~ ("*-ControlledFolderAccessProtect…` |
| **Powershell Service Dacl Modification Set Service** | `any where (process.executable:"*\\pwsh.exe" or process.pe.original_file_name:"pwsh.dll") and (process.command_line like~…` |
| **Powershell Susp Parameter Variation** | `any where (process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) and (process.command_line like~ ("* -windowsty…` |
| **Powershell Susp Parent Process** | `any where (process.parent.executable:"*tomcat*" or (process.parent.executable like~ ("*\\amigo.exe", "*\\browser.exe", "…` |
| **Powershell Susp Ps Appdata** | `any where (process.command_line like~ ("*powershell.exe*", "*\\powershell*", "*\\pwsh*", "*pwsh.exe*")) and ((process.co…` |
| **Powershell Webclient Casing** | `any where ((process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe")) or (process.pe.original_file_name like~ ("Pow…` |
| **Powershell X509Enrollment** | `any where process.command_line like~ ("*X509Enrollment.CBinaryConverter*", "*884e2002-217d-11da-b2a4-000e7bbb2b09*")` |
| **Powershell Zip Compress** | `any where process.command_line like~ ("*Compress-Archive -Path*-DestinationPath $env:TEMP*", "*Compress-Archive -Path*-D…` |
| **Registry Set Unsecure Powershell Policy** | `any where (process.command_line like~ ("*\\ShellIds\\Microsoft.PowerShell\\ExecutionPolicy*", "*\\Policies\\Microsoft\\W…` |
| **Susp Powershell Execution Via Dll** | `any where ((process.executable like~ ("*\\InstallUtil.exe", "*\\RegAsm.exe", "*\\RegSvcs.exe", "*\\regsvr32.exe", "*\\ru…` |
| **Registry Set Custom File Open Handler Powershell Execution** | `any where registry.path:"*shell\\open\\command\\*" and (winlog.event_data.Details:"*powershell*" and winlog.event_data.D…` |
| **Registry Set Powershell As Service** | `any where registry.path:"*\\Services\\*" and registry.path:"*\\ImagePath" and (winlog.event_data.Details like~ ("*powers…` |
| **Registry Set Powershell Crypto Namespace** | `any where registry.path:"*\\Shell\\Open\\Command*" and (winlog.event_data.Details like~ ("*powershell*", "*pwsh*")) and …` |
| **Registry Set Powershell Execution Policy** | `any where ((registry.path like~ ("*\\ShellIds\\Microsoft.PowerShell\\ExecutionPolicy", "*\\Policies\\Microsoft\\Windows\…` |

### Privilege Escalation (31)

| Rule | What it detects |
|------|----------------|
| **System32 Local Folder Privilege Escalation** | `any where (file.path like~ ("C:\\Windows\\System32\\logonUI.exe.local*", "C:\\Windows\\System32\\werFault.exe.local*", "…` |
| **Uac Bypass Consent Comctl32** | `any where file.path:"C:\\Windows\\System32\\consent.exe.@*" and file.path:"*\\comctl32.dll"` |
| **Uac Bypass Dotnet Profiler** | `any where file.path:"C:\\Users\\*" and file.path:"*\\AppData\\Local\\Temp\\pe386.dll"` |
| **Uac Bypass Eventvwr** | `any where (file.path like~ ("*\\Microsoft\\Event Viewer\\RecentViews", "*\\Microsoft\\EventV~1\\RecentViews")) and (not …` |
| **Uac Bypass Ieinstal** | `any where process.executable:"C:\\Program Files\\Internet Explorer\\IEInstal.exe" and file.path:"C:\\Users\\*" and file.…` |
| **Uac Bypass Msconfig Gui** | `any where file.path:"C:\\Users\\*" and file.path:"*\\AppData\\Local\\Temp\\pkgmgr.exe"` |
| **Uac Bypass Ntfs Reparse Point** | `any where file.path:"C:\\Users\\*" and file.path:"*\\AppData\\Local\\Temp\\api-ms-win-core-kernel32-legacy-l1.DLL"` |
| **Uac Bypass Winsat** | `any where file.path:"C:\\Users\\*" and (file.path like~ ("*\\AppData\\Local\\Temp\\system32\\winsat.exe", "*\\AppData\\L…` |
| **Image Load Uac Bypass Iscsicpl** | `any where (process.executable:"C:\\Windows\\SysWOW64\\iscsicpl.exe" and file.path:"*\\iscsiexe.dll") and (not (file.path…` |
| **Pipe Created Apt Turla Named Pipes** | `any where file.name like~ ("\\atctl", "\\comnap", "\\iehelper", "\\sdlrpc", "\\userpipe")` |
| **Proc Access Win Uac Bypass Editionupgrademanagerobj** | `any where winlog.event_data.CallTrace:"*editionupgrademanagerobj.dll*"` |
| **Explorer Nouaccheck** | `any where (process.executable:"*\\explorer.exe" and process.command_line:"*/NOUACCHECK*") and (not (process.parent.comma…` |
| **Powershell Token Obfuscation** | `any where (process.command_line like~ ("SigmaRegularExpression(regexp=SigmaString(['\\w+`(\\w+|-|.)`[\\w+|\\s]']), flags…` |
| **Uac Bypass Cleanmgr** | `any where process.command_line:"*\"\\system32\\cleanmgr.exe /autoclean /d C:" and process.parent.command_line:"C:\\Windo…` |
| **Uac Bypass Cmstp Com Object Access** | `any where process.parent.executable:"*\\DllHost.exe" and (process.parent.command_line like~ ("* /Processid:{3E5FC7F9-9A5…` |
| **Uac Bypass Consent Comctl32** | `any where process.parent.executable:"*\\consent.exe" and process.executable:"*\\werfault.exe" and (winlog.event_data.Int…` |
| **Uac Bypass Eventvwr Recentviews** | `any where (process.command_line like~ ("*\\Event Viewer\\RecentViews*", "*\\EventV~1\\RecentViews*")) and process.comman…` |
| **Uac Bypass Fodhelper** | `any where process.parent.executable:"*\\fodhelper.exe"` |
| **Uac Bypass Idiagnostic Profile** | `any where process.parent.executable:"*\\DllHost.exe" and process.parent.command_line:"* /Processid:{12C21EA7-2EB8-4B55-9…` |
| **Uac Bypass Ieinstal** | `any where (winlog.event_data.IntegrityLevel like~ ("High", "System", "S-1-16-16384", "S-1-16-12288")) and process.parent…` |
| **Uac Bypass Pkgmgr Dism** | `any where process.parent.executable:"*\\pkgmgr.exe" and process.executable:"*\\dism.exe" and (winlog.event_data.Integrit…` |
| **Uac Bypass Sdclt** | `any where process.executable:"*sdclt.exe" and (winlog.event_data.IntegrityLevel like~ ("High", "S-1-16-12288"))` |
| **Uac Bypass Wsreset** | `any where process.parent.executable:"*\\wsreset.exe" and (not (process.executable:"*\\conhost.exe" or process.pe.origina…` |
| **Registry Set Bypass Uac Using Eventviewer** | `any where registry.path:"*_Classes\\mscfile\\shell\\open\\command\\(Default)" and (not winlog.event_data.Details:"%Syste…` |
| **Registry Set Uac Bypass Eventvwr** | `any where registry.path:"*\\mscfile\\shell\\open\\command"` |
| **Registry Set Uac Bypass Sdclt** | `any where registry.path:"*Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand" or (registry.path:"*Softwa…` |
| **Registry Set Uac Bypass Winsat** | `any where registry.path:"*\\Root\\InventoryApplicationFile\\winsat.exe|*" and registry.path:"*\\LowerCaseLongPath" and w…` |
| **Registry Set Uac Bypass Wmp** | `any where registry.path:"*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\St…` |
| **Registry Set Uac Disable** | `any where registry.path:"*\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA*" and winlog.event_data.Deta…` |
| **Registry Set Uac Disable Notification** | `any where registry.path:"*\\Microsoft\\Security Center\\UACDisableNotify*" and winlog.event_data.Details:"DWORD (0x00000…` |
| **Registry Set Uac Disable Secure Desktop Prompt** | `any where registry.path:"*\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop*" and winlog.eve…` |

### Ransomware / Impact (15)

| Rule | What it detects |
|------|----------------|
| **Malware Snake Encrypted Payload Ioc** | `any where file.path:"C:\\Windows\\System32\\Com\\Comadmin.dat"` |
| **Diskshadow Script Mode Susp Ext** | `any where ((process.pe.original_file_name:"diskshadow.exe" or process.executable:"*\\diskshadow.exe") and process.comman…` |
| **Malware Blackbyte Ransomware** | `any where (process.executable:"C:\\Users\\Public\\*" and process.command_line:"* -single *") or (process.command_line li…` |
| **Malware Conti Ransomware Commands** | `any where process.command_line:"*-m *" and process.command_line:"*-net *" and process.command_line:"*-size *" and proces…` |
| **Malware Conti Ransomware Database Dump** | `any where (process.executable:"*\\sqlcmd.exe" or (process.command_line like~ ("*sqlcmd *", "*sqlcmd.exe*"))) and process…` |
| **Malware Darkside Ransomware** | `any where (process.command_line like~ ("*=[char][byte]('0x'+*", "* -work worker0 -path *")) or (process.parent.command_l…` |
| **Malware Lockergoga Ransomware** | `any where process.command_line:"*-i SM-tgytutrc -s*"` |
| **Malware Maze Ransomware** | `any where (process.parent.executable:"*\\WINWORD.exe" and process.executable:"*.tmp") or (process.executable:"*\\wmic.ex…` |
| **Susp Shadow Copies Deletion** | `any where (((process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe", "*\\wmic.exe", "*\\vssadmin.exe", "*\\disksha…` |
| **Registry Set Malware Snake Encrypted Key** | `any where registry.path:"*\\SOFTWARE\\Classes\\.wav\\OpenWithProgIds\\*" and (not (registry.path like~ ("*.AssocFile.WAV…` |
| **Possible Dc Shadow** | `any where winlog.channel:"Security" and ((event.code:"4742" and winlog.event_data.ServicePrincipalNames:"*GC/*") or (eve…` |
| **Susp Opened Encrypted Zip** | `any where winlog.channel:"Security" and ((event.code:"5379" and winlog.event_data.TargetName:"*Microsoft_Windows_Shell_Z…` |
| **Susp Opened Encrypted Zip Filename** | `any where winlog.channel:"Security" and ((event.code:"5379" and winlog.event_data.TargetName:"*Microsoft_Windows_Shell_Z…` |
| **Susp Opened Encrypted Zip Outlook** | `any where winlog.channel:"Security" and (event.code:"5379" and (winlog.event_data.TargetName:"*Microsoft_Windows_Shell_Z…` |
| **System Kdcsvc Tgs No Suitable Encryption Key Found** | `any where winlog.channel:"System" and ((winlog.provider_name like~ ("Kerberos-Key-Distribution-Center", "Microsoft-Windo…` |

---

## ⏭️ Skip — Elastic Already Covers These (283 rules)

Don't import the Sigma version. Elastic has equivalent or better coverage.
(282 clear overlaps · 1 auto-resolved from the 'pick one' bucket)

| Sigma Rule | Elastic Equivalent | Score | Notes |
|-----------|-------------------|-------|-------|
| Exploit Cve 2021 26857 Msexchange | Microsoft Exchange Server UM Spawning Suspicious Processes, risk 47 | 1.00 | Near-identical logic |
| Proc Access Win Lsass Seclogon Access | Suspicious LSASS Access via MalSecLogon, risk 73 | 1.00 | Near-identical logic |
| Cdb Arbitrary Command Execution | Execution via Windows Command Debugging Utility, risk 47 | 1.00 | Near-identical logic |
| Cmd Unusual Parent | Unusual Parent Process for cmd.exe, risk 47 | 1.00 | Near-identical logic |
| Dns Susp Child Process | Unusual Child Process of dns.exe, risk 73 | 1.00 | Near-identical logic |
| Eventvwr Susp Child Process | Bypass UAC via Event Viewer, risk 73 | 1.00 | Near-identical logic |
| Fsutil Drive Enumeration | Peripheral Device Discovery, risk 21 | 1.00 | Near-identical logic |
| Iis Connection Strings Decryption | Microsoft IIS Connection Strings Decryption, risk 73 | 1.00 | Near-identical logic |
| Net Use Mount Admin Share | Mounting Hidden or WebDav Remote Shares, risk 47 | 1.00 | Near-identical logic |
| Net Use Mount Internet Share | Mounting Hidden or WebDav Remote Shares, risk 47 | 1.00 | Near-identical logic |
| Powershell Disable Firewall | Windows Firewall Disabled via PowerShell, risk 47 | 1.00 | Near-identical logic |
| Powershell Shadowcopy Deletion | Volume Shadow Copy Deletion via PowerShell, risk 73 | 1.00 | Elastic is more specific (extra conditions) |
| Renamed Sysinternals Psexec Service | Suspicious Process Execution via Renamed PsExec Executable, risk 47 | 1.00 | Near-identical logic |
| Sc Sdset Deny Service Access | Service DACL Modification via sc.exe, risk 47 | 1.00 | Near-identical logic |
| Susp Priv Escalation Via Named Pipe | Privilege Escalation via Named Pipe Impersonation, risk 73 | 1.00 | Near-identical logic |
| Susp Workfolders | Signed Proxy Execution via MS Work Folders, risk 47 | 1.00 | Near-identical logic |
| Sysinternals Psexesvc | Suspicious Process Execution via Renamed PsExec Executable, risk 47 | 1.00 | Near-identical logic |
| Uac Bypass Hijacking Firwall Snap In | UAC Bypass via Windows Firewall Snap-In Hijack, risk 47 | 1.00 | Near-identical logic |
| Xwizard Execution Non Default Location | Execution of COM object via Xwizard, risk 47 | 1.00 | Near-identical logic |
| Susp Group Policy Abuse Privilege Addition | Group Policy Abuse for Privilege Addition, risk 73 | 0.98 | Near-identical logic |
| Susp Possible Shadow Credentials Added | Potential Shadow Credentials added to AD Object, risk 73 | 0.97 | Near-identical logic |
| Alert Enable Weak Encryption | Kerberos Pre-authentication Disabled for User, risk 47 | 0.96 | Near-identical logic |
| Susp Group Policy Startup Script Added To Gpo | Startup/Logon Script added to Group Policy Object, risk 47 | 0.93 | Near-identical logic |
| Image Load Exploit Cve 2021 1675 Spoolsv Dll Load | Suspicious Print Spooler File Deletion, risk 47 | 0.90 | Elastic is more specific (extra conditions) |
| Uac Bypass Idiagnostic Profile | Suspicious Print Spooler File Deletion, risk 47 | 0.90 | Elastic is more specific (extra conditions) |
| Diskshadow Child Process Susp | Suspicious Execution from a Mounted Device, risk 47 | 0.89 | Elastic is more specific (extra conditions) |
| Net Use Mount Share | Mounting Hidden or WebDav Remote Shares, risk 47 | 0.88 | Elastic is more specific (extra conditions) |
| Net Use Network Connections Discovery | Mounting Hidden or WebDav Remote Shares, risk 47 | 0.88 | Elastic is more specific (extra conditions) |
| Exploit Cve 2021 40444 Office Directory Traversal | Microsoft Build Engine Started by an Office Application, risk 73 | 0.86 | Near-identical logic |
| Susp Elevated System Shell | Command and Scripting Interpreter via Windows Scripts, risk 73 | 0.86 | Elastic is more specific (extra conditions) |
| Bcdedit Boot Conf Tamper | Modification of Boot Configuration, risk 21 | 0.86 | Near-identical logic |
| Gpo Scheduledtasks | Scheduled Task Execution at Scale via GPO, risk 47 | 0.85 | Near-identical logic |
| Exploit Cve 2023 21554 Queuejumper | Suspicious Execution from a Mounted Device, risk 47 | 0.83 | Substantial overlap (score 0.83) |
| Wbadmin Delete All Backups | Backup Deletion with Wbadmin, risk 21 | 0.83 | Elastic is broader (covers more variants) |
| Wbadmin Delete Backups | Backup Deletion with Wbadmin, risk 21 | 0.83 | Elastic is broader (covers more variants) |
| Hktl Crackmapexec Powershell Obfuscation | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.82 | Elastic is more specific (extra conditions) |
| Keyscrambler Susp Child Process | Local Scheduled Task Creation, risk 21 | 0.82 | Substantial overlap (score 0.82) |
| Powershell Cmdline Convertto Securestring | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.82 | Elastic is more specific (extra conditions) |
| Powershell Stop Service | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.82 | Elastic is more specific (extra conditions) |
| Sysinternals Psexec Execution | PsExec Network Connection, risk 21 | 0.82 | Elastic is more specific (extra conditions) |
| Winrar Susp Child Process | Local Scheduled Task Creation, risk 21 | 0.82 | Substantial overlap (score 0.82) |
| Hh Html Help Susp Child Process | Suspicious Execution from a Mounted Device, risk 47 | 0.81 | Elastic is broader (covers more variants) |
| Netsh Wifi Credential Harvesting | Wireless Credential Dumping using Netsh Command, risk 73 | 0.80 | Elastic is broader (covers more variants) |
| Sc Sdset Hide Sevices | Service DACL Modification via sc.exe, risk 47 | 0.80 | Substantial overlap (score 0.80) |
| Sc Sdset Modification | Service DACL Modification via sc.exe, risk 47 | 0.80 | Elastic is more specific (extra conditions) |
| Powershell Cmdline Special Characters | Clearing Windows Console History, risk 47 | 0.78 | Substantial overlap (score 0.78) |
| Wmiprvse Spawns Powershell | Clearing Windows Console History, risk 47 | 0.78 | Substantial overlap (score 0.78) |
| Net Use Password Plaintext | Mounting Hidden or WebDav Remote Shares, risk 47 | 0.78 | Substantial overlap (score 0.78) |
| Sc Sdset Allow Service Changes | Service DACL Modification via sc.exe, risk 47 | 0.77 | Elastic is broader (covers more variants) |
| Scrcons Susp Child Process | Suspicious Execution from a Mounted Device, risk 47 | 0.77 | Substantial overlap (score 0.77) |
| Netsh Fw Disable | Disable Windows Firewall Rules via Netsh, risk 47 | 0.77 | Elastic is broader (covers more variants) |
| Office Svchost Parent | Execution of File Written or Modified by Microsoft Office, risk 73 | 0.75 | Substantial overlap (score 0.75) |
| Powershell Add Windows Capability | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.75 | Substantial overlap (score 0.75) |
| Uac Bypass Icmluautil | UAC Bypass via ICMLuaUtil Elevated COM Interface, risk 73 | 0.75 | Elastic is broader (covers more variants) |
| Netsh Fw Set Rule | Disable Windows Firewall Rules via Netsh, risk 47 | 0.73 | Substantial overlap (score 0.73) |
| Susp Elavated Msi Spawned Shell | Command and Scripting Interpreter via Windows Scripts, risk 73 | 0.73 | Substantial overlap (score 0.73) |
| Susp Elevated System Shell Uncommon Parent | Command and Scripting Interpreter via Windows Scripts, risk 73 | 0.72 | Substantial overlap (score 0.72) |
| Powershell New Netfirewallrule Allow | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.72 | Substantial overlap (score 0.72) |
| Shell Write Susp Directory | Suspicious Execution from a Mounted Device, risk 47 | 0.71 | Substantial overlap (score 0.71) |
| Image Load Office Dotnet Assembly Dll Load | Execution of File Written or Modified by Microsoft Office, risk 73 | 0.71 | Substantial overlap (score 0.71) |
| Proc Access Win Lsass Werfault | Potential Credential Access via LSASS Memory Dump, risk 73 | 0.71 | Substantial overlap (score 0.71) |
| Certutil Download | Suspicious CertUtil Commands, risk 47 | 0.71 | Substantial overlap (score 0.71) |
| Sc Disable Service | Service Command Lateral Movement, risk 21 | 0.71 | Substantial overlap (score 0.71) |
| Exploit Cve 2021 41379 | Command and Scripting Interpreter via Windows Scripts, risk 73 | 0.71 | Substantial overlap (score 0.71) |
| Msdt Susp Parent | Suspicious Microsoft Diagnostics Wizard Execution, risk 73 | 0.69 | Substantial overlap (score 0.69) |
| Servu Susp Child Process | Suspicious Execution from a Mounted Device, risk 47 | 0.69 | Substantial overlap (score 0.69) |
| 7Zip Password Extraction | Encrypting Files with WinRar or 7z, risk 47 | 0.68 | Substantial overlap (score 0.68) |
| 7Zip Password Compression | Encrypting Files with WinRar or 7z, risk 47 | 0.68 | Substantial overlap (score 0.68) |
| Susp Execution From Public Folder As Parent | Suspicious Execution from a Mounted Device, risk 47 | 0.68 | Substantial overlap (score 0.68) |
| Initial Access Dll Search Order Hijacking | Startup Persistence by a Suspicious Process, risk 47 | 0.67 | Substantial overlap (score 0.67) |
| Powershell Abnormal Commandline Size | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.67 | Substantial overlap (score 0.67) |
| Cmd Mklink Osk Cmd | Symbolic Link to Shadow Copy Created, risk 47 | 0.67 | Substantial overlap (score 0.67) |
| Fsutil Usage | Delete Volume USN Journal with Fsutil, risk 21 | 0.67 | Elastic is broader (covers more variants) |
| Office Spawn Exe From Users Directory | Microsoft Build Engine Started by an Office Application, risk 73 | 0.67 | Substantial overlap (score 0.67) |
| Powershell Active Directory Module Dll Import | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.67 | Substantial overlap (score 0.67) |
| Powershell Install Unsigned Appx Packages | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.67 | Substantial overlap (score 0.67) |
| Powershell Reverse Shell Connection | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.67 | Substantial overlap (score 0.67) |
| Powershell Set Acl | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.67 | Substantial overlap (score 0.67) |
| Susp Cli Obfuscation Unicode Img | Command and Scripting Interpreter via Windows Scripts, risk 73 | 0.67 | Substantial overlap (score 0.67) |
| Wbadmin Restore File | NTDS Dump via Wbadmin, risk 47 | 0.67 | Elastic is broader (covers more variants) |
| Wmic Eventconsumer Creation | Persistence via WMI Event Subscription, risk 21 | 0.67 | Elastic is more specific (extra conditions) |
| Wmic Process Creation | Persistence via WMI Event Subscription, risk 21 | 0.67 | Substantial overlap (score 0.67) |
| Wmic Recon Process | Persistence via WMI Event Subscription, risk 21 | 0.67 | Substantial overlap (score 0.67) |
| Registry Set Bypass Uac Using Silentcleanup Task | Privilege Escalation via Windir Environment Variable, risk 73 | 0.67 | Elastic is more specific (extra conditions) |
| Remote Access Tools Screenconnect Webshell | ScreenConnect Server Spawning Suspicious Processes, risk 73 | 0.65 | Elastic is more specific (extra conditions) |
| Net Execution | Enumeration of Administrator Accounts, risk 21 | 0.64 | Substantial overlap (score 0.64) |
| Powershell Download Patterns | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.64 | Substantial overlap (score 0.64) |
| Image Load Office Dotnet Clr Dll Load | Execution of File Written or Modified by Microsoft Office, risk 73 | 0.64 | Substantial overlap (score 0.64) |
| Image Load Office Dotnet Gac Dll Load | Execution of File Written or Modified by Microsoft Office, risk 73 | 0.64 | Substantial overlap (score 0.64) |
| Net Groups And Accounts Recon | Enumeration of Administrator Accounts, risk 21 | 0.63 | Substantial overlap (score 0.63) |
| Smb File Creation Admin Shares | Potential Machine Account Relay Attack via SMB, risk 73 | 0.62 | Substantial overlap (score 0.62) |
| Msxsl Remote Execution | Network Connection via MsXsl, risk 21 | 0.62 | Elastic is broader (covers more variants) |
| Desktopimgdownldr Remote File Download | Remote File Download via Desktopimgdownldr Utility, risk 47 | 0.62 | Substantial overlap (score 0.62) |
| Registry Set Dns Over Https Enabled | DNS-over-HTTPS Enabled via Registry, risk 21 | 0.62 | Substantial overlap (score 0.62) |
| Papercut Print Management Exploitation Pc App | Suspicious Execution from a Mounted Device, risk 47 | 0.61 | Substantial overlap (score 0.61) |
| Hktl Koadic | Suspicious Cmd Execution via WMI, risk 73 | 0.59 | Substantial overlap (score 0.59) |
| Net Share Unmount | Enumeration of Administrator Accounts, risk 21 | 0.59 | Elastic is more specific (extra conditions) |
| Net User Add | Enumeration of Administrator Accounts, risk 21 | 0.59 | Elastic is more specific (extra conditions) |
| Net User Add Never Expire | Enumeration of Administrator Accounts, risk 21 | 0.59 | Substantial overlap (score 0.59) |
| Conhost Uncommon Parent | Conhost Spawned By Suspicious Parent Process, risk 73 | 0.59 | Elastic is broader (covers more variants) |
| Malware Darkgate Net User Creation | User Account Creation, risk 21 | 0.59 | Substantial overlap (score 0.59) |
| Diagtrack Eop Default Login Username | Potential Account Takeover - Logon from New Source IP, risk 47 | 0.59 | Substantial overlap (score 0.59) |
| Susp Logon Newcredentials | Potential Account Takeover - Logon from New Source IP, risk 47 | 0.59 | Elastic is more specific (extra conditions) |
| Whoami Parent Anomaly | Account Discovery Command via SYSTEM Account, risk 21 | 0.59 | Substantial overlap (score 0.59) |
| Image Load Office Powershell Dll Load | Execution of File Written or Modified by Microsoft Office, risk 73 | 0.58 | Substantial overlap (score 0.58) |
| Attrib System | Adding Hidden File Attribute via Attrib, risk 21 | 0.58 | Elastic is more specific (extra conditions) |
| Vhd Download Via Browsers | Suspicious HTML File Creation, risk 47 | 0.58 | Substantial overlap (score 0.58) |
| Mstsc Run Local Rpd File Susp Parent | Potential Escalation via Vulnerable MSI Repair, risk 73 | 0.58 | Substantial overlap (score 0.58) |
| Exploit Cve 2021 40444 | Microsoft Build Engine Started by an Office Application, risk 73 | 0.58 | Substantial overlap (score 0.58) |
| Svchost Termserv Proc Spawn | Unusual Executable File Creation by a System Critical Process, risk 73 | 0.58 | Substantial overlap (score 0.58) |
| Powershell Mailboxexport Share | Exchange Mailbox Export via PowerShell, risk 47 | 0.57 | Substantial overlap (score 0.57) |
| Powershell Set Service Disabled | Disabling Windows Defender Security Settings via PowerShell, risk 47 | 0.57 | Substantial overlap (score 0.57) |
| Sqlcmd Veeam Dump | Potential Veeam Credential Access Command, risk 47 | 0.57 | Substantial overlap (score 0.57) |
| Metasploit Authentication | Potential Computer Account NTLM Relay Activity, risk 47 | 0.57 | Substantial overlap (score 0.57) |
| Java Keytool Susp Child Process | Suspicious MS Outlook Child Process, risk 21 | 0.57 | Substantial overlap (score 0.57) |
| Java Manageengine Susp Child Process | Suspicious MS Outlook Child Process, risk 21 | 0.57 | Substantial overlap (score 0.57) |
| Powershell Set Policies To Unsecure Level | Command and Scripting Interpreter via Windows Scripts, risk 73 | 0.57 | Substantial overlap (score 0.57) |
| Fsutil Symlinkevaluation | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.56 | Substantial overlap (score 0.56) |
| Exploit Cve 2019 0708 Scanner Poc | Potential Computer Account NTLM Relay Activity, risk 47 | 0.56 | Substantial overlap (score 0.56) |
| Unusual Modification By Dns Exe | Unusual File Operation by dns.exe, risk 47 | 0.56 | Substantial overlap (score 0.56) |
| Unusual Deletion By Dns Exe | Unusual File Operation by dns.exe, risk 47 | 0.56 | Substantial overlap (score 0.56) |
| Image Load Susp Python Image Load | Simple HTTP Web Server Connection, risk 21 | 0.56 | Substantial overlap (score 0.56) |
| Image Load Uac Bypass Via Dism | Windows Subsystem for Linux Enabled via Dism Utility, risk 47 | 0.56 | Substantial overlap (score 0.56) |
| Hh Chm Remote Download Or Execution | Network Connection via Compiled HTML File, risk 21 | 0.56 | Substantial overlap (score 0.56) |
| Installutil Download | InstallUtil Process Making Network Connections, risk 47 | 0.56 | Elastic is broader (covers more variants) |
| Office Arbitrary Cli Download | Suspicious Image Load (taskschd.dll) from MS Office, risk 21 | 0.56 | Substantial overlap (score 0.56) |
| Regasm Regsvcs Uncommon Location Execution | Network Connection via Registration Utility, risk 21 | 0.56 | Substantial overlap (score 0.56) |
| Alert Ad User Backdoors | Account Configured with Never-Expiring Password, risk 47 | 0.55 | Substantial overlap (score 0.55) |
| Logman Disable Eventlog | Disable Windows Event and Security Logs Using Built-in Tools, risk 21 | 0.55 | Substantial overlap (score 0.55) |
| Powershell Set Acl Susp Location | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.55 | Substantial overlap (score 0.55) |
| Winrm Susp Child Process | Suspicious Execution from a Mounted Device, risk 47 | 0.55 | Substantial overlap (score 0.55) |
| Admin Rdp Login | Potential Account Takeover - Logon from New Source IP, risk 47 | 0.54 | Substantial overlap (score 0.54) |
| Overpass The Hash | Potential Account Takeover - Logon from New Source IP, risk 47 | 0.54 | Substantial overlap (score 0.54) |
| Ad User Enumeration | Potential Credential Access via DCSync, risk 47 | 0.54 | Substantial overlap (score 0.54) |
| Dcom Iertutil Dll Hijack | Potential Machine Account Relay Attack via SMB, risk 73 | 0.54 | Substantial overlap (score 0.54) |
| Wmiprvse Wbemcomn Dll Hijack | Potential Machine Account Relay Attack via SMB, risk 73 | 0.54 | Substantial overlap (score 0.54) |
| Create Remote Thread Win Hktl Cactustorch | Startup Persistence by a Suspicious Process, risk 47 | 0.54 | Elastic is more specific (extra conditions) |
| Exploit Cve 2022 29072 7Zip | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.54 | Substantial overlap (score 0.54) |
| Remote Access Tools Screenconnect Remote Execution Susp | Network Activity to a Suspicious Top Level Domain, risk 73 | 0.54 | Substantial overlap (score 0.54) |
| Cmd Ping Copy Combined Execution | Remote File Copy to a Hidden Share, risk 47 | 0.53 | Substantial overlap (score 0.53) |
| Fltmc Unload Driver Sysmon | Potential Evasion via Filter Manager, risk 47 | 0.53 | Elastic is broader (covers more variants) |
| Netsh Fw Add Rule | Disable Windows Firewall Rules via Netsh, risk 47 | 0.53 | Substantial overlap (score 0.53) |
| Image Load Office Vbadll Load | Execution of File Written or Modified by Microsoft Office, risk 73 | 0.53 | Substantial overlap (score 0.53) |
| Image Load Susp Script Dotnet Clr Dll Load | Startup Persistence by a Suspicious Process, risk 47 | 0.53 | Substantial overlap (score 0.53) |
| Domain Telegram Api Non Browser Access | Suspicious File Downloaded from Google Drive, risk 47 | 0.53 | Substantial overlap (score 0.53) |
| Dfsvc Suspicious Child Processes | Suspicious Execution from a Mounted Device, risk 47 | 0.53 | Substantial overlap (score 0.53) |
| Java Susp Child Process | Suspicious MS Outlook Child Process, risk 21 | 0.53 | Substantial overlap (score 0.53) |
| Ad Replication Non Machine Account | Potential Credential Access via DCSync, risk 47 | 0.52 | Elastic is broader (covers more variants) |
| Alert Ruler | Potential Computer Account NTLM Relay Activity, risk 47 | 0.52 | Substantial overlap (score 0.52) |
| Forfiles Proxy Execution  | Command Execution via ForFiles, risk 47 | 0.51 | Elastic is more specific (extra conditions) |
| Powershell Snapins Hafnium | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.51 | Substantial overlap (score 0.51) |
| Exploit Cve 2017 8759 | Microsoft Build Engine Started an Unusual Process, risk 21 | 0.50 | Substantial overlap (score 0.50) |
| Malware Snake Service Execution | Potential Windows Error Manager Masquerading, risk 47 | 0.50 | Substantial overlap (score 0.50) |
| Csc Compilation | Microsoft Build Engine Started an Unusual Process, risk 21 | 0.50 | Substantial overlap (score 0.50) |
| Diskshadow Child Process | Bypass UAC via Event Viewer, risk 73 | 0.50 | Substantial overlap (score 0.50) |
| Image Load Iexplore Dcom Iertutil Dll Hijack | Microsoft Build Engine Started an Unusual Process, risk 21 | 0.50 | Substantial overlap (score 0.50) |
| Dism Enable Powershell Web Access Feature | Potential DLL Side-Loading via Trusted Microsoft Programs, risk 47 | 0.50 | Substantial overlap (score 0.50) |
| Ieexec Download | Network Connection via Signed Binary, risk 21 | 0.50 | Substantial overlap (score 0.50) |
| Mpcmdrun Dll Sideload Defender | Remote File Download via MpCmdRun, risk 47 | 0.50 | Substantial overlap (score 0.50) |
| Office Outlook Susp Child Processes | Suspicious Execution from a Mounted Device, risk 47 | 0.50 | Substantial overlap (score 0.50) |
| Office Winword Dll Load | Potential DLL Side-Loading via Trusted Microsoft Programs, risk 47 | 0.50 | Substantial overlap (score 0.50) |
| Powershell Base64 Invoke | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.50 | Substantial overlap (score 0.50) |
| Powershell Disable Defender Av Security Monitoring | Disable Windows Event and Security Logs Using Built-in Tools, risk 21 | 0.50 | Substantial overlap (score 0.50) |
| Sc Create Service | Service Command Lateral Movement, risk 21 | 0.50 | Substantial overlap (score 0.50) |
| Sigverif Uncommon Child Process | Bypass UAC via Event Viewer, risk 73 | 0.50 | Substantial overlap (score 0.50) |
| Susp Copy Lateral Movement | NTDS or SAM Database File Copied, risk 73 | 0.50 | Substantial overlap (score 0.50) |
| Susp Remote Desktop Tunneling | Potential Remote Desktop Tunneling Detected, risk 73 | 0.50 | Elastic is broader (covers more variants) |
| Taskkill Sep | High Number of Process and/or Service Terminations, risk 47 | 0.50 | Substantial overlap (score 0.50) |
| Winrm Remote Powershell Session Process | Incoming Execution via PowerShell Remoting, risk 47 | 0.50 | Substantial overlap (score 0.50) |
| Mshta Susp Child Processes | Local Scheduled Task Creation, risk 21 | 0.49 | Substantial overlap (score 0.49) |
| Wmiprvse Susp Child Processes | Creation or Modification of Root Certificate, risk 21 | 0.49 | Substantial overlap (score 0.49) |
| Domain Notion Api Susp Communication | Suspicious File Downloaded from Google Drive, risk 47 | 0.49 | Substantial overlap (score 0.49) |
| Wermgr Susp Child Process | Suspicious MS Outlook Child Process, risk 21 | 0.49 | Substantial overlap (score 0.49) |
| Member Added Security Enabled Global Group | Active Directory Group Modification by SYSTEM, risk 47 | 0.49 | Substantial overlap (score 0.49) |
| Susp Wmi Login | Potential Account Takeover - Logon from New Source IP, risk 47 | 0.49 | Substantial overlap (score 0.49) |
| Wmi Persistence | Potential Credential Access via DCSync, risk 47 | 0.49 | Substantial overlap (score 0.49) |
| Audit Cve | Windows CryptoAPI Spoofing Vulnerability (CVE-2020-0601 - CurveBall), risk 21 | 0.48 | Substantial overlap (score 0.48) |
| Exploit Cve 2023 38831 Winrar Child Proc | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.48 | Substantial overlap (score 0.48) |
| Sc Change Sevice Image Path By Non Admin | Service Command Lateral Movement, risk 21 | 0.48 | Substantial overlap (score 0.48) |
| Exploit Cve 2024 37085 Esxi Admins Group Creation | Enumeration of Administrator Accounts, risk 21 | 0.47 | Substantial overlap (score 0.47) |
| Netsh Fw Enable Group Rule | Disable Windows Firewall Rules via Netsh, risk 47 | 0.47 | Substantial overlap (score 0.47) |
| Susp Copy System Dir | NTDS or SAM Database File Copied, risk 73 | 0.47 | Substantial overlap (score 0.47) |
| Rundll32 Susp Shellexec Ordinal Execution | Suspicious Execution from a Mounted Device, risk 47 | 0.46 | Substantial overlap (score 0.46) |
| Pdqdeploy Runner Susp Children | Suspicious ScreenConnect Client Child Process, risk 47 | 0.46 | Substantial overlap (score 0.46) |
| Dllhost No Cli Execution | Unusual Network Connection via DllHost, risk 47 | 0.45 | Elastic is broader (covers more variants) |
| Iis Susp Module Registration | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.45 | Substantial overlap (score 0.45) |
| Powershell Import Module | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.45 | Substantial overlap (score 0.45) |
| Access Token Abuse | Potential Account Takeover - Logon from New Source IP, risk 47 | 0.45 | Substantial overlap (score 0.45) |
| Protected Storage Service Access | Potential Machine Account Relay Attack via SMB, risk 73 | 0.45 | Substantial overlap (score 0.45) |
| Susp Ldap Dataexchange | AdminSDHolder SDProp Exclusion Added, risk 73 | 0.45 | Elastic is broader (covers more variants) |
| Office Outlook Macro Creation | Persistence via Microsoft Outlook VBA, risk 47 | 0.44 | Substantial overlap (score 0.44) |
| Office Outlook Susp Macro Creation | Persistence via Microsoft Outlook VBA, risk 47 | 0.44 | Substantial overlap (score 0.44) |
| Cmd Mklink Shadow Copies Access Symlink | Symbolic Link to Shadow Copy Created, risk 47 | 0.44 | Elastic is more specific (extra conditions) |
| Wbadmin Dump Sensitive Files | Backup Deletion with Wbadmin, risk 21 | 0.44 | Substantial overlap (score 0.44) |
| Petitpotam Network Share | Active Directory Forced Authentication from Linux Host - SMB Named Pipes, risk 47 | 0.44 | Substantial overlap (score 0.44) |
| Desktopimgdownldr Susp Execution | Control Panel Process with Unusual Arguments, risk 73 | 0.44 | Substantial overlap (score 0.44) |
| Webshell Susp Process Spawned From Webserver | Suspicious PDF Reader Child Process, risk 21 | 0.44 | Substantial overlap (score 0.44) |
| Proc Access Win Susp Potential Shellcode Injection | LSASS Memory Dump Handle Access, risk 47 | 0.44 | Substantial overlap (score 0.44) |
| Susp Eventlog Clear | Clearing Windows Event Logs, risk 21 | 0.43 | Substantial overlap (score 0.43) |
| Malware Kamikakabot Lnk Lure Execution | Suspicious Cmd Execution via WMI, risk 73 | 0.43 | Substantial overlap (score 0.43) |
| Powershell Crypto Namespace | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.43 | Substantial overlap (score 0.43) |
| Powershell Xor Commandline | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.43 | Substantial overlap (score 0.43) |
| Susp Shadow Copies Creation | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.43 | Substantial overlap (score 0.43) |
| Susp Logon Explicit Credentials | Startup Persistence by a Suspicious Process, risk 47 | 0.42 | Substantial overlap (score 0.42) |
| Renamed Binary Highly Relevant | Command Obfuscation via Unicode Modifier Letters, risk 73 | 0.42 | Substantial overlap (score 0.42) |
| Malware Pikabot Rundll32 Uncommon Extension | Suspicious Microsoft Diagnostics Wizard Execution, risk 73 | 0.42 | Substantial overlap (score 0.42) |
| Hh Chm Execution | Network Connection via Compiled HTML File, risk 21 | 0.42 | Substantial overlap (score 0.42) |
| Renamed Curl | Suspicious Curl to Google App Script Endpoint, risk 73 | 0.42 | Substantial overlap (score 0.42) |
| Susp Lolbin Exec From Non C Drive | Delayed Execution via Ping, risk 21 | 0.42 | Substantial overlap (score 0.42) |
| Susp Proc Wrong Parent | Unusual Executable File Creation by a System Critical Process, risk 73 | 0.42 | Substantial overlap (score 0.42) |
| Werfault Reflect Debugger Exec | Bypass UAC via Event Viewer, risk 73 | 0.42 | Substantial overlap (score 0.42) |
| Office Susp Child Processes | Suspicious MS Office Child Process, risk 47 | 0.41 | Substantial overlap (score 0.41) |
| Net User Default Accounts Manipulation | Enumeration of Administrator Accounts, risk 21 | 0.41 | Substantial overlap (score 0.41) |
| Susp Procexplorer Driver Created In Tmp Folder | Suspicious Lsass Process Access, risk 47 | 0.41 | Substantial overlap (score 0.41) |
| Exploit Cve 2020 10189 | Process Created with a Duplicated Token, risk 47 | 0.41 | Substantial overlap (score 0.41) |
| Scrcons Remote Wmi Scripteventconsumer | Potential Account Takeover - Logon from New Source IP, risk 47 | 0.41 | Substantial overlap (score 0.41) |
| Browsers Chromium Headless File Download | Potential File Download via a Headless Browser, risk 73 | 0.41 | Substantial overlap (score 0.41) |
| Powershell Hide Services Via Set Service | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.41 | Substantial overlap (score 0.41) |
| Susp Time Modification | Full User-Mode Dumps Enabled System-Wide, risk 47 | 0.41 | Substantial overlap (score 0.41) |
| Powershell Susp Child Processes | Suspicious Execution from a Mounted Device, risk 47 | 0.41 | Substantial overlap (score 0.41) |
| Query Win Domain Azurewebsites | First Time Seen DNS Query to RMM Domain, risk 47 | 0.41 | Substantial overlap (score 0.41) |
| Spoolsv Susp Child Processes | Suspicious PDF Reader Child Process, risk 21 | 0.40 | Substantial overlap (score 0.40) |
| Exploit Cve 2020 1350 | Unusual Child Process of dns.exe, risk 73 | 0.40 | Elastic is broader (covers more variants) |
| Mssql Susp Child Process | Suspicious Execution from a Mounted Device, risk 47 | 0.40 | Substantial overlap (score 0.40) |
| Powershell Audio Capture | PowerShell Suspicious Script with Audio Capture Capabilities, risk 73 | 0.40 | Substantial overlap (score 0.40) |
| Qemu Suspicious Execution | Potential Traffic Tunneling using QEMU, risk 47 | 0.40 | Elastic is broader (covers more variants) |
| Susp Registry Modification Of Ms Setting Protocol Handler | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.40 | Substantial overlap (score 0.40) |
| Wbadmin Restore Sensitive Files | NTDS Dump via Wbadmin, risk 47 | 0.40 | Elastic is broader (covers more variants) |
| Xwizard Runwizard Com Object Exec | Execution of COM object via Xwizard, risk 47 | 0.40 | Substantial overlap (score 0.40) |
| Registry Set Bypass Uac Using Delegateexecute | NullSessionPipe Registry Modification, risk 47 | 0.40 | Substantial overlap (score 0.40) |
| Registry Set Office Outlook Enable Load Macro Provider On Boot | Scheduled Tasks AT Command Enabled, risk 47 | 0.40 | Substantial overlap (score 0.40) |
| Registry Set Office Outlook Enable Macro Execution | Scheduled Tasks AT Command Enabled, risk 47 | 0.40 | Substantial overlap (score 0.40) |
| Hktl Jlaive Batch Execution | Adding Hidden File Attribute via Attrib, risk 21 | 0.39 | Substantial overlap (score 0.39) |
| Office Macro Files Downloaded | First Time Seen DNS Query to RMM Domain, risk 47 | 0.39 | Substantial overlap (score 0.39) |
| Susp Abusing Debug Privilege | Conhost Spawned By Suspicious Parent Process, risk 73 | 0.39 | Substantial overlap (score 0.39) |
| Domain Azurewebsites | First Time Seen DNS Query to RMM Domain, risk 47 | 0.39 | Substantial overlap (score 0.39) |
| Malware Trickbot Wermgr | Potential Windows Error Manager Masquerading, risk 47 | 0.38 | Substantial overlap (score 0.38) |
| Malware Chrome Loader Execution | Browser Process Spawned from an Unusual Parent, risk 73 | 0.38 | Substantial overlap (score 0.38) |
| Exploit Cve 2023 34362 Moveit Transfer Exploitation Activity | Microsoft Build Engine Started an Unusual Process, risk 21 | 0.38 | Substantial overlap (score 0.38) |
| Lsass Werfault Dump | Bypass UAC via Event Viewer, risk 73 | 0.38 | Substantial overlap (score 0.38) |
| Rdp File Susp Creation | First Time Seen DNS Query to RMM Domain, risk 47 | 0.38 | Substantial overlap (score 0.38) |
| Uac Bypass Wmp | Host File System Changes via Windows Subsystem for Linux, risk 47 | 0.38 | Substantial overlap (score 0.38) |
| Image Load Wmic Remote Xsl Scripting Dlls | Volume Shadow Copy Deletion via WMIC, risk 73 | 0.38 | Substantial overlap (score 0.38) |
| Mmc Mmc20 Lateral Movement | Bypass UAC via Event Viewer, risk 73 | 0.38 | Substantial overlap (score 0.38) |
| Regsvr32 Susp Child Process | Suspicious Execution from a Mounted Device, risk 47 | 0.38 | Substantial overlap (score 0.38) |
| Malware Guloader Execution | Potential Escalation via Vulnerable MSI Repair, risk 73 | 0.38 | Substantial overlap (score 0.38) |
| Bash File Execution | Suspicious Execution via Windows Subsystem for Linux, risk 21 | 0.38 | Substantial overlap (score 0.38) |
| Msdt Arbitrary Command Execution | Suspicious Microsoft Diagnostics Wizard Execution, risk 73 | 0.38 | Substantial overlap (score 0.38) |
| Pass The Hash 2 | Potential Account Takeover - Logon from New Source IP, risk 47 | 0.38 | Substantial overlap (score 0.38) |
| Ad Object Writedac Access | Potential Credential Access via DCSync, risk 47 | 0.38 | Substantial overlap (score 0.38) |
| Query Win Susp External Ip Lookup | DNS Request for IP Lookup Service via Unsigned Binary, risk 47 | 0.38 | Substantial overlap (score 0.38) |
| Domain External Ip Lookup | DNS Request for IP Lookup Service via Unsigned Binary, risk 47 | 0.38 | Substantial overlap (score 0.38) |
| Mssql Veaam Susp Child Processes | Suspicious MS Outlook Child Process, risk 21 | 0.38 | Substantial overlap (score 0.38) |
| Winrar Uncommon Folder Execution | Encrypting Files with WinRar or 7z, risk 47 | 0.38 | Substantial overlap (score 0.38) |
| Powershell Invoke Webrequest Direct Ip | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.38 | Substantial overlap (score 0.38) |
| Powershell Invoke Webrequest Download | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.38 | Substantial overlap (score 0.38) |
| Ssh Rdp Tunneling | Potential Remote Desktop Tunneling Detected, risk 73 | 0.38 | Substantial overlap (score 0.38) |
| Susp Private Keys Recon | Microsoft Exchange Worker Spawning Suspicious Processes, risk 73 | 0.38 | Substantial overlap (score 0.38) |
| Susp System Exe Anomaly | Unusual Parent-Child Relationship, risk 47 | 0.38 | Substantial overlap (score 0.38) |
| Conhost Headless Powershell | Proxy Execution via Console Window Host, risk 73 | 0.37 | Substantial overlap (score 0.37) |
| Image Load Dll Dbghelp Dbgcore Susp Load | Startup Persistence by a Suspicious Process, risk 47 | 0.37 | Substantial overlap (score 0.37) |
| Netsh Fw Rules Discovery | Disable Windows Firewall Rules via Netsh, risk 47 | 0.37 | Substantial overlap (score 0.37) |
| Account Backdoor Dcsync Rights | Potential Active Directory Replication Account Backdoor, risk 47 | 0.36 | Elastic is broader (covers more variants) |
| Mmc Susp Child Process | Suspicious Microsoft HTML Application Child Process, risk 73 | 0.36 | Substantial overlap (score 0.36) |
| Powershell Frombase64String Archive | Suspicious .NET Reflection via PowerShell, risk 47 | 0.36 | Substantial overlap (score 0.36) |
| Wsl Child Processes Anomalies | Execution via Windows Subsystem for Linux, risk 47 | 0.36 | Substantial overlap (score 0.36) |
| Browsers Chromium Headless Exec | Potential File Download via a Headless Browser, risk 73 | 0.36 | Substantial overlap (score 0.36) |
| Browsers Chromium Mockbin Abuse | Potential File Download via a Headless Browser, risk 73 | 0.36 | Substantial overlap (score 0.36) |
| Ntds Dit Uncommon Parent Process | Web Shell Detection: Script Process Child of Common Web Processes, risk 73 | 0.36 | Substantial overlap (score 0.36) |
| Msbuild Susp Parent Process | Microsoft Build Engine Started by a Script Process, risk 47 | 0.36 | Substantial overlap (score 0.36) |
| Dcsync | Potential Credential Access via DCSync, risk 47 | 0.36 | Elastic is broader (covers more variants) |
| Vscode Tunnel Renamed Execution | Attempt to Establish VScode Remote Tunnel, risk 47 | 0.36 | Substantial overlap (score 0.36) |
| Image Load Side Load Ccleaner Du | Persistence via Scheduled Job Creation, risk 47 | 0.36 | Substantial overlap (score 0.36) |
| Image Load Side Load Windows Defender | Remote File Download via MpCmdRun, risk 47 | 0.36 | Substantial overlap (score 0.36) |
| Malware Pingback Backdoor | Service Command Lateral Movement, risk 21 | 0.35 | Substantial overlap (score 0.35) |
| Rundll32 Susp Execution With Image Extension | Control Panel Process with Unusual Arguments, risk 73 | 0.35 | Substantial overlap (score 0.35) |
| Dpapi Domain Backupkey Extraction | Potential Credential Access via DCSync, risk 47 | 0.35 | Substantial overlap (score 0.35) |
| Sdiagnhost Susp Child | MsiExec Service Child Process With Network Connection, risk 47 | 0.35 | Substantial overlap (score 0.35) |
| Sc Stop Service | Service Control Spawned via Script Interpreter, risk 21 | 0.35 | Elastic is more specific (extra conditions) |
| Wmic Recon Group | Enumeration of Administrator Accounts, risk 21 | 0.34 | Elastic is more specific (extra conditions) |
| Bash Command Execution | Suspicious Execution via Windows Subsystem for Linux, risk 21 | 0.23 | Elastic is more specific (extra conditions) |
| Renamed Msdt | Suspicious Microsoft Diagnostics Wizard Execution, risk 73 | 0.23 | Elastic is more specific (extra conditions) |
| Certutil Download Direct Ip | Suspicious CertUtil Commands, risk 47 | 0.33 | sigma adds only generic/noise conditions |

---

## 🔍 Weak Overlap — Probably Safe to Add (576 rules)

These share some signal with an Elastic rule but not enough to call it covered.
In most cases the Sigma rule is safe to import. Check the top matches if in doubt.

| Sigma Rule | Best Elastic Match | Score | Shared |
|-----------|-------------------|-------|--------|
| Registry Set Persistence Office Vsto | Startup Persistence by a Suspicious Process | 0.20 | `proc_name:excel.exe`, `proc_name:powerpnt.exe`, `proc_name:regsvr32.exe` |
| Susp Gpo Files | Creation or Modification of a new GPO Scheduled Task or Service | 0.20 | `file_path:scheduledtasks.xml`, `file_path:services.xml` |
| Susp Legitimate App Dropping Exe | Potential Execution via FileFix Phishing Attack | 0.19 | `proc_name:certreq.exe`, `proc_name:certutil.exe`, `proc_name:mshta.exe` |
| System Susp Service Installation Script | Suspicious Service was Installed in the System | 0.19 | `event_code:7045`, `proc_name:powershell`, `proc_name:regsvr32` |
| Lolbin Susp Sqldumper Activity | LSASS Memory Dump Creation | 0.19 | `proc_name:sqldumper.exe` |
| Susp Shell Spawn Susp Program | Suspicious Microsoft HTML Application Child Process | 0.19 | `proc_name:bitsadmin.exe`, `proc_name:certutil.exe`, `proc_name:schtasks.exe` |
| Schtasks Appdata Local System | Local Scheduled Task Creation | 0.19 | `proc_cmdline:/create`, `proc_cmdline:/ru`, `proc_cmdline:/tr` |
| System Malware Goofy Guineapig Service Persistence | Suspicious Service was Installed in the System | 0.19 | `event_code:7045`, `proc_name:rundll32` |
| Invoke Obfuscation Stdin Services Security | Suspicious Service was Installed in the System | 0.19 | `event_code:4697`, `proc_name:powershell` |
| Invoke Obfuscation Via Rundll Services Security | Suspicious Service was Installed in the System | 0.19 | `event_code:4697`, `proc_name:powershell` |
| Powershell Script Installed As Service | Suspicious Service was Installed in the System | 0.19 | `event_code:4697`, `proc_name:powershell` |
| System Invoke Obfuscation Stdin Services | Suspicious Service was Installed in the System | 0.19 | `event_code:7045`, `proc_name:powershell` |
| System Invoke Obfuscation Via Rundll Services | Suspicious Service was Installed in the System | 0.19 | `event_code:7045`, `proc_name:powershell` |
| System Powershell Script Installed As Service | Suspicious Service was Installed in the System | 0.19 | `event_code:7045`, `proc_name:powershell` |
| System Service Install Remcom | Suspicious Service was Installed in the System | 0.19 | `event_code:7045`, `proc_name:remcomsvc.exe` |
| System Susp Service Installation Folder | Suspicious Service was Installed in the System | 0.19 | `event_code:7045`, `proc_name:127.0.0.1` |
| Certutil Encode Susp Extensions | Control Panel Process with Unusual Arguments | 0.19 | `proc_cmdline:.gif`, `proc_cmdline:.jpeg`, `proc_cmdline:.jpg` |
| Adsi Cache Creation By Uncommon Tool | LSASS Memory Dump Handle Access | 0.19 | `proc_name:dllhost.exe`, `proc_name:svchost.exe`, `proc_name:wmiprvse.exe` |
| Exploit Cve 2023 38331 Winrar Susp Double Ext | Encrypting Files with WinRar or 7z | 0.19 | `proc_name:winrar.exe` |
| Exploit Cve 2023 40477 Winrar Rev File Abuse | Encrypting Files with WinRar or 7z | 0.19 | `proc_name:winrar.exe` |
| Desktop Ini Created By Uncommon Process | Encrypting Files with WinRar or 7z | 0.19 | `proc_name:7z.exe` |
| Apt Oilrig Mar18 | Potential Enumeration via Active Directory Web Service | 0.19 | `proc_name:.exe` |
| Browsers Chromium Sensitive Files | Unusual Web Config File Access | 0.19 | `proc_name:msmpeng.exe` |
| Pipe Created Adfs Namedpipe Connection Uncommon Tool | Suspicious Print Spooler SPL File Created | 0.19 | `proc_name:mmc.exe`, `proc_name:svchost.exe` |
| Dotnet Arbitrary Dll Csproj Execution | Executable File Creation with Multiple Extensions | 0.19 | `proc_name:dotnet.exe` |
| Hh Susp Execution | Network Connection via Compiled HTML File | 0.19 | `proc_name:hh.exe` |
| Registry Set Netsh Helper Dll Potential Persistence | Potential System Tampering via File Modification | 0.19 | `proc_name:poqexec.exe` |
| Auditpol Susp Execution | Attempt to Disable Auditd Service | 0.18 | `proc_cmdline:disable`, `proc_cmdline:remove` |
| Susp Web Request Cmd And Cmdlets | File Download Detected via Defend for Containers | 0.18 | `proc_cmdline:curl`, `proc_cmdline:wget` |
| Powershell Cmdline Reversed Strings | Microsoft Exchange Worker Spawning Suspicious Processes | 0.18 | `proc_name:powershell.exe`, `proc_name:pwsh.exe`, `proc_orig_name:powershell.exe` |
| Powershell Decode Gzip | Suspicious .NET Reflection via PowerShell | 0.18 | `proc_cmdline:gzipstream` |
| Registry Event Shell Open Keys Manipulation | NullSessionPipe Registry Modification | 0.18 | `reg_data:(empty)` |
| Pfx File Creation | File Creation in /var/log via Suspicious Process | 0.18 |  |
| Sed File Creation | File Creation in /var/log via Suspicious Process | 0.18 |  |
| Msiexec Install Quiet | Suspicious ScreenConnect Client Child Process | 0.18 | `proc_cmdline:-i`, `proc_cmdline:-q`, `proc_cmdline:/i` |
| Date Changed To Another Year | RDP Enabled via Registry | 0.18 | `proc_name:svchost.exe`, `proc_name:tiworker.exe` |
| Malware Serpent Backdoor Payload Execution | Local Scheduled Task Creation | 0.18 | `proc_cmdline:/create`, `proc_name:cmd.exe`, `proc_name:powershell.exe` |
| Pua Rclone Execution | Potential Data Exfiltration via Rclone | 0.18 | `proc_cmdline:copy`, `proc_cmdline:sync`, `proc_name:rclone.exe` |
| Plink Susp Tunneling | Potential Remote Desktop Tunneling Detected | 0.18 | `proc_cmdline::3389` |
| Print Remote File Copy | UAC Bypass via DiskCleanup Scheduled Task Hijack | 0.18 | `proc_cmdline:/d` |
| Susp Sysnative | Node.js Pre or Post-Install Script Execution | 0.18 | `proc_cmdline:install` |
| Uac Bypass Dismhost | Network Connection via Registration Utility | 0.18 | `proc_integrity:system` |
| Uac Bypass Msconfig Gui | Network Connection via Registration Utility | 0.18 | `proc_integrity:system` |
| Uac Bypass Wsreset Integrity Level | Network Connection via Registration Utility | 0.18 | `proc_integrity:system` |
| Image Load Wsman Provider Image Load | Suspicious Print Spooler SPL File Created | 0.18 | `proc_name:mmc.exe`, `proc_name:svchost.exe` |
| Hktl Sharpwsus Wsuspendu Execution | Service Control Spawned via Script Interpreter | 0.17 | `proc_cmdline:create`, `proc_cmdline:delete` |
| Diskshadow Script Mode | Potential Credential Access via Windows Utilities | 0.17 | `proc_name:diskshadow.exe`, `proc_orig_name:diskshadow.exe` |
| Diskshadow Script Mode Susp Location | Potential Credential Access via Windows Utilities | 0.17 | `proc_name:diskshadow.exe`, `proc_orig_name:diskshadow.exe` |
| Malware Darkgate Autoit3 Binary Creation | Windows Server Update Service Spawning Suspicious Processes | 0.17 | `proc_name:curl.exe` |
| Malware Bluesky Ransomware Files Indicators | Potential Machine Account Relay Attack via SMB | 0.17 | `event_code:5145` |
| Exploit Cve 2023 23397 Outlook Remote File Query | Suspicious Inter-Process Communication via Outlook | 0.17 | `proc_name:outlook.exe` |
| Registry Enumeration For Credentials Cli | Credential Acquisition via Registry Hive Dumping | 0.17 | `proc_cmdline:export`, `proc_cmdline:save`, `proc_name:reg.exe` |
| Susp Add User Local Admin Group | Enumeration of Administrator Accounts | 0.17 | `proc_cmdline:/add`, `proc_cmdline:localgroup` |
| Susp Add User Privileged Group | Enumeration of Administrator Accounts | 0.17 | `proc_cmdline:/add`, `proc_cmdline:localgroup` |
| Susp Legitimate App Dropping Script | Suspicious ScreenConnect Client Child Process | 0.17 | `proc_name:certreq.exe`, `proc_name:certutil.exe`, `proc_name:mshta.exe` |
| Apt Slingshot | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:schtasks.exe` |
| Malware Raspberry Robin Execution | Local Scheduled Task Creation | 0.17 | `proc_cmdline:/f`, `proc_name:regsvr32.exe`, `proc_name:rundll32.exe` |
| Malware Kamikakabot Schtasks Persistence | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:schtasks.exe` |
| Microsoft Workflow Compiler Execution | Unusual Process Network Connection | 0.17 | `proc_name:microsoft.workflow.compiler.exe` |
| Mode Codepage Change | Remote File Copy to a Hidden Share | 0.17 | `proc_cmdline:cp` |
| Schtasks Creation From Susp Parent | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:schtasks.exe` |
| Wscript Cscript Script Exec | Proxy Execution via Console Window Host | 0.17 | `proc_cmdline:.js`, `proc_cmdline:.vbs` |
| Image Load Cmstp Load Dll From Susp Location | Unusual Process Network Connection | 0.17 | `proc_name:cmstp.exe` |
| Bitsadmin Download | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:bitsadmin.exe` |
| Certutil Certificate Installation | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:certutil.exe` |
| Certutil Encode | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:certutil.exe` |
| Certutil Export Pfx | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:certutil.exe` |
| Cloudflared Tunnel Run | Potential Privilege Escalation via Container Misconfiguration | 0.17 | `proc_cmdline:run` |
| Csi Use Of Csharp Console | Unusual Process Network Connection | 0.17 | `proc_name:csi.exe` |
| Fsi Fsharp Code Execution | Unusual Process Network Connection | 0.17 | `proc_name:fsi.exe` |
| Hktl Invoke Obfuscation Via Use Mhsta | Disable Windows Firewall Rules via Netsh | 0.17 | `proc_cmdline:set` |
| Iexpress Susp Execution | Unusual Process Network Connection | 0.17 | `proc_name:iexpress.exe` |
| Netsh Port Forwarding | Potential CVE-2025-33053 Exploitation | 0.17 | `proc_name:netsh.exe` |
| Odbcconf Driver Install | Unusual Process Network Connection | 0.17 | `proc_name:odbcconf.exe` |
| Odbcconf Driver Install Susp | Unusual Process Network Connection | 0.17 | `proc_name:odbcconf.exe` |
| Odbcconf Register Dll Regsvr | Unusual Process Network Connection | 0.17 | `proc_name:odbcconf.exe` |
| Odbcconf Register Dll Regsvr Susp | Unusual Process Network Connection | 0.17 | `proc_name:odbcconf.exe` |
| Odbcconf Response File | Unusual Process Network Connection | 0.17 | `proc_name:odbcconf.exe` |
| Odbcconf Response File Susp | Unusual Process Network Connection | 0.17 | `proc_name:odbcconf.exe` |
| Powershell Amsi Init Failed Bypass | Potential Antimalware Scan Interface Bypass via PowerShell | 0.17 | `proc_cmdline:system.management.automation.amsiutils` |
| Powershell Base64 Wmi Classes | Microsoft Exchange Worker Spawning Suspicious Processes | 0.17 | `proc_name:powershell.exe`, `proc_name:pwsh.exe`, `proc_orig_name:powershell.exe` |
| Reg Add Run Key | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:reg.exe` |
| Reg Add Safeboot | Potential Data Exfiltration via Rclone | 0.17 | `proc_cmdline:copy` |
| Reg Defender Exclusion | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:reg.exe` |
| Reg Enable Windows Recall | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:reg.exe` |
| Reg Lsa Ppl Protection Disabled | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:reg.exe` |
| Reg Machineguid | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:reg.exe` |
| Reg Modify Group Policy Settings | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:reg.exe` |
| Reg Query Registry | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:reg.exe` |
| Reg Service Imagepath Change | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:reg.exe` |
| Reg Software Discovery | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:reg.exe` |
| Reg Susp Paths | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:reg.exe` |
| Registry Special Accounts Hide User | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:reg.exe` |
| Renamed Plink | Linux init (PID 1) Secret Dump via GDB | 0.17 | `proc_cmdline:-p` |
| Schtasks Creation | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:schtasks.exe` |
| Schtasks Creation Temp Folder | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:schtasks.exe` |
| Schtasks Guid Task Name | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:schtasks.exe` |
| Schtasks Schedule Type | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:schtasks.exe` |
| Schtasks Schedule Type System | Suspicious Microsoft HTML Application Child Process | 0.17 | `proc_name:schtasks.exe` |
| Susp Hiding Malware In Fonts Folder | Proxy Execution via Console Window Host | 0.17 | `proc_cmdline:.bat`, `proc_cmdline:.cmd`, `proc_cmdline:.js` |
| Susp Non Exe Image | Network Activity to a Suspicious Top Level Domain | 0.17 | `proc_name:.com`, `proc_name:.exe`, `proc_name:.scr` |
| Susp Task Folder Evasion | Potential Data Exfiltration via Rclone | 0.17 | `proc_cmdline:copy` |
| Sysinternals Psexec Remote Execution | Linux init (PID 1) Secret Dump via GDB | 0.17 | `proc_cmdline:-p` |
| Uac Bypass Cmstp | Unusual Process Network Connection | 0.17 | `proc_name:cmstp.exe` |
| Vsdiagnostics Execution Proxy | Service Command Lateral Movement | 0.17 | `proc_cmdline:start` |
| Wmic Recon Product | Node.js Pre or Post-Install Script Execution | 0.17 | `proc_cmdline:install` |
| Registry Set Timeproviders Dllname | Potential Persistence via Time Provider Modification | 0.17 | `reg_data:c:\\windows\\system32\\w32time.dll` |
| Uac Bypass Wmp | Unusual Print Spooler Child Process | 0.16 | `proc_integrity:system`, `proc_name:cmd.exe` |
| Wfp Endpoint Agent Blocked | Potential Evasion via Windows Filtering Platform | 0.16 | `proc_name:cb.exe`, `proc_name:cramtray.exe`, `proc_name:csfalconcontainer.exe` |
| Cmd Del Execution | Local Scheduled Task Creation | 0.16 | `proc_cmdline:/f`, `proc_name:cmd.exe`, `proc_orig_name:cmd.exe` |
| Schtasks Folder Combos | Local Scheduled Task Creation | 0.16 | `proc_cmdline:/create`, `proc_name:schtasks.exe`, `proc_orig_name:schtasks.exe` |
| Schtasks Reg Loader | Local Scheduled Task Creation | 0.16 | `proc_cmdline:/create`, `proc_name:schtasks.exe`, `proc_orig_name:schtasks.exe` |
| Schtasks Reg Loader Encoded | Local Scheduled Task Creation | 0.16 | `proc_cmdline:/create`, `proc_name:schtasks.exe`, `proc_orig_name:schtasks.exe` |
| Wab Unusual Parents | Process Created with a Duplicated Token | 0.16 | `proc_parent_name:svchost.exe`, `proc_parent_name:wmiprvse.exe` |
| Wget Download Susp Locations | Suspicious Execution via Microsoft Office Add-Ins | 0.16 | `proc_cmdline::\\users\\public\\`, `proc_cmdline::\\windows\\temp\\`, `proc_cmdline:http` |
| Susp Download Office Domain | File Download Detected via Defend for Containers | 0.16 | `proc_cmdline:curl`, `proc_cmdline:wget` |
| Mshta Susp Pattern | Script Execution via Microsoft HTML Application | 0.16 | `proc_cmdline:.hta`, `proc_cmdline:.htm`, `proc_name:mshta.exe` |
| Susp Service Creation | Service Command Lateral Movement | 0.16 | `proc_cmdline:binpath=`, `proc_cmdline:create`, `proc_name:sc.exe` |
| Hktl Cobaltstrike Process Patterns | UAC Bypass Attempt with IEditionUpgradeManager Elevated COM Interface | 0.16 | `proc_parent_name:dllhost.exe` |
| Werfault Lsass Shtinkering | Unusual Execution via Microsoft Common Console File | 0.16 | `proc_name:werfault.exe` |
| Proc Access Win Malware Verclsid Shellcode | LSASS Memory Dump Handle Access | 0.16 | `access_mask:0x1fffff` |
| Proc Access Win Hktl Cobaltstrike Bof Injection Pattern | LSASS Memory Dump Handle Access | 0.16 | `access_mask:0x1fffff` |
| Proc Access Win Uac Bypass Wow64 Logger | LSASS Memory Dump Handle Access | 0.16 | `access_mask:0x1fffff` |
| Splwow64 Cli Anomaly | Suspicious Print Spooler SPL File Created | 0.16 | `proc_name:splwow64.exe` |
| Image Load Wmi Module Load By Uncommon Process | Statistical Model Detected C2 Beaconing Activity | 0.16 | `proc_name:msmpeng.exe`, `proc_name:waappagent.exe`, `proc_name:windowsazureguestagent.exe` |
| Gpg4Win Decryption | Attempt to Install Kali Linux via WSL | 0.16 | `proc_cmdline:-d` |
| Gpg4Win Encryption | Command Execution via ForFiles | 0.16 | `proc_cmdline:-c` |
| Winget Add Custom Source | BPF filter applied using TC | 0.16 | `proc_cmdline:add` |
| Winget Add Insecure Custom Source | BPF filter applied using TC | 0.16 | `proc_cmdline:add` |
| Winget Add Susp Custom Source | BPF filter applied using TC | 0.16 | `proc_cmdline:add` |
| Powershell Encode | Suspicious ScreenConnect Client Child Process | 0.16 | `proc_cmdline:-e`, `proc_cmdline:-ec`, `proc_cmdline:-enc` |
| Malware Pikabot Rundll32 Activity | Unusual Execution via Microsoft Common Console File | 0.16 | `proc_name:wermgr.exe` |
| Mstsc Remote Connection | Lateral Movement via Startup Folder | 0.16 | `proc_name:mstsc.exe` |
| Office Excel Dcom Lateral Movement | Suspicious Command Prompt Network Connection | 0.16 | `proc_parent_name:excel.exe` |
| Schtasks Delete | Suspicious Microsoft HTML Application Child Process | 0.16 | `proc_name:schtasks.exe` |
| Browsers Remote Debugging | Browser Extension Install | 0.15 | `proc_name:firefox.exe` |
| Browsers Tor Execution | Browser Extension Install | 0.15 | `proc_name:firefox.exe` |
| Renamed Whoami | Account Discovery Command via SYSTEM Account | 0.15 | `proc_name:whoami.exe` |
| Susp Alternate Data Streams | NTDS or SAM Database File Copied | 0.15 | `proc_cmdline:/d`, `proc_cmdline:/y` |
| Whoami Execution From High Priv Process | Account Discovery Command via SYSTEM Account | 0.15 | `proc_name:whoami.exe` |
| Papercut Print Management Exploitation Indicators | Suspicious Windows Powershell Arguments | 0.15 | `proc_cmdline:-outfile`, `proc_cmdline:invoke-webrequest` |
| Mstsc Run Local Rdp File Susp Location | Suspicious Microsoft Diagnostics Wizard Execution | 0.15 | `proc_cmdline::\\users\\public\\`, `proc_cmdline::\\windows\\temp\\` |
| Malware Pikabot Rundll32 Hollowing | Unusual Execution via Microsoft Common Console File | 0.15 | `proc_name:wermgr.exe` |
| Malware Rorschach Ransomware Activity | Potential CVE-2025-33053 Exploitation | 0.15 | `proc_name:netsh.exe` |
| Office Outlook Mail Credential | Unusual Web Config File Access | 0.15 | `proc_name:msmpeng.exe` |
| Reg Direct Asep Registry Keys Modification | Suspicious Microsoft HTML Application Child Process | 0.15 | `proc_name:reg.exe` |
| Reg Import From Suspicious Paths | Suspicious Microsoft HTML Application Child Process | 0.15 | `proc_name:reg.exe` |
| Malware Dridex | Suspicious MS Outlook Child Process | 0.15 | `proc_name:net.exe`, `proc_name:net1.exe`, `proc_name:regsvr32.exe` |
| Schtasks System | Local Scheduled Task Creation | 0.15 | `proc_cmdline:/create`, `proc_cmdline:/ru`, `proc_name:schtasks.exe` |
| Wuauclt Network Connection | ImageLoad via Windows Update Auto Update Client | 0.15 | `proc_cmdline:/runhandlercomserver` |
| Gup Download | Shell Execution via Apple Scripting | 0.15 | `proc_cmdline:http` |
| Lolbin Susp Driver Installed By Pnputil | Attempt to Install Kali Linux via WSL | 0.15 | `proc_cmdline:-i` |
| Uac Bypass Winsat | Network Connection via Registration Utility | 0.15 | `proc_integrity:system` |
| Registry Set Taskcache Entry | Suspicious Print Spooler SPL File Created | 0.15 | `proc_name:msiexec.exe`, `proc_name:svchost.exe`, `proc_name:system` |
| Registry Set Asep Reg Keys Modification Winsock2 | NullSessionPipe Registry Modification | 0.15 | `reg_data:(empty)` |
| Image Load Dll Azure Microsoft Account Token Provider Dll Load | Browser Process Spawned from an Unusual Parent | 0.15 | `proc_name:msedge.exe` |
| Forfiles Child Process Masquerading | Potential File Transfer via Curl for Windows | 0.15 | `proc_parent_name:forfiles.exe` |
| Mofcomp Execution | Whoami Process Activity | 0.15 | `proc_parent_name:cmd.exe`, `proc_parent_name:wmiprvse.exe` |
| Webshell Chopper | Microsoft Exchange Worker Spawning Suspicious Processes | 0.15 | `proc_parent_name:w3wp.exe` |
| Apt Sofacy | Control Panel Process with Unusual Arguments | 0.15 | `proc_cmdline:\\appdata\\local\\` |
| Apt Aptc12 Bluemushroom | Control Panel Process with Unusual Arguments | 0.15 | `proc_cmdline:\\appdata\\local\\` |
| Exploit Cve 2021 26084 Atlassian Confluence | Proxy Execution via Console Window Host | 0.15 | `proc_cmdline:curl`, `proc_cmdline:powershell` |
| Infdefaultinstall Execute Sct Scripts | Control Panel Process with Unusual Arguments | 0.15 | `proc_cmdline:.inf` |
| Powershell Download Susp File Sharing Domains | Microsoft Exchange Worker Spawning Suspicious Processes | 0.15 | `proc_name:powershell.exe`, `proc_name:pwsh.exe`, `proc_orig_name:powershell.exe` |
| Lolbin Gather Network Info Script Output | SELinux Configuration Creation or Renaming | 0.15 | `file_path:config` |
| Net Cli Artefact | Potential Command and Control via Internet Explorer | 0.15 | `proc_name:rundll32.exe`, `proc_parent_cmdline:-embedding` |
| Office Startup Persistence | Startup Persistence by a Suspicious Process | 0.14 | `proc_name:excel.exe`, `proc_name:winword.exe` |
| Iis Appcmd Http Logging | Service Command Lateral Movement | 0.14 | `proc_cmdline:config` |
| Iis Appcmd Susp Rewrite Rule | Service Command Lateral Movement | 0.14 | `proc_cmdline:config` |
| Powershell Download Dll | Shell Execution via Apple Scripting | 0.14 | `proc_cmdline:http` |
| Regedit Import Keys Ads | Unusual Base64 Encoding/Decoding Activity | 0.14 | `proc_cmdline:-a`, `proc_cmdline:-c`, `proc_cmdline:-e` |
| Winget Local Install Via Manifest | BPF filter applied using TC | 0.14 | `proc_cmdline:add` |
| Registry Set New Network Provider | Potential System Tampering via File Modification | 0.14 | `proc_name:poqexec.exe` |
| Registry Set Susp Printer Driver | NullSessionPipe Registry Modification | 0.14 | `reg_data:(empty)` |
| Curl Susp Download | Control Panel Process with Unusual Arguments | 0.14 | `proc_cmdline:.gif`, `proc_cmdline:.jpeg`, `proc_cmdline:.jpg` |
| Wmic Remote Execution | Suspicious Network Tool Launched Inside A Container | 0.14 | `proc_cmdline:127.0.0.1`, `proc_cmdline:localhost` |
| Taskkill Execution | High Number of Process and/or Service Terminations | 0.14 | `proc_cmdline:/f`, `proc_cmdline:/im`, `proc_cmdline:/pid` |
| User Driver Loaded | Suspicious Lsass Process Access | 0.14 | `proc_name:procexp.exe`, `proc_name:procexp64.exe`, `proc_name:procmon.exe` |
| Wscript Cscript Dropper | Proxy Execution via Console Window Host | 0.14 | `proc_cmdline:.js`, `proc_cmdline:.vbs` |
| Control Panel Item | Suspicious Microsoft HTML Application Child Process | 0.14 | `proc_name:reg.exe` |
| Hktl Powersploit Empire Default Schtasks | Suspicious Microsoft HTML Application Child Process | 0.14 | `proc_name:schtasks.exe` |
| Vscode Tunnel Remote Shell  | Elastic Defend Alert from GenAI Utility or Descendant | 0.14 | `proc_parent_name:node.exe` |
| Registry Set Disable Winevt Logging | RDP Enabled via Registry | 0.14 | `proc_name:svchost.exe`, `proc_name:tiworker.exe` |
| Schtasks Env Folder | Local Scheduled Task Creation | 0.14 | `proc_cmdline:-create`, `proc_cmdline:/create`, `proc_cmdline:/xml` |
| Susp System User Anomaly | Suspicious PDF Reader Child Process | 0.14 | `proc_name:cscript.exe`, `proc_name:forfiles.exe`, `proc_name:mshta.exe` |
| Susp Failed Logon Reasons | Potential Computer Account NTLM Relay Activity | 0.14 | `event_code:4625` |
| Proc Access Win Lsass Python Based Tool | LSASS Memory Dump Handle Access | 0.14 | `access_mask:0x1fffff` |
| Curl Download Direct Ip Exec | File Download Detected via Defend for Containers | 0.14 | `proc_cmdline:--output`, `proc_cmdline:--remote-name`, `proc_cmdline:-o` |
| Curl Download Direct Ip Susp Extensions | File Download Detected via Defend for Containers | 0.14 | `proc_cmdline:--output`, `proc_cmdline:--remote-name`, `proc_cmdline:-o` |
| Susp Creation By Mobsync | Suspicious Script Object Execution | 0.14 | `proc_name:mobsync.exe` |
| Sysinternals Procmon Driver Susp Creation | Suspicious Lsass Process Access | 0.14 | `proc_name:procmon.exe` |
| Regedit Import Keys | Unusual Base64 Encoding/Decoding Activity | 0.14 | `proc_cmdline:-a`, `proc_cmdline:-c`, `proc_cmdline:-e` |
| Squirrel Download | Shell Execution via Apple Scripting | 0.14 | `proc_cmdline:http` |
| Uac Bypass Changepk Slui | Network Connection via Registration Utility | 0.14 | `proc_integrity:system` |
| Registry Set Sip Persistence | SIP Provider Modification | 0.14 | `reg_data:mso.dll`, `reg_data:wintrust.dll` |
| Certutil Download File Sharing Domains | Suspicious CertUtil Commands | 0.14 | `proc_cmdline:urlcache`, `proc_cmdline:verifyctl`, `proc_name:certutil.exe` |
| Mssql Sqltoolsps Susp Execution | Conhost Spawned By Suspicious Parent Process | 0.14 | `proc_parent_name:smss.exe` |
| Susp Electron Execution Proxy | First Time Seen DNS Query to RMM Domain | 0.14 | `proc_name:chrome.exe`, `proc_name:msedge.exe`, `proc_name:msedgewebview2.exe` |
| Susp Userinit Child | Conhost Spawned By Suspicious Parent Process | 0.14 | `proc_parent_name:userinit.exe` |
| Userinit Uncommon Child Processes | Conhost Spawned By Suspicious Parent Process | 0.14 | `proc_parent_name:userinit.exe` |
| Susp Scheduled Task Creation | Remote Scheduled Task Creation via RPC | 0.14 |  |
| Susp Startup Folder Persistence | Startup Folder Persistence via Unsigned Process | 0.14 |  |
| Dump64 Defender Av Bypass Rename | Potential Credential Access via Windows Utilities | 0.13 | `proc_cmdline:-ma`, `proc_orig_name:procdump` |
| Susp Binary Dropper | Suspicious Print Spooler SPL File Created | 0.13 | `proc_name:.exe`, `proc_name:msiexec.exe`, `proc_name:svchost.exe` |
| Hktl Cobaltstrike Bloopers Cmd | Proxy Execution via Console Window Host | 0.13 | `proc_cmdline:cmd`, `proc_cmdline:cmd.exe` |
| Mpcmdrun Remove Windows Defender Definition | Windows Firewall Disabled via PowerShell | 0.13 | `proc_cmdline:-all` |
| Susp Obfuscated Ip Download | Suspicious Python Shell Command Execution | 0.13 | `proc_cmdline:curl`, `proc_cmdline:wget` |
| Proc Access Win Susp Direct Ntopenprocess Call | Potential Masquerading as Communication Apps | 0.13 | `proc_name:discord.exe`, `proc_name:teams.exe` |
| Schtasks Disable | Suspicious Microsoft HTML Application Child Process | 0.13 | `proc_name:schtasks.exe` |
| Apt Mint Sandstorm Aspera Faspex Susp Child Process | Suspicious ScreenConnect Client Child Process | 0.13 | `proc_cmdline:/add`, `proc_cmdline:downloadstring`, `proc_cmdline:http` |
| Sc Service Tamper For Persistence | Proxy Execution via Console Window Host | 0.13 | `proc_cmdline:.bat`, `proc_cmdline:.cmd`, `proc_cmdline:.js` |
| Vscode Tunnel Execution | Attempt to Establish VScode Remote Tunnel | 0.13 | `proc_cmdline:--accept-server-license-terms` |
| Net Quic | Mounting Hidden or WebDav Remote Shares | 0.13 | `proc_name:net.exe`, `proc_name:net1.exe`, `proc_orig_name:net.exe` |
| Python | Suspicious Installer Package Spawns Network Event | 0.13 | `proc_name:python` |
| Proc Access Win Susp All Access Uncommon Target | Connection to Commonly Abused Free SSL Certificate Providers | 0.13 | `proc_name:notepad.exe` |
| Certutil Decode | Suspicious Microsoft HTML Application Child Process | 0.13 | `proc_name:certutil.exe` |
| Reg Desktop Background Change | Suspicious Microsoft HTML Application Child Process | 0.13 | `proc_name:reg.exe` |
| Schtasks One Time Only Midnight Task | Suspicious Microsoft HTML Application Child Process | 0.13 | `proc_name:schtasks.exe` |
| Registry Event Esentutl Volume Shadow Copy Service Keys | NTDS or SAM Database File Copied | 0.13 | `proc_name:esentutl.exe` |
| Whoami Groups Discovery | Enumeration of Users or Groups via Built-in Commands | 0.13 | `proc_cmdline:/groups` |
| Disable Event Auditing | Sensitive Audit Policy Sub-Category Disabled | 0.13 | `event_code:4719` |
| Disable Event Auditing Critical | Sensitive Audit Policy Sub-Category Disabled | 0.13 | `event_code:4719` |
| Sc Service Path Modification | Proxy Execution via Console Window Host | 0.13 | `proc_cmdline:cmd`, `proc_cmdline:mshta`, `proc_cmdline:powershell` |
| Image Load Dll Sdiageng Load By Msdt | Suspicious Microsoft Diagnostics Wizard Execution | 0.13 | `proc_name:msdt.exe` |
| Malware Formbook | Suspicious Cmd Execution via WMI | 0.12 | `proc_cmdline:/c` |
| Malware Kapeka Backdoor Rundll32 Execution | Attempt to Install Kali Linux via WSL | 0.12 | `proc_cmdline:-d` |
| Exchange Webshell Drop Suspicious | Potential DLL Side-Loading via Trusted Microsoft Programs | 0.12 | `proc_name:w3wp.exe` |
| Image Load Dll Vssapi Susp Load | Process Execution from an Unusual Directory | 0.12 | `proc_name:systemsettings.exe` |
| Image Load Dll Vsstrace Susp Load | Process Execution from an Unusual Directory | 0.12 | `proc_name:systemsettings.exe` |
| Attrib System Susp Paths | Proxy Execution via Console Window Host | 0.12 | `proc_cmdline:.bat`, `proc_cmdline:.vbs` |
| Bcdedit Susp Execution | Backup Deletion with Wbadmin | 0.12 | `proc_cmdline:delete` |
| Createdump Lolbin Execution | Potential Linux Backdoor User Account Creation | 0.12 | `proc_cmdline:-u` |
| Googleupdate Susp Child Process | Process Execution from an Unusual Directory | 0.12 | `proc_name:setup.exe` |
| Hktl Soaphound Execution | Command Execution via ForFiles | 0.12 | `proc_cmdline:-c` |
| Mode Codepage Russian | Remote File Copy to a Hidden Share | 0.12 | `proc_cmdline:cp` |
| Net View Share And Sessions Enum | Service Command Lateral Movement | 0.12 | `proc_cmdline:\\\\` |
| Renamed Createdump | Potential Linux Backdoor User Account Creation | 0.12 | `proc_cmdline:-u` |
| Rundll32 Ntlmrelay | Shell Execution via Apple Scripting | 0.12 | `proc_cmdline:http` |
| Susp Disable Raccine | Backup Deletion with Wbadmin | 0.12 | `proc_cmdline:delete` |
| Whoami All Execution | Windows Firewall Disabled via PowerShell | 0.12 | `proc_cmdline:-all` |
| Registry Event Susp Atbroker Change | NullSessionPipe Registry Modification | 0.12 | `reg_data:(empty)` |
| Registry Set Asep Reg Keys Modification Wow6432Node Currentversion | NullSessionPipe Registry Modification | 0.12 | `reg_data:(empty)` |
| Susp Kerberos Manipulation | Suspicious Kerberos Authentication Ticket Request | 0.12 | `event_code:4768`, `event_code:4769` |
| Aadhealth Mon Agent Regkey Access | LSASS Memory Dump Handle Access | 0.12 | `event_code:4656` |
| Aadhealth Svc Agent Regkey Access | LSASS Memory Dump Handle Access | 0.12 | `event_code:4656` |
| Node Abuse | Unusual File Creation - Alternate Data Stream | 0.12 | `proc_name:node.exe` |
| Malware Babyshark | Script Execution via Microsoft HTML Application | 0.12 | `proc_cmdline:.hta` |
| Sysinternals Psloglist | Command Execution via ForFiles | 0.12 | `proc_cmdline:-c`, `proc_cmdline:-d`, `proc_cmdline:/c` |
| Reg Screensaver | Suspicious Microsoft HTML Application Child Process | 0.12 | `proc_name:reg.exe` |
| Whoami Output | Whoami Process Activity | 0.12 | `proc_name:whoami.exe` |
| Whoami Priv Discovery | Whoami Process Activity | 0.12 | `proc_name:whoami.exe` |
| Netsh Fw Allow Program In Susp Location | Remote Desktop Enabled in Windows Firewall by Netsh | 0.12 | `proc_cmdline:action=allow`, `proc_name:netsh.exe`, `proc_orig_name:netsh.exe` |
| Sysinternals Adexplorer Execution | Active Directory Discovery using AdExplorer | 0.12 | `proc_orig_name:adexp` |
| Sysinternals Adexplorer Susp Execution | Active Directory Discovery using AdExplorer | 0.12 | `proc_orig_name:adexp` |
| Notepad Plus Plus Persistence | Suspicious DLL Loaded for Persistence or Privilege Escalation | 0.12 | `file_path:.dll`, `proc_name:.exe` |
| Susp Lsass Dump Generic | LSASS Memory Dump Handle Access | 0.12 | `access_mask:0x1010`, `access_mask:0x1f3fff`, `event_code:4656` |
| Apt Evilnum Jul20 | Remote Management Access Launch After MSI Install | 0.12 | `proc_cmdline:/i` |
| Scheduled Task Deletion | Suspicious Execution via Scheduled Task | 0.12 |  |
| Dump File Creation | File Creation in /var/log via Suspicious Process | 0.12 |  |
| Explorer Child Of Shell Process | Suspicious Explorer Child Process | 0.12 |  |
| User Creation | User Account Creation | 0.12 |  |
| Creation System File | File Creation in /var/log via Suspicious Process | 0.12 |  |
| Dump File Susp Creation | File Creation in /var/log via Suspicious Process | 0.12 |  |
| Susp Powershell Profile | Persistence via PowerShell profile | 0.12 |  |
| Hktl Crackmapexec Execution | Unusual Base64 Encoding/Decoding Activity | 0.12 | `proc_cmdline:-d`, `proc_cmdline:-u` |
| Odbcconf Exec Susp Locations | Suspicious Execution via Microsoft Office Add-Ins | 0.12 | `proc_cmdline::\\programdata\\`, `proc_cmdline::\\users\\public\\`, `proc_cmdline::\\windows\\temp\\` |
| Powershell Run Script From Ads | Suspicious Powershell Script | 0.12 |  |
| Registry Set Persistence Chm | Registry Persistence via AppCert DLL | 0.12 |  |
| Registry Set Persistence Ie | Registry Persistence via AppCert DLL | 0.12 |  |
| Registry Set Persistence Xll | Registry Persistence via AppCert DLL | 0.12 |  |
| Registry Set Asep Reg Keys Modification System Scripts | NullSessionPipe Registry Modification | 0.12 | `reg_data:(empty)` |
| Registry Set Malware Raspberry Robin Internet Settings Zonemap Tamper | Control Panel Process with Unusual Arguments | 0.12 | `proc_name:control.exe` |
| Create Remote Thread Win Susp Uncommon Target Image | Connection to Commonly Abused Free SSL Certificate Providers | 0.12 | `proc_name:explorer.exe`, `proc_name:notepad.exe` |
| Apt Mustangpanda | System File Ownership Change | 0.12 | `proc_cmdline:/f` |
| Expand Cabinet Files | Suspicious Microsoft Diagnostics Wizard Execution | 0.12 | `proc_cmdline::\\users\\public\\`, `proc_cmdline::\\windows\\temp\\` |
| Verclsid Runs Com | Suspicious Cmd Execution via WMI | 0.12 | `proc_cmdline:/c` |
| Apt Mint Sandstorm Manage Engine Susp Child Process | Suspicious ScreenConnect Client Child Process | 0.11 | `proc_cmdline:/add`, `proc_cmdline:downloadstring`, `proc_cmdline:http` |
| Susp Event Log Query | Command Obfuscation via Unicode Modifier Letters | 0.11 | `proc_name:wevtutil.exe`, `proc_name:wmic.exe`, `proc_orig_name:wevtutil.exe` |
| Wmic Service Manipulation | Elastic Agent Service Terminated | 0.11 | `proc_cmdline:stopservice`, `proc_name:wmic.exe` |
| Wmic Terminate Application | Elastic Agent Service Terminated | 0.11 | `proc_cmdline:terminate`, `proc_name:wmic.exe` |
| Wmic Uninstall Application | Elastic Agent Service Terminated | 0.11 | `proc_cmdline:uninstall`, `proc_name:wmic.exe` |
| Wmic Namespace Defender | Suspicious Execution from a Mounted Device | 0.11 | `proc_name:wmic.exe` |
| Wmic Recon Computersystem | Suspicious Execution from a Mounted Device | 0.11 | `proc_name:wmic.exe` |
| Wmic Recon Csproduct | Suspicious Execution from a Mounted Device | 0.11 | `proc_name:wmic.exe` |
| Wmic Recon Hotfix | Suspicious Execution from a Mounted Device | 0.11 | `proc_name:wmic.exe` |
| Wmic Recon Product Class | Suspicious Execution from a Mounted Device | 0.11 | `proc_name:wmic.exe` |
| Wmic Recon Service | Suspicious Execution from a Mounted Device | 0.11 | `proc_name:wmic.exe` |
| Wmic Recon System Info Uncommon | Suspicious Execution from a Mounted Device | 0.11 | `proc_name:wmic.exe` |
| Wmic Recon Unquoted Service Search | Suspicious Execution from a Mounted Device | 0.11 | `proc_name:wmic.exe` |
| Wmic Recon Volume | Suspicious Execution from a Mounted Device | 0.11 | `proc_name:wmic.exe` |
| Esentutl Params | Encrypting Files with WinRar or 7z | 0.11 | `proc_cmdline:/p` |
| Query Win Remote Access Software Domains Non Browsers | First Time Seen DNS Query to RMM Domain | 0.11 | `proc_name:brave.exe`, `proc_name:chrome.exe`, `proc_name:firefox.exe` |
| Dsquery Domain Trust Discovery | Enumerating Domain Trusts via DSQUERY.EXE | 0.11 | `proc_name:dsquery.exe`, `proc_orig_name:dsquery.exe` |
| Vaultcmd List Creds | Searching for Saved Credentials via VaultCmd | 0.11 | `proc_name:vaultcmd.exe`, `proc_orig_name:vaultcmd.exe` |
| Remote Access Tools Screenconnect Remote Execution | Suspicious ScreenConnect Client Child Process | 0.11 | `proc_name:cmd.exe`, `proc_parent_name:screenconnect.clientservice.exe` |
| Apt Revil Kaseya | Unusual Web Config File Access | 0.11 | `proc_name:msmpeng.exe` |
| Image Load Side Load Keyscrambler | Untrusted DLL Loaded by Azure AD Sync Service | 0.11 | `file.code_signature.status:valid` |
| Bitsadmin Download Direct Ip | Suspicious Execution from a Mounted Device | 0.11 | `proc_name:bitsadmin.exe` |
| Certutil Encode Susp Location | Suspicious Microsoft HTML Application Child Process | 0.11 | `proc_name:certutil.exe` |
| Lodctr Performance Counter Tampering | Suspicious SolarWinds Child Process | 0.11 | `proc_name:lodctr.exe` |
| Powershell Enable Susp Windows Optional Feature | Windows Subsystem for Linux Enabled via Dism Utility | 0.11 | `proc_cmdline:microsoft-windows-subsystem-linux` |
| Susp Obfuscated Ip Via Cli | Suspicious SolarWinds Child Process | 0.11 | `proc_name:arp.exe` |
| Sysinternals Procdump Evasion | Remote File Copy to a Hidden Share | 0.11 | `proc_cmdline:copy` |
| Uac Bypass Computerdefaults | Network Connection via Registration Utility | 0.11 | `proc_integrity:system` |
| Powershell Base64 Hidden Flag | Microsoft Exchange Worker Spawning Suspicious Processes | 0.11 | `proc_name:powershell.exe`, `proc_name:pwsh.exe`, `proc_orig_name:powershell.exe` |
| Python Path Configuration Files | Suspicious Execution from VS Code Extension | 0.11 | `proc_name:python.exe` |
| Mshta Susp Execution | Control Panel Process with Unusual Arguments | 0.11 | `proc_cmdline:.bmp`, `proc_cmdline:.gif`, `proc_cmdline:.jpg` |
| Registry Event Scheduled Task Creation | Remote Scheduled Task Creation via RPC | 0.11 |  |
| Codeintegrity Revoked Driver Loaded | Expired or Revoked Driver Loaded | 0.11 |  |
| Hidden User Creation | Creation of a Hidden Local User Account | 0.11 |  |
| Mpcmdrun Download Arbitrary File | Remote File Download via MpCmdRun | 0.11 |  |
| Registry New Network Provider | Network Logon Provider Registry Modification | 0.11 |  |
| Registry Event Office Test Regadd | Office Test Registry Persistence | 0.11 |  |
| Susp Appx Execution | GenAI Process Performing Encoding/Chunking Prior to Network Activity | 0.11 | `proc_cmdline:base64`, `proc_name:powershell.exe`, `proc_name:pwsh.exe` |
| Create Non Existent Dlls | Suspicious DLL Loaded for Persistence or Privilege Escalation | 0.11 | `file_path:oci.dll`, `file_path:wbemcomn.dll` |
| Exploit Cve 2020 1048 | Suspicious Command Prompt Network Connection | 0.11 | `proc_cmdline:.bat` |
| Hktl Crackmapexec Patterns | Suspicious Cmd Execution via WMI | 0.11 | `proc_cmdline:\\windows\\temp\\` |
| Schtasks Susp Pattern | Suspicious ScreenConnect Client Child Process | 0.11 | `proc_cmdline:-enc`, `proc_cmdline:/create`, `proc_name:schtasks.exe` |
| Registry Set Exploit Cve 2020 1048 New Printer Port | Potential Persistence via Time Provider Modification | 0.11 | `reg_data:.dll` |
| Office Uncommon File Startup | Startup Persistence by a Suspicious Process | 0.11 | `proc_name:excel.exe`, `proc_name:winword.exe` |
| Bitsadmin Download Susp Extensions | Control Panel Process with Unusual Arguments | 0.11 | `proc_cmdline:.gif`, `proc_cmdline:.jpeg`, `proc_cmdline:.jpg` |
| Rdrleakdiag Process Dumping | Encrypting Files with WinRar or 7z | 0.11 | `proc_cmdline:-p`, `proc_cmdline:/p` |
| Susp Eventlog Content Recon | Command Obfuscation via Unicode Modifier Letters | 0.11 | `proc_name:wevtutil.exe`, `proc_name:wmic.exe`, `proc_orig_name:wevtutil.exe` |
| Registry Set Cobaltstrike Service Installs | Suspicious ImagePath Service Creation | 0.11 | `reg_data:%comspec%` |
| Regsvr32 Flags Anomaly | Delayed Execution via Ping | 0.10 | `proc_cmdline:-n`, `proc_name:regsvr32.exe` |
| Uac Bypass Ntfs Reparse Point | Network Connection via Registration Utility | 0.10 | `proc_integrity:system` |
| Registry Set Persistence Event Viewer Events Asp | NullSessionPipe Registry Modification | 0.10 | `reg_data:(empty)` |
| Apt Unc2452 Cmds | Suspicious Print Spooler File Deletion | 0.10 | `proc_name:dllhost.exe` |
| Malware Adwind | Proxy Execution via Console Window Host | 0.10 | `proc_cmdline:.vbs` |
| Browsers Chromium Headless Debugging | Proxy Execution via Console Window Host | 0.10 | `proc_cmdline:--headless` |
| Hktl Invoke Obfuscation Clip | Proxy Execution via Console Window Host | 0.10 | `proc_cmdline:cmd` |
| Susp Embed Exe Lnk | Proxy Execution via Console Window Host | 0.10 | `proc_cmdline:powershell` |
| Susp Raccess Sensitive Fext | Potential Machine Account Relay Attack via SMB | 0.10 | `event_code:5145` |
| Pipe Created Hktl Efspotato | Potential NTLM Relay Attack against a Computer Account | 0.10 | `file_name:srvsvc` |
| Adplus Memory Dump | Potential Upgrade of Non-interactive Shell | 0.10 | `proc_cmdline:-c` |
| Hktl Cobaltstrike Bloopers Modules | PowerShell Share Enumeration Script | 0.10 | `proc_cmdline:invoke-sharefinder` |
| Hktl Invoke Obfuscation Via Var | Suspicious Cmd Execution via WMI | 0.10 | `proc_cmdline:/c` |
| Hktl Krbrelay | PowerShell Mailbox Collection Script | 0.10 | `proc_cmdline:session` |
| Svchost Uncommon Parent Process | Unusual Parent-Child Relationship | 0.10 | `proc_name:svchost.exe`, `proc_parent_name:msmpeng.exe`, `proc_parent_name:services.exe` |
| Proc Access Win Lsass Susp Access Flag | Suspicious Lsass Process Access | 0.10 | `access_mask:0x100000`, `access_mask:0x40`, `proc_name:lsass.exe` |
| Image Load Side Load Vivaldi Elf | Suspicious HTML File Creation | 0.10 | `proc_name:vivaldi.exe` |
| Proc Tampering Susp Process Hollowing | Suspicious HTML File Creation | 0.10 | `proc_name:opera.exe` |
| Domain Dead Drop Resolvers | First Time Seen DNS Query to RMM Domain | 0.10 | `proc_name:brave.exe`, `proc_name:chrome.exe`, `proc_name:firefox.exe` |
| Sysinternals Procdump | Potential Credential Access via Windows Utilities | 0.10 | `proc_name:procdump.exe` |
| Mal Cosmik Duke Persistence | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| System Apt Stonedrill | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Apt Carbonpaper Turla | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Apt Turla Service Png | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Apt Oilrig Mar18 | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Malware Coldsteel Persistence Service | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| Hybridconnectionmgr Svc Installation | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| Invoke Obfuscation Clip Services Security | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| Invoke Obfuscation Obfuscated Iex Services Security | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| Invoke Obfuscation Var Services Security | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| Invoke Obfuscation Via Compress Services Security | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| Invoke Obfuscation Via Stdin Services Security | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| Invoke Obfuscation Via Use Clip Services Security | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| Invoke Obfuscation Via Use Mshta Services Security | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| Invoke Obfuscation Via Var Services Security | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| Mal Creddumper | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| Metasploit Or Impacket Smb Psexec Service Install | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| Pcap Drivers | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| Service Install Remote Access Software | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| Tap Driver Installation | Suspicious Service was Installed in the System | 0.10 | `event_code:4697` |
| System Hack Smbexec | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Invoke Obfuscation Clip Services | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Invoke Obfuscation Obfuscated Iex Services | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Invoke Obfuscation Var Services | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Invoke Obfuscation Via Compress Services | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Invoke Obfuscation Via Stdin Services | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Invoke Obfuscation Via Use Clip Services | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Invoke Obfuscation Via Use Mshta Services | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Krbrelayup Service Installation | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Mal Creddumper | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Moriya Rootkit | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Service Install Anydesk | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Service Install Csexecsvc | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Service Install Hacktools | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Service Install Mesh Agent | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Service Install Paexec | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Service Install Pdqdeploy | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Service Install Pdqdeploy Runner | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Service Install Pua Proceshacker | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Service Install Remote Utilities | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Service Install Sliver | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Service Install Susp | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Service Install Tacticalrmm | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Service Install Tap Driver | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Susp Rtcore64 Service Install | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| System Susp Service Installation Folder Pattern | Suspicious Service was Installed in the System | 0.10 | `event_code:7045` |
| Webshell Hacking | Command Obfuscation via Unicode Modifier Letters | 0.10 | `proc_name:ntdsutil.exe`, `proc_name:procdump.exe`, `proc_name:vssadmin.exe` |
| Registry Set Add Port Monitor | Unusual Print Spooler Child Process | 0.09 | `proc_name:spoolsv.exe` |
| System Invoke Obfuscation Via Var Services | Suspicious Service was Installed in the System | 0.09 | `event_code:7045` |
| Hktl Meterpreter Getsystem | Suspicious Command Prompt Network Connection | 0.09 | `proc_cmdline:/c` |
| Pua Cleanwipe | Suspicious Execution with NodeJS | 0.09 | `proc_cmdline:-r` |
| Sqlcmd Veeam Db Recon | PowerShell Script with Veeam Credential Access Capabilities | 0.09 | `proc_cmdline:veeambackup` |
| Teams Suspicious Objectaccess | Potential Masquerading as Communication Apps | 0.09 | `proc_name:teams.exe` |
| Teams Sensitive Files | Potential Masquerading as Communication Apps | 0.09 | `proc_name:teams.exe` |
| Ntds Dit Uncommon Process | Suspicious Execution via Windows Subsystem for Linux | 0.09 | `proc_name:wsl.exe` |
| Renamed Msteams | Potential Masquerading as Communication Apps | 0.09 | `proc_name:teams.exe` |
| Teams Suspicious Command Line Cred Access | Potential Masquerading as Communication Apps | 0.09 | `proc_name:teams.exe` |
| Pua Nircmd | Interactive Terminal Spawned via Perl | 0.09 | `proc_cmdline:exec` |
| Python Inline Command Execution | Execution with Explicit Credentials via Scripting | 0.09 | `proc_parent_name:python` |
| Vmware Toolbox Cmd Persistence Susp | Proxy Execution via Console Window Host | 0.09 | `proc_cmdline:script` |
| File Access Browser Credential | Unusual Web Config File Access | 0.09 | `proc_name:msmpeng.exe` |
| Registry Delete Removal Com Hijacking Registry Key | Suspicious JetBrains TeamCity Child Process | 0.09 | `proc_name:explorer.exe`, `proc_name:msiexec.exe`, `proc_name:reg.exe` |
| Apt Diamond Sleet Scheduled Task | Suspicious Execution via Scheduled Task | 0.09 |  |
| Powershell Network Connection | Suspicious Network Connection via systemd | 0.09 |  |
| Sc Query | Service DACL Modification via sc.exe | 0.09 | `proc_name:sc.exe`, `proc_orig_name:sc.exe` |
| Account Discovery | AWS Account Discovery By Rare User | 0.09 |  |
| Susp Scheduled Task Delete Or Disable | Suspicious Execution via Scheduled Task | 0.09 |  |
| Lsass Shtinkering | LSASS Process Access via Windows API | 0.09 |  |
| Mysqld Uncommon File Creation | File Creation in /var/log via Suspicious Process | 0.09 |  |
| New Scr File | Sudoers File Activity | 0.09 |  |
| Powershell Drop Binary Or Script | Suspicious Powershell Script | 0.09 |  |
| Powershell Module Creation | Dracut Module Creation | 0.09 |  |
| Powershell Module Susp Creation | Dracut Module Creation | 0.09 |  |
| Susp Vscode Powershell Profile | Persistence via PowerShell profile | 0.09 |  |
| Image Load Side Load Office Dlls | Suspicious WMI Image Load from MS Office | 0.09 |  |
| Findstr Lsass | LSASS Process Access via Windows API | 0.09 |  |
| Ilasm Il Code Compilation | Suspicious .NET Code Compilation | 0.09 |  |
| Lolbin Wfc | AWS EC2 LOLBin Execution via SSM SendCommand | 0.09 |  |
| Lsass Process Clone | LSASS Process Access via Windows API | 0.09 |  |
| Msiexec Web Install | Potential Remote Install via MsiExec | 0.09 |  |
| Ping Hex Ip | Delayed Execution via Ping | 0.09 |  |
| Powershell Download Iex | Remote File Download via PowerShell | 0.09 |  |
| Powershell Script Engine Parent | Suspicious Powershell Script | 0.09 |  |
| Renamed Ftp | Suspicious File Renamed via SMB | 0.09 |  |
| Sc Query Interesting Services | Service DACL Modification via sc.exe | 0.09 | `proc_name:sc.exe`, `proc_orig_name:sc.exe` |
| Schtasks Powershell Persistence | Persistence via PowerShell profile | 0.09 |  |
| Susp Execution Path | Suspicious Path Mounted | 0.09 |  |
| Susp Lsass Dmp Cli Keywords | LSASS Process Access via Windows API | 0.09 |  |
| Susp Service Dir | Chkconfig Service Add | 0.09 |  |
| Susp Whoami As Param | Whoami Process Activity | 0.09 |  |
| Wget Download Susp File Sharing Domains | Executable File Download via Wget | 0.09 |  |
| Wuauclt No Cli Flags Execution | ImageLoad via Windows Update Auto Update Client | 0.09 | `proc_name:wuauclt.exe`, `proc_orig_name:wuauclt.exe` |
| Registry Event Add Local Hidden User | Creation of a Hidden Local User Account | 0.09 |  |
| Registry Event Runonce Persistence | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Event Susp Mic Cam Access | RDP Enabled via Registry | 0.09 |  |
| Registry Set Dbgmanageddebugger Persistence | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Set Disabled Microsoft Defender Eventlog | Windows Defender Disabled via Registry Modification | 0.09 |  |
| Registry Set Disabled Pua Protection On Microsoft Defender | Windows Defender Disabled via Registry Modification | 0.09 |  |
| Registry Set Hhctrl Persistence | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Set Persistence App Paths | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Set Persistence Autodial Dll | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Set Persistence Com Key Linking | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Set Persistence Globalflags | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Set Persistence Ifilter | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Set Persistence Lsa Extension | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Set Persistence Mpnotify | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Set Persistence Mycomputer | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Set Persistence Reflectdebugger | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Set Persistence Scrobj Dll | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Set Powershell Enablescripts Enabled | RDP Enabled via Registry | 0.09 |  |
| Registry Set Powershell Logging Disabled | PowerShell Script Block Logging Disabled | 0.09 |  |
| Registry Set Telemetry Persistence | Registry Persistence via AppCert DLL | 0.09 |  |
| Registry Set Tls Protocol Old Version Enabled | RDP Enabled via Registry | 0.09 |  |
| Registry Set Treatas Persistence | Registry Persistence via AppCert DLL | 0.09 |  |
| Wget Download Direct Ip | Suspicious ScreenConnect Client Child Process | 0.09 | `proc_cmdline:http`, `proc_name:wget.exe` |
| Hktl Pypykatz | Network Activity to a Suspicious Top Level Domain | 0.09 | `proc_name:python.exe` |
| Python Adidnsdump | Network Activity to a Suspicious Top Level Domain | 0.09 | `proc_name:python.exe` |
| Python Pty Spawn | Network Activity to a Suspicious Top Level Domain | 0.09 | `proc_name:python.exe` |
| Registry Set Disable Autologger Sessions | Unusual Web Config File Access | 0.09 | `proc_name:msmpeng.exe` |
| Malware Emotet Loader Execution | Proxy Execution via Console Window Host | 0.09 | `proc_cmdline:.vbs` |
| Browsers Credential | Unusual Web Config File Access | 0.09 | `proc_name:msmpeng.exe` |
| Registry Set Servicedll Hijack | Potential System Tampering via File Modification | 0.09 | `proc_name:poqexec.exe` |
| Registry Set Asep Reg Keys Modification Session Manager | NullSessionPipe Registry Modification | 0.09 | `reg_data:(empty)` |
| System Service Install Uncommon | Suspicious Service was Installed in the System | 0.09 | `event_code:7045` |
| Iis Appcmd Susp Module Install | Node.js Pre or Post-Install Script Execution | 0.09 | `proc_cmdline:install` |
| Raw Access Thread Susp Disk Access Using Uncommon Tools | Unusual Web Config File Access | 0.08 | `proc_name:msmpeng.exe` |
| Hktl Zipexec | Enumeration of Administrator Accounts | 0.08 | `proc_cmdline:/delete` |
| Exploit Other Win Server Undocumented Rce | Potential Timestomp in Executable Files | 0.08 | `user_name:network service` |
| Hktl Krbrelayup | Attempt to Install Kali Linux via WSL | 0.08 | `proc_cmdline:-d` |
| Susp Privilege Escalation Cli Patterns | Proxy Execution via Console Window Host | 0.08 | `proc_cmdline:powershell` |
| Registry Set Asep Reg Keys Modification Currentcontrolset | Suspicious Print Spooler SPL File Created | 0.08 | `proc_name:poqexec.exe`, `proc_name:spoolsv.exe` |
| Curl Download Susp File Sharing Domains | File Download Detected via Defend for Containers | 0.08 | `proc_cmdline:--output`, `proc_cmdline:--remote-name`, `proc_cmdline:-o` |
| Certoc Load Dll Susp Locations | Suspicious Execution via Scheduled Task | 0.08 | `proc_cmdline:c:\\windows\\tasks\\`, `proc_cmdline:c:\\windows\\temp\\` |
| Remote Access Tools Anydesk Revoked Cert | File Deletion via Shred | 0.08 | `proc_cmdline:--remove` |
| Lolbin Printbrm | Curl Execution via Shell Profile | 0.08 | `proc_cmdline:-f` |
| Office Onenote Embedded Script Execution | Potential File Download via a Headless Browser | 0.08 | `proc_parent_name:onenote.exe` |
| Malware Goofy Guineapig Googleupdate Uncommon Child Instance | Unusual Parent Process for cmd.exe | 0.08 | `proc_parent_name:googleupdate.exe` |
| Malware Kapeka Backdoor Scheduled Task Creation | Remote Scheduled Task Creation via RPC | 0.08 |  |
| System Volume Shadow Copy Mount | Volume Shadow Copy Deletion via PowerShell | 0.08 |  |
| Sysinternals Sdelete File Deletion | Potential Secure File Deletion via SDelete Utility | 0.08 |  |
| Creation Unquoted Service Path | Potential Exploitation of an Unquoted Service Path Vulnerability | 0.08 |  |
| Image Load Side Load Cpl From Non System Location | Suspicious WMI Image Load from MS Office | 0.08 |  |
| Image Load Side Load From Non System Location | Suspicious WMI Image Load from MS Office | 0.08 |  |
| Proc Access Win Svchost Credential Dumping | Potential Linux Credential Dumping via Proc Filesystem | 0.08 |  |
| 7Zip Exfil Dmp Files | Encrypting Files with WinRar or 7z | 0.08 | `proc_name:7z.exe`, `proc_name:7za.exe`, `proc_orig_name:7z.exe` |
| Registry Privilege Escalation Via Service Key | Potential Privilege Escalation via Service ImagePath Modification | 0.08 |  |
| Registry Set Disabled Exploit Guard Net Protection On Ms Defender | Windows Defender Disabled via Registry Modification | 0.08 |  |
| Registry Set Office Outlook Security Settings | MS Office Macro Security Registry Modifications | 0.08 |  |
| Registry Set Persistence Shim Database Uncommon Location | Uncommon Registry Persistence Change | 0.08 |  |
| Apt Muddywater Activity | Proxy Execution via Console Window Host | 0.08 | `proc_cmdline:powershell` |
| Msiexec Execute Dll | NTDS or SAM Database File Copied | 0.08 | `proc_cmdline:/y` |
| Powershell Sam Access | NTDS or SAM Database File Copied | 0.08 | `proc_cmdline:copy-item` |
| Reg Bitlocker | High Number of Process and/or Service Terminations | 0.08 | `proc_cmdline:/f` |
| Regedit Export Critical Keys | Kernel Load or Unload via Kexec Detected | 0.08 | `proc_cmdline:-e` |
| Regedit Export Keys | Kernel Load or Unload via Kexec Detected | 0.08 | `proc_cmdline:-e` |
| Sqlite Chromium Profile Data | NTDS or SAM Database File Copied | 0.08 | `proc_cmdline:\\user data\\` |
| Susp Non Priv Reg Or Ps | Proxy Execution via Console Window Host | 0.08 | `proc_cmdline:powershell` |
| Systeminfo Execution | Enumeration Command Spawned via WMIPrvSE | 0.08 | `proc_name:systeminfo.exe` |
| Hktl Covenant | Suspicious Windows Powershell Arguments | 0.08 | `proc_cmdline:-encodedcommand` |
| Powershell Exec Data File | Suspicious Execution via Windows Subsystem for Linux | 0.08 | `proc_cmdline:cat` |
| Reg Rdp Keys Tamper | Suspicious Microsoft HTML Application Child Process | 0.08 | `proc_name:reg.exe` |
| Remote Time Discovery | Suspicious MS Outlook Child Process | 0.08 | `proc_name:net.exe`, `proc_name:net1.exe` |
| Registry Set Renamed Sysinternals Eula Accepted | Suspicious Lsass Process Access | 0.07 | `proc_name:procexp.exe`, `proc_name:procexp64.exe` |
| Wmic Susp Process Creation | Proxy Execution via Console Window Host | 0.07 | `proc_cmdline:mshta`, `proc_cmdline:powershell` |
| Registry Set Asep Reg Keys Modification Classes | NullSessionPipe Registry Modification | 0.07 | `reg_data:(empty)` |
| Exploit Cve 2021 35211 Servu | Suspicious Python Shell Command Execution | 0.07 | `proc_cmdline:whoami` |
| Susp Jwt Token Search | Suspicious Python Shell Command Execution | 0.07 | `proc_cmdline:find` |
| Susp Scheduled Task Update | Unusual Scheduled Task Update | 0.07 | `event_code:4702` |
| Bitsadmin Download File Sharing Domains | Suspicious Execution from a WebDav Share | 0.07 | `proc_cmdline:trycloudflare.com`, `proc_name:bitsadmin.exe` |
| Malware Coldsteel Service Dll Creation | GCP Service Account Key Creation | 0.07 |  |
| Registry Event Apt Diamond Sleet Scheduled Task | Suspicious Execution via Scheduled Task | 0.07 |  |
| Apt Fin7 Powertrash Lateral Movement | WMI Incoming Lateral Movement | 0.07 |  |
| Dfsvc Child Processes | Unusual Child Processes of RunDLL32 | 0.07 |  |
| Mssql Failed Logon | Spike in Failed Logon Events | 0.07 |  |
| Codeintegrity Unsigned Driver Loaded | Untrusted Driver Loaded | 0.07 |  |
| Codeintegrity Unsigned Image Loaded | Unsigned DLL Loaded by Svchost | 0.07 |  |
| Ntlm Brute Force | AWS S3 Bucket Enumeration or Brute Force | 0.07 |  |
| External Device | Spike in Bytes Sent to an External Device | 0.07 |  |
| System Defender Disabled | Windows Defender Disabled via Registry Modification | 0.07 |  |
| System Service Terminated Unexpectedly | Suspicious Service was Installed in the System | 0.07 |  |
| Driver Load Win Mal Drivers Names | Kernel Driver Load | 0.07 |  |
| Office Addin Persistence | Persistence via Microsoft Office AddIns | 0.07 |  |
| Remote Access Tools Screenconnect Remote File | Remote Execution via File Shares | 0.07 |  |
| Susp Desktopimgdownldr File | Remote File Download via Desktopimgdownldr Utility | 0.07 |  |
| Susp Teamviewer Remote Session | Remote File Copy via TeamViewer | 0.07 |  |
| Taskmgr Lsass Dump | LSASS Memory Dump Creation | 0.07 |  |
| Image Load Dll Rstrtmgr Suspicious Load | Suspicious WMI Image Load from MS Office | 0.07 |  |
| Image Load Side Load 7Za | Suspicious WMI Image Load from MS Office | 0.07 |  |
| Susp Outbound Mobsync Connection | Perl Outbound Network Connection | 0.07 |  |
| Agentexecutor Potential Abuse | Potential LSA Authentication Package Abuse | 0.07 |  |
| Configsecuritypolicy Download File | Git Repository or File Download to Suspicious Directory | 0.07 |  |
| Dotnetdump Memory Dump | LSASS Memory Dump Creation | 0.07 |  |
| Hktl Mimikatz Command Line | SystemKey Access via Command Line | 0.07 |  |
| Office Outlook Susp Child Processes Remote | Suspicious MS Office Child Process | 0.07 |  |
| Plink Port Forwarding | Port Forwarding Rule Addition | 0.07 |  |
| Powershell Downgrade Attack | Potential HTTP Downgrade Attack | 0.07 |  |
| Powershell Download Com Cradles | Remote File Download via PowerShell | 0.07 |  |
| Powershell Export Certificate | Exchange Mailbox Export via PowerShell | 0.07 |  |
| Powershell Run Script From Input Stream | Suspicious Powershell Script | 0.07 |  |
| Registry Typed Paths Persistence | Registry Persistence via AppCert DLL | 0.07 |  |
| Sndvol Susp Child Processes | Unusual Child Processes of RunDLL32 | 0.07 |  |
| Susp Network Scan Loop | Potential Network Scan Detected | 0.07 |  |
| Susp Script Exec From Env Folder | Windows Script Execution from Archive | 0.07 |  |
| Susp Script Exec From Temp | Windows Script Execution from Archive | 0.07 |  |
| Tasklist Module Enumeration | Unusual Kernel Module Enumeration | 0.07 |  |
| Winrar Exfil Dmp Files | Encrypting Files with WinRar or 7z | 0.07 |  |
| Wmi Persistence Script Event Consumer | Executable Bit Set for Potential Persistence Script | 0.07 |  |
| Wpbbin Potential Persistence | Potential Persistence via File Modification | 0.07 |  |
| Registry Set Change Rdp Port | Uncommon Registry Persistence Change | 0.07 |  |
| Registry Set Crashdump Disabled | Windows Defender Disabled via Registry Modification | 0.07 |  |
| Registry Set Creation Service Susp Folder | GCP Service Account Key Creation | 0.07 |  |
| Registry Set Defender Exclusions | Windows Defender Disabled via Registry Modification | 0.07 |  |
| Registry Set Disable Windows Firewall | Attempt to Disable IPTables or Firewall | 0.07 |  |
| Registry Set Hangs Debugger Persistence | Registry Persistence via AppCert DLL | 0.07 |  |
| Registry Set Hide File | Windows Registry File Creation in SMB Share | 0.07 |  |
| Registry Set Office Enable Dde | Office Test Registry Persistence | 0.07 |  |
| Registry Set Persistence Amsi Providers | Registry Persistence via AppCert DLL | 0.07 |  |
| Registry Set Persistence Appx Debugger | Registry Persistence via AppCert DLL | 0.07 |  |
| Registry Set Persistence Comhijack Psfactorybuffer | Registry Persistence via AppCert DLL | 0.07 |  |
| Registry Set Persistence Natural Language | Registry Persistence via AppCert DLL | 0.07 |  |
| Registry Set Persistence Outlook Homepage | Registry Persistence via AppCert DLL | 0.07 |  |
| Registry Set Persistence Outlook Todaypage | Registry Persistence via AppCert DLL | 0.07 |  |
| Registry Set Persistence Typed Paths | Registry Persistence via AppCert DLL | 0.07 |  |
| Registry Set Services Etw Tamper | SolarWinds Process Disabling Services via Registry | 0.07 |  |
| Registry Set Wab Dllpath Reg Change | Uncommon Registry Persistence Change | 0.07 |  |
| Registry Set Windows Defender Tamper | Windows Defender Disabled via Registry Modification | 0.07 |  |
| File Block Executable | Executable File Download via Wget | 0.07 |  |
| File Executable Detected | Executable File Download via Wget | 0.07 |  |
| Susp File Sharing Domains Susp Folders | Connection to Commonly Abused Web Services | 0.07 | `dns_name:cdn.discordapp.com`, `dns_name:gofile.io`, `dns_name:paste.ee` |
| Susp Initiated Uncommon Or Suspicious Locations | Connection to Commonly Abused Web Services | 0.07 | `dns_name:cdn.discordapp.com`, `dns_name:gofile.io`, `dns_name:paste.ee` |
| Bitsadmin Download Susp Targetfolder | Control Panel Process with Unusual Arguments | 0.07 | `proc_cmdline::\\users\\public\\`, `proc_cmdline:\\appdata\\local\\` |
| Csc Susp Dynamic Compilation | Microsoft Exchange Worker Spawning Suspicious Processes | 0.07 | `proc_parent_name:w3wp.exe` |

---

## ❓ Uncompared — Check Manually (38 rules)

These rules use regex patterns or event-code-only conditions that couldn't be parsed structurally. Check whether an Elastic equivalent exists.

| Rule | Query |
|------|-------|
| Driver Load Win Susp Temp Use | `any where file.path:"*\\Temp\\*"` |
| Susp Credential Manager Access | `any where (file.path like~ ("*\\AppData\\Local\\Microsoft\\Credentials\\*", "*\\AppData\\Roaming\\Mi…` |
| Susp Gpo Access Uncommon Process | `any where (file.path:"\\*" and (file.path:"*\\sysvol\\*" and file.path:"*\\Policies\\*")) and (not (…` |
| Creation New Shim Database | `any where file.path like~ ("*:\\Windows\\apppatch\\Custom\\*", "*:\\Windows\\apppatch\\CustomSDB\\*"…` |
| Gotoopener Artefact | `any where file.path:"*\\AppData\\Local\\Temp\\LogMeInInc\\GoToAssist Remote Support Expert\\*"` |
| Pcre Net Temp File | `any where file.path:"*\\AppData\\Local\\Temp\\ba9ea7344a4a5f591d6e5dc32a13494b\\*"` |
| Rclone Config Files | `any where file.path:"*:\\Users\\*" and file.path:"*\\.config\\rclone\\*"` |
| Scheduled Task Creation | `any where file.path like~ ("*:\\Windows\\System32\\Tasks\\*", "*:\\Windows\\SysWOW64\\Tasks\\*", "*:…` |
| Susp Homoglyph Filename | `any where (file.path like~ ("*А*", "*В*", "*Е*", "*К*", "*М*", "*Н*", "*О*", "*Р*", "*С*", "*Т*", "*…` |
| Susp Recycle Bin Fake Exec | `any where (process.executable like~ ("*RECYCLERS.BIN\\*", "*RECYCLER.BIN\\*")) or (file.path like~ (…` |
| Wmiexec Default Filename | `any where file.path like~ ("SigmaRegularExpression(regexp=SigmaString(['\\\\Windows\\\\__1\\d{9}\\.\…` |
| Image Load Dll Pcre Dotnet Dll Load | `any where file.path:"*\\AppData\\Local\\Temp\\ba9ea7344a4a5f591d6e5dc32a13494b\\*"` |
| Image Load Susp Dll Load System Process | `any where process.executable:"C:\\Windows\\*" and (file.path like~ ("C:\\Users\\Public\\*", "C:\\Per…` |
| Susp Initaited Public Folder | `any where (network.direction:"true" and process.executable:"*:\\Users\\Public\\*") and (not process.…` |
| Pipe Created Hktl Cobaltstrike Re | `any where file.name like~ ("SigmaRegularExpression(regexp=SigmaString(['\\\\mojo\\.5688\\.8052\\.(',…` |
| Pipe Created Hktl Coercedpotato | `any where file.name:"*\\coerced\\*"` |
| Hktl Empire Powershell Uac Bypass | `any where process.command_line like~ ("* -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\…` |
| Hktl Invoke Obfuscation Obfuscated Iex Commandline | `any where process.command_line like~ ("SigmaRegularExpression(regexp=SigmaString(['\\$PSHome\\[\\s',…` |
| Hktl Invoke Obfuscation Stdin | `any where process.command_line:"SigmaRegularExpression(regexp=SigmaString(['cmd.{0,5}(', <SpecialCha…` |
| Hktl Invoke Obfuscation Var | `any where process.command_line:"SigmaRegularExpression(regexp=SigmaString(['cmd.{0,5}(', <SpecialCha…` |
| Hktl Invoke Obfuscation Via Stdin | `any where process.command_line:"SigmaRegularExpression(regexp=SigmaString(['(', <SpecialChars.WILDCA…` |
| Malware Raspberry Robin Single Dot Ending File | `any where process.command_line:"SigmaRegularExpression(regexp=SigmaString(['\\\\[a-zA-Z0-9]{1,32}\\.…` |
| Malware Snatch Ransomware | `any where process.command_line like~ ("SigmaRegularExpression(regexp=SigmaString(['shutdown\\s+/r /f…` |
| Office Outlook Execution From Temp | `any where process.executable:"*\\Temporary Internet Files\\Content.Outlook\\*"` |
| Powershell Amsi Null Bits Bypass | `any where process.command_line like~ ("*if(0){{{0}}}' -f $(0 -as [char]) +*", "*#<NULL>*")` |
| Powershell Import Module Susp Dirs | `any where process.command_line like~ ("*Import-Module \"$Env:Temp\\*", "*Import-Module '$Env:Temp\\*…` |
| Powershell Susp Download Patterns | `any where process.command_line like~ ("*IEX ((New-Object Net.WebClient).DownloadString*", "*IEX (New…` |
| Registry Provlaunch Provisioning Command | `any where process.command_line:"*SOFTWARE\\Microsoft\\Provisioning\\Commands\\*"` |
| Rundll32 Run Locations | `any where (process.executable like~ ("*:\\RECYCLER\\*", "*:\\SystemVolumeInformation\\*")) or (proce…` |
| Susp Cli Obfuscation Unicode | `any where process.command_line like~ ("*ˣ*", "*˪*", "*ˢ*", "*∕*", "*⁄*", "*―*", "*—*", "* *", "*¯*",…` |
| Susp Commandline Path Traversal Evasion | `any where ((process.executable:"*\\Windows\\*" and (process.command_line like~ ("*\\..\\Windows\\*",…` |
| Susp Homoglyph Cyrillic Lookalikes | `any where (process.command_line like~ ("*А*", "*В*", "*Е*", "*К*", "*М*", "*Н*", "*О*", "*Р*", "*С*"…` |
| Susp Network Command | `any where process.command_line like~ ("SigmaRegularExpression(regexp=SigmaString(['ipconfig\\s+/all'…` |
| Susp Recycle Bin Fake Execution | `any where process.executable like~ ("*RECYCLERS.BIN\\*", "*RECYCLER.BIN\\*")` |
| Susp Redirect Local Admin Share | `any where process.command_line:"*>*" and (process.command_line like~ ("*\\\\127.0.0.1\\admin$\\*", "…` |
| Susp Sysvol Access | `any where process.command_line:"*\\SYSVOL\\*" and process.command_line:"*\\policies\\*"` |
| Uac Bypass Trustedpath | `any where process.executable like~ ("*C:\\Windows \\System32\\*", "*C:\\Windows \\SysWOW64\\*")` |
| Wmi Event Subscription | `any where event.code like~ ("19", "20", "21")` |