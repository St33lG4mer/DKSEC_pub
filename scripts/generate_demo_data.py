#!/usr/bin/env python3
"""Generate demo catalog data for Streamlit Community Cloud deployment."""
import json
import shutil
import uuid
from pathlib import Path

ROOT = Path(__file__).parent.parent


def mk(catalog, name, desc, sev, mitre, cats, conds, raw_q, lang, tq=None):
    return {
        "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{catalog}:{name}")),
        "catalog": catalog, "name": name, "description": desc, "severity": sev,
        "mitre_techniques": mitre, "event_categories": cats, "conditions": conds,
        "raw_query": raw_q, "language": lang, "translated_query": tq,
        "source_path": "demo", "metadata": {},
    }


def c(f, rf, op, v):
    return {"field": f, "raw_field": rf, "operator": op, "values": v, "raw_values": v}


SIGMA = [
    mk("sigma", "Mimikatz Credential Dumping", "Detects execution of Mimikatz for credential dumping", "critical",
       ["attack.t1003.001"], ["process"], [c("process.name", "Image", "==", ["mimikatz.exe"])],
       'process where process.name == "mimikatz.exe"', "sigma",
       'process where process.name == "mimikatz.exe"'),
    mk("sigma", "PowerShell Encoded Command", "Detects PowerShell executing encoded commands", "high",
       ["attack.t1059.001"], ["process"],
       [c("process.name", "Image", "==", ["powershell.exe"]),
        c("process.command_line", "CommandLine", "like~", ["*-EncodedCommand*"])],
       'process where process.name == "powershell.exe" and process.command_line like~ "*-EncodedCommand*"', "sigma",
       'process where process.name == "powershell.exe" and process.command_line like~ "*-EncodedCommand*"'),
    mk("sigma", "Scheduled Task Creation via Schtasks", "Detects creation of scheduled tasks via schtasks.exe", "medium",
       ["attack.t1053.005"], ["process"],
       [c("process.name", "Image", "==", ["schtasks.exe"]),
        c("process.command_line", "CommandLine", "like~", ["*/create*"])],
       'process where process.name == "schtasks.exe" and process.command_line like~ "*/create*"', "sigma",
       'process where process.name == "schtasks.exe" and process.command_line like~ "*/create*"'),
    mk("sigma", "LSASS Memory Dump via ProcDump", "Detects ProcDump targeting LSASS process memory", "critical",
       ["attack.t1003.001"], ["process"],
       [c("process.name", "Image", "in", ["procdump.exe", "procdump64.exe"]),
        c("process.command_line", "CommandLine", "like~", ["*lsass*"])],
       'process where process.name in ("procdump.exe","procdump64.exe") and process.command_line like~ "*lsass*"',
       "sigma",
       'process where process.name in ("procdump.exe","procdump64.exe") and process.command_line like~ "*lsass*"'),
    mk("sigma", "Net User Discovery", "Detects enumeration of local and domain users", "low",
       ["attack.t1087.001", "attack.t1087.002"], ["process"],
       [c("process.name", "Image", "in", ["net.exe", "net1.exe"]),
        c("process.command_line", "CommandLine", "like~", ["*user*"])],
       'process where process.name in ("net.exe","net1.exe") and process.command_line like~ "*user*"', "sigma",
       'process where process.name in ("net.exe","net1.exe") and process.command_line like~ "*user*"'),
    mk("sigma", "WMI Remote Execution", "Detects remote code execution via WMI", "high",
       ["attack.t1047"], ["process"],
       [c("process.name", "Image", "==", ["wmic.exe"]),
        c("process.command_line", "CommandLine", "like~", ["*process call create*"])],
       'process where process.name == "wmic.exe" and process.command_line like~ "*process call create*"', "sigma",
       'process where process.name == "wmic.exe" and process.command_line like~ "*process call create*"'),
    mk("sigma", "Certutil Download", "Detects certutil used to download files (LOLBin abuse)", "high",
       ["attack.t1105"], ["process"],
       [c("process.name", "Image", "==", ["certutil.exe"]),
        c("process.command_line", "CommandLine", "like~", ["*-urlcache*"])],
       'process where process.name == "certutil.exe" and process.command_line like~ "*-urlcache*"', "sigma",
       'process where process.name == "certutil.exe" and process.command_line like~ "*-urlcache*"'),
    mk("sigma", "Suspicious Registry Run Key Modification",
       "Detects modification of Run/RunOnce registry keys for persistence", "medium",
       ["attack.t1547.001"], ["registry"],
       [c("registry.path", "TargetObject", "like~", ["*\\CurrentVersion\\Run*"])],
       'registry where registry.path like~ "*\\\\CurrentVersion\\\\Run*"', "sigma",
       'registry where registry.path like~ "*\\\\CurrentVersion\\\\Run*"'),
    mk("sigma", "Pass-the-Hash via Mimikatz", "Detects pass-the-hash attacks using Mimikatz sekurlsa module",
       "critical", ["attack.t1550.002"], ["process"],
       [c("process.command_line", "CommandLine", "like~", ["*sekurlsa::pth*"])],
       'process where process.command_line like~ "*sekurlsa::pth*"', "sigma",
       'process where process.command_line like~ "*sekurlsa::pth*"'),
    mk("sigma", "Remote Service Creation", "Detects creation of remote services for lateral movement", "high",
       ["attack.t1021.002"], ["process"],
       [c("process.name", "Image", "==", ["sc.exe"]),
        c("process.command_line", "CommandLine", "like~", ["*create*"])],
       'process where process.name == "sc.exe" and process.command_line like~ "*create*"', "sigma",
       'process where process.name == "sc.exe" and process.command_line like~ "*create*"'),
    mk("sigma", "Credential Dumping - SAM Registry Hive", "Detects attempts to dump the SAM registry hive",
       "critical", ["attack.t1003.002"], ["process"],
       [c("process.command_line", "CommandLine", "like~", ["*reg save*"])],
       'process where process.command_line like~ "*reg save*" and process.command_line like~ "*\\\\sam*"', "sigma",
       'process where process.command_line like~ "*reg save*" and process.command_line like~ "*\\\\sam*"'),
    mk("sigma", "RunDLL32 Suspicious Execution", "Detects rundll32 executing DLLs from uncommon paths", "high",
       ["attack.t1218.011"], ["process"],
       [c("process.name", "Image", "==", ["rundll32.exe"]),
        c("process.command_line", "CommandLine", "like~", ["*\\\\Temp\\\\*"])],
       'process where process.name == "rundll32.exe" and process.command_line like~ "*\\\\Temp\\\\*"', "sigma",
       'process where process.name == "rundll32.exe" and process.command_line like~ "*\\\\Temp\\\\*"'),
    mk("sigma", "DNS Query for C2 Domains", "Detects DNS lookups to common C2 infrastructure patterns", "medium",
       ["attack.t1071.004"], ["dns"],
       [c("dns.question.name", "QueryName", "like~", ["*.duckdns.org", "*.ngrok.io"])],
       'dns where dns.question.name like~ "*.duckdns.org"', "sigma",
       'dns where dns.question.name like~ "*.duckdns.org"'),
    mk("sigma", "Lateral Movement via PsExec", "Detects lateral movement using PsExec remote execution", "high",
       ["attack.t1570", "attack.t1021.002"], ["process"],
       [c("process.name", "Image", "in", ["psexec.exe", "psexesvc.exe"])],
       'process where process.name in ("psexec.exe","psexesvc.exe")', "sigma",
       'process where process.name in ("psexec.exe","psexesvc.exe")'),
    # --- Gaps (no Elastic equivalent) ---
    mk("sigma", "Suspicious PowerShell Download Cradle",
       "Detects PowerShell download cradles using Net.WebClient or IEX", "high",
       ["attack.t1059.001", "attack.t1105"], ["process"],
       [c("process.command_line", "CommandLine", "like~", ["*Net.WebClient*", "*DownloadString*"])],
       'process where process.command_line like~ "*Net.WebClient*" and process.command_line like~ "*DownloadString*"',
       "sigma",
       'process where process.command_line like~ "*Net.WebClient*" and process.command_line like~ "*DownloadString*"'),
    mk("sigma", "UAC Bypass via EventViewer", "Detects UAC bypass technique using Windows Event Viewer", "high",
       ["attack.t1548.002"], ["process", "registry"],
       [c("registry.path", "TargetObject", "like~", ["*mscfile\\\\shell\\\\open\\\\command*"])],
       'registry where registry.path like~ "*mscfile\\\\shell\\\\open\\\\command*"', "sigma", None),
    mk("sigma", "Cobalt Strike Named Pipe", "Detects named pipes used by Cobalt Strike beacon", "critical",
       ["attack.t1071"], ["file"],
       [c("file.name", "PipeName", "like~", ["\\\\msagent_*", "\\\\status_*"])],
       'file where file.name like~ "\\\\msagent_*"', "sigma", None),
    mk("sigma", "Kerberoasting via Rubeus", "Detects Rubeus tool used for Kerberoasting attacks", "critical",
       ["attack.t1558.003"], ["process"],
       [c("process.command_line", "CommandLine", "like~", ["*rubeus*", "*kerberoast*"])],
       'process where process.command_line like~ "*rubeus*"', "sigma", None),
    mk("sigma", "Suspicious Mshta Execution", "Detects mshta.exe executing remote scripts", "high",
       ["attack.t1218.005"], ["process"],
       [c("process.name", "Image", "==", ["mshta.exe"]),
        c("process.command_line", "CommandLine", "like~", ["*http*", "*vbscript*"])],
       'process where process.name == "mshta.exe" and process.command_line like~ "*http*"', "sigma", None),
    mk("sigma", "DLL Side-Loading via Legitimate App",
       "Detects DLL side-loading by placing malicious DLL next to legit binary", "medium",
       ["attack.t1574.002"], ["process"],
       [c("process.parent.name", "ParentImage", "in", ["OneDrive.exe", "Teams.exe", "Outlook.exe"])],
       'process where process.parent.name in ("OneDrive.exe","Teams.exe")', "sigma", None),
]

ELASTIC = [
    mk("elastic", "Credential Dumping - LSASS Access", "Detects access to LSASS process for credential dumping",
       "critical", ["attack.t1003.001"], ["process"],
       [c("process.name", "process.name", "in", ["mimikatz.exe", "procdump.exe", "procdump64.exe"])],
       'process where process.name in ("mimikatz.exe","procdump.exe","procdump64.exe")', "eql"),
    mk("elastic", "PowerShell Obfuscated Command Execution",
       "Detects PowerShell running encoded/obfuscated commands", "high", ["attack.t1059.001"], ["process"],
       [c("process.name", "process.name", "==", ["powershell.exe"]),
        c("process.command_line", "process.command_line", "like~", ["*-EncodedCommand*"])],
       'process where process.name == "powershell.exe" and process.command_line like~ "*-EncodedCommand*"', "eql"),
    mk("elastic", "Scheduled Task via Schtasks", "Detects task scheduling via schtasks.exe", "medium",
       ["attack.t1053.005"], ["process"],
       [c("process.name", "process.name", "==", ["schtasks.exe"]),
        c("process.command_line", "process.command_line", "like~", ["*/create*"])],
       'process where process.name == "schtasks.exe" and process.command_line like~ "*/create*"', "eql"),
    mk("elastic", "Windows Registry Run Key Persistence",
       "Detects addition of entries to registry Run keys", "medium", ["attack.t1547.001"], ["registry"],
       [c("registry.path", "registry.path", "like~", ["*\\\\CurrentVersion\\\\Run*"])],
       'registry where registry.path like~ "*\\\\CurrentVersion\\\\Run*"', "eql"),
    mk("elastic", "Remote Code Execution via WMI", "Detects WMI used for remote command execution", "high",
       ["attack.t1047"], ["process"],
       [c("process.name", "process.name", "==", ["wmic.exe"])],
       'process where process.name == "wmic.exe" and process.command_line like~ "*process call create*"', "eql"),
    mk("elastic", "Certutil File Download", "Detects certutil.exe downloading remote files", "high",
       ["attack.t1105"], ["process"],
       [c("process.name", "process.name", "==", ["certutil.exe"]),
        c("process.command_line", "process.command_line", "like~", ["*-urlcache*"])],
       'process where process.name == "certutil.exe" and process.command_line like~ "*-urlcache*"', "eql"),
    mk("elastic", "Pass-the-Hash Attack Detection",
       "Detects pass-the-hash via NTLM authentication anomalies", "critical", ["attack.t1550.002"],
       ["authentication"], [c("event.action", "event.action", "==", ["logged-in"])],
       'authentication where event.action == "logged-in" and source.ip != "127.0.0.1"', "eql"),
    mk("elastic", "Lateral Movement - Remote Service", "Detects service creation for lateral movement", "high",
       ["attack.t1021.002"], ["process"],
       [c("process.name", "process.name", "==", ["sc.exe"]),
        c("process.command_line", "process.command_line", "like~", ["*create*"])],
       'process where process.name == "sc.exe" and process.command_line like~ "*create*"', "eql"),
    mk("elastic", "PsExec Lateral Movement", "Detects PsExec used for lateral movement between hosts", "high",
       ["attack.t1021.002"], ["process"],
       [c("process.name", "process.name", "in", ["psexec.exe", "psexesvc.exe"])],
       'process where process.name in ("psexec.exe","psexesvc.exe")', "eql"),
    mk("elastic", "SAM Database Access", "Detects attempts to access the SAM database for credential theft",
       "critical", ["attack.t1003.002"], ["process"],
       [c("process.command_line", "process.command_line", "like~", ["*reg save*"])],
       'process where process.command_line like~ "*reg save*" and process.command_line like~ "*\\\\sam*"', "eql"),
    mk("elastic", "Suspicious RunDLL32 Usage", "Detects rundll32 executing from suspicious paths", "high",
       ["attack.t1218.011"], ["process"],
       [c("process.name", "process.name", "==", ["rundll32.exe"])],
       'process where process.name == "rundll32.exe" and process.command_line like~ "*\\\\Temp\\\\*"', "eql"),
    mk("elastic", "DNS Beaconing Detection", "Detects high-frequency DNS queries suggesting C2 beaconing", "medium",
       ["attack.t1071.004"], ["dns"],
       [c("dns.question.name", "dns.question.name", "like~", ["*.duckdns.org", "*.ngrok.io"])],
       'dns where dns.question.name like~ "*.duckdns.org" or dns.question.name like~ "*.ngrok.io"', "eql"),
    mk("elastic", "Net User/View Enumeration", "Detects Windows network and user enumeration", "low",
       ["attack.t1087.001", "attack.t1018"], ["process"],
       [c("process.name", "process.name", "in", ["net.exe", "net1.exe"])],
       'process where process.name in ("net.exe","net1.exe") and process.command_line like~ "*user*"', "eql"),
    mk("elastic", "Elastic Endpoint Malware Detection", "Elastic Endpoint Security malware prevention alert", "high",
       ["attack.t1204"], ["file"],
       [c("event.type", "event.type", "==", ["creation"])],
       'file where event.type == "creation" and file.Ext.malware_classification.identifier != ""', "eql"),
    mk("elastic", "Suspicious PowerShell Network Activity",
       "Detects PowerShell making outbound network connections", "high", ["attack.t1059.001"], ["network"],
       [c("process.name", "process.name", "==", ["powershell.exe"]),
        c("network.direction", "network.direction", "==", ["egress"])],
       'network where process.name == "powershell.exe" and network.direction == "egress"', "eql"),
]

# Clear and write catalog AST files
for catalog, rules in [("sigma", SIGMA), ("elastic", ELASTIC)]:
    ast_dir = ROOT / "catalogs" / catalog / "ast"
    if ast_dir.exists():
        shutil.rmtree(ast_dir)
    ast_dir.mkdir(parents=True)
    for r in rules:
        (ast_dir / f"{r['id']}.json").write_text(
            json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8"
        )

# Build overlaps
OVERLAP_DEFS = [
    ("Mimikatz Credential Dumping", "Credential Dumping - LSASS Access", 0.857),
    ("PowerShell Encoded Command", "PowerShell Obfuscated Command Execution", 0.800),
    ("Scheduled Task Creation via Schtasks", "Scheduled Task via Schtasks", 0.923),
    ("LSASS Memory Dump via ProcDump", "Credential Dumping - LSASS Access", 0.750),
    ("WMI Remote Execution", "Remote Code Execution via WMI", 0.889),
    ("Certutil Download", "Certutil File Download", 0.900),
    ("Suspicious Registry Run Key Modification", "Windows Registry Run Key Persistence", 0.857),
    ("Pass-the-Hash via Mimikatz", "Pass-the-Hash Attack Detection", 0.714),
    ("Remote Service Creation", "Lateral Movement - Remote Service", 0.833),
    ("Credential Dumping - SAM Registry Hive", "SAM Database Access", 0.875),
    ("RunDLL32 Suspicious Execution", "Suspicious RunDLL32 Usage", 0.800),
    ("DNS Query for C2 Domains", "DNS Beaconing Detection", 0.769),
    ("Lateral Movement via PsExec", "PsExec Lateral Movement", 0.923),
    ("Net User Discovery", "Net User/View Enumeration", 0.667),
]

sn = {r["name"]: r for r in SIGMA}
en = {r["name"]: r for r in ELASTIC}
overlaps, ov_ids = [], set()
for sa, eb, j in OVERLAP_DEFS:
    ra, rb = sn.get(sa), en.get(eb)
    if ra and rb:
        overlaps.append({
            "rule_a_id": ra["id"], "rule_b_id": rb["id"],
            "rule_a_name": ra["name"], "rule_b_name": rb["name"],
            "jaccard_score": j, "alert_confirmed": False,
            "rule_a": ra, "rule_b": rb,
        })
        ov_ids.add(ra["id"])

unique_sigma = [r for r in SIGMA if r["id"] not in ov_ids]

out = ROOT / "output"
for sub in ["overlaps", "unique", "reports"]:
    (out / sub).mkdir(parents=True, exist_ok=True)

(out / "overlaps" / "sigma_vs_elastic.json").write_text(
    json.dumps(overlaps, indent=2, ensure_ascii=False), encoding="utf-8")
(out / "unique" / "sigma_vs_elastic.json").write_text(
    json.dumps(unique_sigma, indent=2, ensure_ascii=False), encoding="utf-8")
(out / "reports" / "sigma_vs_elastic_decisions.json").write_text(
    json.dumps({}), encoding="utf-8")

print(f"Sigma: {len(SIGMA)}, Elastic: {len(ELASTIC)}")
print(f"Overlaps: {len(overlaps)}, Gaps: {len(unique_sigma)}")
print("Gap rules:", [r['name'] for r in unique_sigma])
