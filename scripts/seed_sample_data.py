"""
Seed the catalogs/ directory with sample Sigma and Elastic rules.

Usage:
    python scripts/seed_sample_data.py

This creates catalogs/sigma/ast/ and catalogs/elastic/ast/ with realistic
sample rules so you can explore the UI without a live SIEM.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.ast_model import Condition, RuleAST
from storage.rule_store import RuleStore

ROOT = Path(__file__).parent.parent
store = RuleStore(ROOT / "catalogs")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def cond(field: str, op: str, *values: str) -> Condition:
    return Condition(field=field, raw_field=field, operator=op,
                     values=list(values), raw_values=list(values))

def rule(rule_id: str, catalog: str, name: str, desc: str, severity: str,
         techniques: list[str], categories: list[str], conditions: list[Condition],
         raw_query: str, language: str, translated_query: str | None = None) -> RuleAST:
    return RuleAST(
        id=rule_id,
        catalog=catalog,
        name=name,
        description=desc,
        severity=severity,
        mitre_techniques=techniques,
        event_categories=categories,
        conditions=conditions,
        raw_query=raw_query,
        language=language,
        translated_query=translated_query,
        source_path=f"sample/{catalog}/{rule_id}.yml",
    )

# ---------------------------------------------------------------------------
# Sigma rules (20)
# ---------------------------------------------------------------------------

SIGMA = [
    rule("s-0001", "sigma", "Mimikatz via LSASS Memory Access",
         "Detects Mimikatz credential dumping via LSASS memory access.",
         "critical", ["attack.t1003.001"], ["process"],
         [cond("process.name", "==", "mimikatz.exe"),
          cond("process.args", "like~", "*sekurlsa*")],
         "process.name:mimikatz.exe AND process.args:*sekurlsa*", "sigma",
         'process where process.name == "mimikatz.exe" and process.args like~ "*sekurlsa*"'),

    rule("s-0002", "sigma", "PowerShell Encoded Command Execution",
         "Detects execution of Base64-encoded PowerShell commands.",
         "high", ["attack.t1059.001"], ["process"],
         [cond("process.name", "==", "powershell.exe"),
          cond("process.args", "like~", "*-enc*")],
         "process.name:powershell.exe AND process.args:*-enc*", "sigma",
         'process where process.name == "powershell.exe" and process.args like~ "*-enc*"'),

    rule("s-0003", "sigma", "WMI Spawning a Process",
         "Detects WMI spawning suspicious child processes.",
         "high", ["attack.t1047"], ["process"],
         [cond("process.parent.name", "==", "WmiPrvSE.exe"),
          cond("process.name", "in", "cmd.exe", "powershell.exe", "wscript.exe")],
         "ParentImage:WmiPrvSE.exe AND Image:(cmd.exe OR powershell.exe)", "sigma",
         'process where process.parent.name == "WmiPrvSE.exe"'),

    rule("s-0004", "sigma", "Credential Dumping via Registry",
         "Detects credential dumping via registry hive copy.",
         "critical", ["attack.t1003.002"], ["process"],
         [cond("process.name", "==", "reg.exe"),
          cond("process.args", "like~", "*save*HKLM\\SAM*")],
         "Image:reg.exe AND CommandLine:*save*SAM*", "sigma",
         'process where process.name == "reg.exe" and process.args like~ "*save*SAM*"'),

    rule("s-0005", "sigma", "Suspicious Scheduled Task Creation",
         "Detects creation of scheduled tasks via schtasks.exe.",
         "medium", ["attack.t1053.005"], ["process"],
         [cond("process.name", "==", "schtasks.exe"),
          cond("process.args", "like~", "*/create*")],
         "Image:schtasks.exe AND CommandLine:*/create*", "sigma",
         'process where process.name == "schtasks.exe" and process.args like~ "*/create*"'),

    rule("s-0006", "sigma", "Net User Account Discovery",
         "Detects enumeration of local user accounts.",
         "low", ["attack.t1087.001"], ["process"],
         [cond("process.name", "==", "net.exe"),
          cond("process.args", "like~", "*user*")],
         "Image:net.exe AND CommandLine:*user*", "sigma",
         'process where process.name == "net.exe" and process.args like~ "*user*"'),

    rule("s-0007", "sigma", "LSASS Memory Access by Non-System Process",
         "Detects suspicious processes accessing LSASS memory.",
         "critical", ["attack.t1003.001"], ["process"],
         [cond("target.process.name", "==", "lsass.exe"),
          cond("process.name", "!=", "svchost.exe")],
         "TargetImage:lsass.exe AND NOT SourceImage:svchost.exe", "sigma",
         'process where target.process.name == "lsass.exe"'),

    rule("s-0008", "sigma", "Remote Service Installation",
         "Detects remote service installation via sc.exe.",
         "high", ["attack.t1569.002"], ["process"],
         [cond("process.name", "==", "sc.exe"),
          cond("process.args", "like~", "*create*")],
         "Image:sc.exe AND CommandLine:*create*", "sigma",
         'process where process.name == "sc.exe" and process.args like~ "*create*"'),

    rule("s-0009", "sigma", "Suspicious DLL Side-Loading",
         "Detects DLL side-loading patterns in non-system paths.",
         "high", ["attack.t1574.002"], ["process", "library"],
         [cond("dll.path", "like~", "*\\AppData\\*"),
          cond("process.name", "!=", "explorer.exe")],
         "ImageLoaded:*\\AppData\\* AND NOT Image:explorer.exe", "sigma",
         'library where dll.path like~ "*\\\\AppData\\\\*"'),

    rule("s-0010", "sigma", "Outlook Spawning Suspicious Child Process",
         "Detects Outlook spawning process that could indicate phishing.",
         "high", ["attack.t1566.001"], ["process"],
         [cond("process.parent.name", "==", "OUTLOOK.EXE"),
          cond("process.name", "in", "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")],
         "ParentImage:OUTLOOK.EXE AND Image:(cmd.exe OR powershell.exe)", "sigma",
         'process where process.parent.name == "OUTLOOK.EXE"'),

    rule("s-0011", "sigma", "DCSync Attack Detection",
         "Detects DCSync attacks using directory replication privileges.",
         "critical", ["attack.t1003.006"], ["authentication"],
         [cond("event.action", "==", "Directory Service Replication"),
          cond("user.name", "!=", "SYSTEM")],
         "EventID:4662 AND ObjectType:replicationOfChanges", "sigma",
         'authentication where event.action == "Directory Service Replication"'),

    rule("s-0012", "sigma", "Pass-the-Hash Activity",
         "Detects pass-the-hash lateral movement via NTLM.",
         "high", ["attack.t1550.002"], ["authentication"],
         [cond("event.action", "==", "Logon"),
          cond("winlog.event_data.LogonType", "==", "3"),
          cond("winlog.event_data.AuthenticationPackageName", "==", "NTLM")],
         "EventID:4624 AND LogonType:3 AND AuthPackage:NTLM", "sigma",
         'authentication where winlog.event_data.LogonType == "3"'),

    rule("s-0013", "sigma", "Cobalt Strike Beacon Activity",
         "Detects Cobalt Strike beacon C2 patterns.",
         "critical", ["attack.t1071.001"], ["network"],
         [cond("destination.port", "in", "443", "80"),
          cond("network.bytes", "like~", "*204*")],
         "dst_port:(80 OR 443) AND bytes:204", "sigma",
         'network where destination.port in (443, 80)'),

    rule("s-0014", "sigma", "Suspicious PowerShell Download Cradle",
         "Detects PowerShell downloading and executing payloads.",
         "high", ["attack.t1059.001", "attack.t1105"], ["process"],
         [cond("process.name", "==", "powershell.exe"),
          cond("process.args", "like~", "*IEX*"),
          cond("process.args", "like~", "*DownloadString*")],
         "Image:powershell.exe AND CommandLine:*IEX*DownloadString*", "sigma",
         'process where process.name == "powershell.exe" and process.args like~ "*IEX*"'),

    rule("s-0015", "sigma", "Windows Defender Disabled via Registry",
         "Detects disabling of Windows Defender via registry modification.",
         "high", ["attack.t1562.001"], ["registry"],
         [cond("registry.path", "like~", "*\\Windows Defender\\*"),
          cond("registry.data.strings", "in", "0", "false")],
         "TargetObject:*\\Windows Defender\\* AND Details:(0 OR false)", "sigma",
         'registry where registry.path like~ "*\\\\Windows Defender\\\\*"'),

    rule("s-0016", "sigma", "Kerberoasting Activity",
         "Detects Kerberoasting via RC4 encryption TGS requests.",
         "high", ["attack.t1558.003"], ["authentication"],
         [cond("winlog.event_data.TicketEncryptionType", "==", "0x17"),
          cond("winlog.event_data.ServiceName", "!=", "krbtgt")],
         "EventID:4769 AND TicketEncryptionType:0x17", "sigma",
         'authentication where winlog.event_data.TicketEncryptionType == "0x17"'),

    rule("s-0017", "sigma", "DNS Tunneling via Abnormal Query Length",
         "Detects DNS tunneling via unusually long query names.",
         "medium", ["attack.t1071.004"], ["network", "dns"],
         [cond("dns.question.name", "like~", "*.*.*.*.*.* *")],
         "dns.question.name:*.*.*.*.*.*", "sigma",
         'network where length(dns.question.name) > 50'),

    rule("s-0018", "sigma", "Suspicious Certutil Usage",
         "Detects certutil.exe used for downloading or encoding.",
         "high", ["attack.t1105", "attack.t1140"], ["process"],
         [cond("process.name", "==", "certutil.exe"),
          cond("process.args", "in", "-urlcache", "-decode", "-encode")],
         "Image:certutil.exe AND CommandLine:(-urlcache OR -decode OR -encode)", "sigma",
         'process where process.name == "certutil.exe"'),

    rule("s-0019", "sigma", "RDP Lateral Movement",
         "Detects RDP-based lateral movement.",
         "medium", ["attack.t1021.001"], ["network"],
         [cond("destination.port", "==", "3389"),
          cond("network.direction", "==", "egress")],
         "dst_port:3389", "sigma",
         'network where destination.port == 3389'),

    rule("s-0020", "sigma", "Suspicious Process Injection via CreateRemoteThread",
         "Detects process injection via CreateRemoteThread API.",
         "critical", ["attack.t1055.001"], ["process"],
         [cond("event.action", "==", "CreateRemoteThread"),
          cond("process.name", "!=", "svchost.exe")],
         "EventID:8 AND NOT SourceImage:svchost.exe", "sigma",
         'process where event.action == "CreateRemoteThread"'),
]

# ---------------------------------------------------------------------------
# Elastic rules (15) — some overlap with Sigma, some are unique to Elastic
# ---------------------------------------------------------------------------

ELASTIC = [
    # Overlapping with Sigma (similar logic, different catalog)
    rule("e-0001", "elastic", "Mimikatz Execution Detected",
         "Elastic rule detecting Mimikatz credential dumping.",
         "critical", ["attack.t1003.001"], ["process"],
         [cond("process.name", "==", "mimikatz.exe")],
         'process where process.name == "mimikatz.exe"', "eql",
         'process where process.name == "mimikatz.exe"'),

    rule("e-0002", "elastic", "Encoded PowerShell Command",
         "Elastic rule for encoded PowerShell execution.",
         "high", ["attack.t1059.001"], ["process"],
         [cond("process.name", "==", "powershell.exe"),
          cond("process.args", "like~", "*-enc*")],
         'process where process.name == "powershell.exe" and process.args like~ "*-enc*"', "eql",
         'process where process.name == "powershell.exe" and process.args like~ "*-enc*"'),

    rule("e-0003", "elastic", "WMI Process Spawning",
         "Elastic EQL rule for WMI spawning child processes.",
         "high", ["attack.t1047"], ["process"],
         [cond("process.parent.name", "==", "WmiPrvSE.exe")],
         'process where process.parent.name == "WmiPrvSE.exe"', "eql",
         'process where process.parent.name == "WmiPrvSE.exe"'),

    rule("e-0004", "elastic", "Credential Dumping - SAM Registry Hive",
         "Elastic rule for SAM hive credential dumping.",
         "critical", ["attack.t1003.002"], ["process"],
         [cond("process.name", "==", "reg.exe"),
          cond("process.args", "like~", "*save*SAM*")],
         'process where process.name == "reg.exe" and process.args like~ "*SAM*"', "eql",
         'process where process.name == "reg.exe" and process.args like~ "*SAM*"'),

    rule("e-0005", "elastic", "Scheduled Task via Command Line",
         "Elastic rule for scheduled task creation.",
         "medium", ["attack.t1053.005"], ["process"],
         [cond("process.name", "==", "schtasks.exe"),
          cond("process.args", "like~", "*/create*")],
         'process where process.name == "schtasks.exe"', "eql",
         'process where process.name == "schtasks.exe"'),

    rule("e-0006", "elastic", "Remote Service via sc.exe",
         "Elastic rule detecting sc.exe service creation.",
         "high", ["attack.t1569.002"], ["process"],
         [cond("process.name", "==", "sc.exe"),
          cond("process.args", "like~", "*create*")],
         'process where process.name == "sc.exe" and process.args like~ "*create*"', "eql",
         'process where process.name == "sc.exe" and process.args like~ "*create*"'),

    rule("e-0007", "elastic", "Windows Defender Tampered via Registry",
         "Elastic rule for Windows Defender registry tampering.",
         "high", ["attack.t1562.001"], ["registry"],
         [cond("registry.path", "like~", "*\\Windows Defender\\*")],
         'registry where registry.path like~ "*\\Windows Defender\\*"', "eql",
         'registry where registry.path like~ "*\\\\Windows Defender\\\\*"'),

    rule("e-0008", "elastic", "Kerberos TGS Request with RC4",
         "Elastic rule for Kerberoasting via RC4 ticket encryption.",
         "high", ["attack.t1558.003"], ["authentication"],
         [cond("winlog.event_data.TicketEncryptionType", "==", "0x17")],
         'authentication where winlog.event_data.TicketEncryptionType == "0x17"', "eql",
         'authentication where winlog.event_data.TicketEncryptionType == "0x17"'),

    rule("e-0009", "elastic", "DCSync Replication Request",
         "Elastic rule for DCSync attacks.",
         "critical", ["attack.t1003.006"], ["authentication"],
         [cond("event.action", "==", "Directory Service Replication")],
         'authentication where event.action == "Directory Service Replication"', "eql",
         'authentication where event.action == "Directory Service Replication"'),

    rule("e-0010", "elastic", "Certutil Download or Decode",
         "Elastic rule for suspicious certutil usage.",
         "high", ["attack.t1105"], ["process"],
         [cond("process.name", "==", "certutil.exe"),
          cond("process.args", "in", "-urlcache", "-decode")],
         'process where process.name == "certutil.exe"', "eql",
         'process where process.name == "certutil.exe"'),

    # Elastic-only rules (no Sigma equivalent in our sample)
    rule("e-0011", "elastic", "AWS S3 Bucket Policy Modified",
         "Detects modification of S3 bucket policies that could expose data.",
         "high", ["attack.t1537"], ["cloud"],
         [cond("event.provider", "==", "s3.amazonaws.com"),
          cond("event.action", "==", "PutBucketPolicy")],
         'any where event.provider == "s3.amazonaws.com" and event.action == "PutBucketPolicy"', "eql",
         'any where event.provider == "s3.amazonaws.com" and event.action == "PutBucketPolicy"'),

    rule("e-0012", "elastic", "Azure AD Conditional Access Disabled",
         "Detects disabling of Azure AD Conditional Access policies.",
         "critical", ["attack.t1556"], ["iam"],
         [cond("event.provider", "==", "Microsoft.Authorization"),
          cond("event.action", "==", "Delete policy")],
         'iam where event.provider == "Microsoft.Authorization"', "eql",
         'iam where event.provider == "Microsoft.Authorization"'),

    rule("e-0013", "elastic", "Kubernetes Pod Created in kube-system",
         "Detects pod creation in kube-system namespace — potential privilege escalation.",
         "high", ["attack.t1610"], ["container"],
         [cond("kubernetes.namespace", "==", "kube-system"),
          cond("event.action", "==", "create"),
          cond("kubernetes.resource.type", "==", "pod")],
         'any where kubernetes.namespace == "kube-system" and event.action == "create"', "eql",
         'any where kubernetes.namespace == "kube-system"'),

    rule("e-0014", "elastic", "GCP Service Account Key Created",
         "Detects creation of GCP service account keys — potential persistence.",
         "medium", ["attack.t1098.001"], ["cloud"],
         [cond("event.provider", "==", "iam.googleapis.com"),
          cond("event.action", "==", "CreateServiceAccountKey")],
         'any where event.provider == "iam.googleapis.com" and event.action == "CreateServiceAccountKey"', "eql",
         'any where event.provider == "iam.googleapis.com"'),

    rule("e-0015", "elastic", "Unusual Linux Process Executed as Root",
         "Detects unusual processes running as root on Linux systems.",
         "high", ["attack.t1068"], ["process"],
         [cond("process.user.id", "==", "0"),
          cond("event.type", "==", "start"),
          cond("host.os.type", "==", "linux")],
         'process where process.user.id == "0" and host.os.type == "linux"', "eql",
         'process where process.user.id == "0" and host.os.type == "linux"'),
]

# ---------------------------------------------------------------------------
# Write to store
# ---------------------------------------------------------------------------

def main():
    sigma_count = 0
    for r in SIGMA:
        store.save(r)
        sigma_count += 1

    elastic_count = 0
    for r in ELASTIC:
        store.save(r)
        elastic_count += 1

    print(f"[OK] Seeded {sigma_count} Sigma rules  ->  {ROOT / 'catalogs' / 'sigma' / 'ast'}")
    print(f"[OK] Seeded {elastic_count} Elastic rules  ->  {ROOT / 'catalogs' / 'elastic' / 'ast'}")
    print()
    print("Launch the UI:")
    print("    streamlit run ui/dashboard.py")


if __name__ == "__main__":
    main()
