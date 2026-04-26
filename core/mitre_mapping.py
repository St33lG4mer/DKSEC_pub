# core/mitre_mapping.py
"""Lightweight MITRE ATT&CK technique → tactic mapping.

Technique IDs are normalised before lookup:
  "attack.t1059.001" → "T1059"
  "T1059.001"        → "T1059"
  "t1059"            → "T1059"

Each base technique maps to one or more tactic names.
Only base technique IDs (no sub-technique suffix) are used for lookup so that
T1059.001 and T1059.003 both resolve through T1059.
"""
from __future__ import annotations

import re

_TECHNIQUE_TACTICS: dict[str, list[str]] = {
    # Initial Access
    "T1078": ["Initial Access", "Defense Evasion", "Persistence", "Privilege Escalation"],
    "T1091": ["Initial Access", "Lateral Movement"],
    "T1133": ["Initial Access", "Persistence"],
    "T1189": ["Initial Access"],
    "T1190": ["Initial Access"],
    "T1195": ["Initial Access"],
    "T1199": ["Initial Access"],
    "T1566": ["Initial Access"],
    # Execution
    "T1047": ["Execution"],
    "T1053": ["Execution", "Persistence", "Privilege Escalation"],
    "T1059": ["Execution"],
    "T1072": ["Execution", "Lateral Movement"],
    "T1106": ["Execution"],
    "T1129": ["Execution"],
    "T1204": ["Execution"],
    "T1559": ["Execution"],
    "T1610": ["Execution"],
    # Persistence
    "T1037": ["Persistence", "Privilege Escalation"],
    "T1098": ["Persistence", "Privilege Escalation"],
    "T1136": ["Persistence"],
    "T1137": ["Persistence"],
    "T1176": ["Persistence"],
    "T1197": ["Defense Evasion", "Persistence"],
    "T1505": ["Persistence"],
    "T1525": ["Persistence"],
    "T1542": ["Defense Evasion", "Persistence"],
    "T1543": ["Persistence", "Privilege Escalation"],
    "T1546": ["Persistence", "Privilege Escalation"],
    "T1547": ["Persistence", "Privilege Escalation"],
    "T1554": ["Persistence"],
    "T1556": ["Credential Access", "Defense Evasion", "Persistence"],
    "T1574": ["Defense Evasion", "Persistence", "Privilege Escalation"],
    # Privilege Escalation
    "T1055": ["Defense Evasion", "Privilege Escalation"],
    "T1068": ["Privilege Escalation"],
    "T1134": ["Defense Evasion", "Privilege Escalation"],
    "T1484": ["Defense Evasion", "Privilege Escalation"],
    "T1548": ["Defense Evasion", "Privilege Escalation"],
    "T1611": ["Privilege Escalation"],
    # Defense Evasion
    "T1006": ["Defense Evasion"],
    "T1014": ["Defense Evasion"],
    "T1027": ["Defense Evasion"],
    "T1036": ["Defense Evasion"],
    "T1070": ["Defense Evasion"],
    "T1112": ["Defense Evasion"],
    "T1140": ["Defense Evasion"],
    "T1202": ["Defense Evasion"],
    "T1205": ["Command and Control", "Defense Evasion", "Persistence"],
    "T1207": ["Defense Evasion"],
    "T1218": ["Defense Evasion"],
    "T1220": ["Defense Evasion"],
    "T1480": ["Defense Evasion"],
    "T1562": ["Defense Evasion"],
    "T1564": ["Defense Evasion"],
    "T1600": ["Defense Evasion"],
    "T1620": ["Defense Evasion"],
    # Credential Access
    "T1003": ["Credential Access"],
    "T1056": ["Collection", "Credential Access"],
    "T1110": ["Credential Access"],
    "T1111": ["Credential Access"],
    "T1187": ["Credential Access"],
    "T1212": ["Credential Access"],
    "T1528": ["Credential Access"],
    "T1539": ["Credential Access"],
    "T1552": ["Credential Access"],
    "T1557": ["Collection", "Credential Access"],
    "T1558": ["Credential Access"],
    "T1606": ["Credential Access"],
    # Discovery
    "T1007": ["Discovery"],
    "T1010": ["Discovery"],
    "T1012": ["Discovery"],
    "T1016": ["Discovery"],
    "T1018": ["Discovery"],
    "T1033": ["Discovery"],
    "T1040": ["Collection", "Discovery"],
    "T1049": ["Discovery"],
    "T1057": ["Discovery"],
    "T1069": ["Discovery"],
    "T1082": ["Discovery"],
    "T1083": ["Discovery"],
    "T1087": ["Discovery"],
    "T1120": ["Discovery"],
    "T1124": ["Discovery"],
    "T1135": ["Discovery"],
    "T1201": ["Discovery"],
    "T1217": ["Discovery"],
    "T1482": ["Discovery"],
    "T1518": ["Discovery"],
    "T1526": ["Discovery"],
    "T1538": ["Discovery"],
    "T1580": ["Discovery"],
    "T1613": ["Discovery"],
    # Lateral Movement
    "T1021": ["Lateral Movement"],
    "T1080": ["Lateral Movement"],
    "T1210": ["Lateral Movement"],
    "T1534": ["Lateral Movement"],
    "T1550": ["Defense Evasion", "Lateral Movement"],
    "T1563": ["Lateral Movement"],
    "T1570": ["Lateral Movement"],
    # Collection
    "T1005": ["Collection"],
    "T1025": ["Collection"],
    "T1039": ["Collection"],
    "T1074": ["Collection"],
    "T1113": ["Collection"],
    "T1114": ["Collection"],
    "T1115": ["Collection"],
    "T1119": ["Collection"],
    "T1123": ["Collection"],
    "T1125": ["Collection"],
    "T1185": ["Collection"],
    "T1213": ["Collection"],
    "T1530": ["Collection"],
    "T1560": ["Collection"],
    # Command and Control
    "T1001": ["Command and Control"],
    "T1008": ["Command and Control"],
    "T1071": ["Command and Control"],
    "T1090": ["Command and Control"],
    "T1095": ["Command and Control"],
    "T1102": ["Command and Control"],
    "T1104": ["Command and Control"],
    "T1105": ["Command and Control"],
    "T1132": ["Command and Control"],
    "T1219": ["Command and Control"],
    "T1568": ["Command and Control"],
    "T1571": ["Command and Control"],
    "T1572": ["Command and Control"],
    "T1573": ["Command and Control"],
    # Exfiltration
    "T1011": ["Exfiltration"],
    "T1020": ["Exfiltration"],
    "T1029": ["Exfiltration"],
    "T1030": ["Exfiltration"],
    "T1041": ["Exfiltration"],
    "T1048": ["Exfiltration"],
    "T1052": ["Exfiltration"],
    "T1537": ["Exfiltration"],
    "T1567": ["Exfiltration"],
    # Impact
    "T1485": ["Impact"],
    "T1486": ["Impact"],
    "T1489": ["Impact"],
    "T1490": ["Impact"],
    "T1491": ["Impact"],
    "T1495": ["Impact"],
    "T1496": ["Impact"],
    "T1498": ["Impact"],
    "T1499": ["Impact"],
    "T1529": ["Impact"],
    "T1531": ["Impact"],
    "T1561": ["Impact"],
    "T1565": ["Impact"],
    # Reconnaissance
    "T1591": ["Reconnaissance"],
    "T1592": ["Reconnaissance"],
    "T1593": ["Reconnaissance"],
    "T1594": ["Reconnaissance"],
    "T1595": ["Reconnaissance"],
    "T1596": ["Reconnaissance"],
    "T1597": ["Reconnaissance"],
    "T1598": ["Reconnaissance"],
    # Resource Development
    "T1583": ["Resource Development"],
    "T1584": ["Resource Development"],
    "T1585": ["Resource Development"],
    "T1586": ["Resource Development"],
    "T1587": ["Resource Development"],
    "T1588": ["Resource Development"],
    "T1589": ["Resource Development"],
    "T1590": ["Resource Development"],
    "T1608": ["Resource Development"],
}

ALL_TACTICS: list[str] = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Reconnaissance",
    "Resource Development",
]


def _normalise_technique_id(raw: str) -> str:
    """Convert any format to 'TXXXX' (no sub-technique suffix)."""
    cleaned = re.sub(r"^attack\.", "", raw.strip(), flags=re.IGNORECASE)
    cleaned = re.sub(r"\.\d+$", "", cleaned)
    cleaned = cleaned.upper()
    if not cleaned.startswith("T"):
        cleaned = "T" + cleaned
    return cleaned


def technique_to_tactics(technique_id: str) -> list[str]:
    """Return list of tactic names for a technique ID string.

    Accepts: "T1059.001", "attack.t1059.001", "t1059".
    Returns [] for unknown techniques.
    """
    normalised = _normalise_technique_id(technique_id)
    return list(_TECHNIQUE_TACTICS.get(normalised, []))


def rules_coverage_by_tactic(rules: list[dict]) -> dict[str, int]:
    """Count unique rules covering each ATT&CK tactic.

    Each rule is counted at most once per tactic, even if it has multiple
    techniques that map to the same tactic.

    Returns dict mapping every tactic (all 14) to count >= 0.
    """
    counts: dict[str, int] = {tactic: 0 for tactic in ALL_TACTICS}

    for rule in rules:
        techniques = rule.get("mitre_techniques") or []
        covered_tactics: set[str] = set()
        for tech in techniques:
            covered_tactics.update(technique_to_tactics(tech))
        for tactic in covered_tactics:
            if tactic in counts:
                counts[tactic] += 1

    return counts