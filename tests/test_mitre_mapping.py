# tests/test_mitre_mapping.py
from __future__ import annotations

import pytest
from core.mitre_mapping import (
    count_rules_without_mitre_tactics,
    rules_coverage_by_tactic,
    technique_to_tactics,
)

# Technique IDs may arrive as "T1059.001", "attack.t1059.001", or "t1059".

def test_technique_id_parsing_attack_prefix():
    tactics = technique_to_tactics("attack.t1059.001")
    assert "Execution" in tactics

def test_technique_id_parsing_uppercase():
    tactics = technique_to_tactics("T1059")
    assert "Execution" in tactics

def test_technique_id_parsing_lowercase_no_prefix():
    tactics = technique_to_tactics("t1003")
    assert "Credential Access" in tactics

def test_unknown_technique_returns_empty():
    tactics = technique_to_tactics("T9999")
    assert tactics == []

def test_persistence_technique():
    tactics = technique_to_tactics("T1053.005")
    assert "Persistence" in tactics or "Execution" in tactics  # schtasks = both

def test_lateral_movement_technique():
    tactics = technique_to_tactics("T1021")
    assert "Lateral Movement" in tactics

def test_rules_coverage_by_tactic_basic():
    """Coverage dict maps each tactic to a count of rules that cover it."""
    rules = [
        {"mitre_techniques": ["attack.t1059.001", "attack.t1003.001"]},
        {"mitre_techniques": ["attack.t1059.001"]},
        {"mitre_techniques": []},
    ]
    cov = rules_coverage_by_tactic(rules)
    assert cov["Execution"] == 2
    assert cov["Credential Access"] == 1
    assert cov.get("Lateral Movement", 0) == 0

def test_rules_coverage_by_tactic_deduplicates_per_rule():
    """One rule with 2 techniques in the same tactic counts as 1 for that tactic."""
    rules = [
        {"mitre_techniques": ["attack.t1059.001", "attack.t1059.003"]},
    ]
    cov = rules_coverage_by_tactic(rules)
    assert cov["Execution"] == 1  # same tactic, different sub-techniques → 1 rule

def test_all_tactics_present_in_coverage():
    """coverage_by_tactic returns all 14 ATT&CK tactics, even with count 0."""
    cov = rules_coverage_by_tactic([])
    expected_tactics = {
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact",
        "Reconnaissance", "Resource Development",
    }
    assert expected_tactics.issubset(set(cov.keys()))


def test_rules_coverage_accepts_direct_tactic_tags():
    rules = [{"mitre_techniques": ["attack.execution", "Command-and-Control"]}]
    cov = rules_coverage_by_tactic(rules)
    assert cov["Execution"] == 1
    assert cov["Command and Control"] == 1


def test_count_rules_without_mitre_tactics():
    rules = [
        {"mitre_techniques": ["attack.t1059.001"]},
        {"mitre_techniques": ["attack.execution"]},
        {"mitre_techniques": []},
        {"mitre_techniques": ["custom.non_mitre_tag"]},
        {},
    ]
    assert count_rules_without_mitre_tactics(rules) == 3