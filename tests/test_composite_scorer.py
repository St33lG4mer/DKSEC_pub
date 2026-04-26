"""
Tests for composite scorer (core.normalizer) and updated compare engine (pipeline.compare).

Covers:
- extract_significant_values
- name_tokens
- composite_score
- _categories_compatible
- compare_rules integration
"""
import pytest

from core.ast_model import RuleAST, Condition
from core.normalizer import extract_significant_values, name_tokens, composite_score
from pipeline.compare import _categories_compatible, compare_rules


def make_rule(id_, catalog, name, values, cats, mitre=[]):
    return RuleAST(
        id=id_, catalog=catalog, name=name, description="",
        severity="medium", mitre_techniques=list(mitre),
        event_categories=list(cats),
        conditions=[Condition("process.name", "process.name", "==", list(values), list(values))],
        raw_query="", language="eql", translated_query=None, source_path="", metadata={}
    )


# ---------------------------------------------------------------------------
# extract_significant_values
# ---------------------------------------------------------------------------

def test_esv_exe_filenames_extracted():
    rule = make_rule("r1", "sigma", "uac_bypass_changepk", ["powershell.exe", "cmd.exe"], [])
    result = extract_significant_values(rule)
    assert "powershell.exe" in result
    assert "cmd.exe" in result


def test_esv_registry_path_extracted():
    rule = make_rule("r2", "sigma", "registry_run_key",
                     ["hklm\\software\\microsoft\\windows\\run"], [])
    result = extract_significant_values(rule)
    assert "hklm\\software\\microsoft\\windows\\run" in result


def test_esv_generic_stop_words_excluded():
    rule = make_rule("r3", "sigma", "generic_rule", ["true", "process", "windows"], [])
    result = extract_significant_values(rule)
    assert result == frozenset()


def test_esv_wildcard_only_excluded():
    rule = make_rule("r4", "sigma", "wildcard_rule", ["*"], [])
    result = extract_significant_values(rule)
    assert "*" not in result


# ---------------------------------------------------------------------------
# name_tokens
# ---------------------------------------------------------------------------

def test_name_tokens_strips_sigma_prefixes():
    rule = make_rule("r5", "sigma", "proc_creation_win_uac_bypass_changepk", [], [])
    tokens = name_tokens(rule)
    assert "uac" in tokens
    assert "bypass" in tokens
    assert "changepk" in tokens
    assert "proc" not in tokens
    assert "creation" not in tokens
    assert "win" not in tokens


def test_name_tokens_space_separated_lowercased():
    rule = make_rule("r6", "sigma", "PowerShell Encoded Command Execution", [], [])
    tokens = name_tokens(rule)
    assert "encoded" in tokens
    assert "command" in tokens
    assert "execution" in tokens


def test_name_tokens_drops_short_words():
    rule = make_rule("r7", "sigma", "win_uac_or_bypass", [], [])
    tokens = name_tokens(rule)
    # "or" has len=2, must be dropped
    assert "or" not in tokens
    # meaningful tokens remain
    assert "uac" in tokens
    assert "bypass" in tokens


# ---------------------------------------------------------------------------
# composite_score
# ---------------------------------------------------------------------------

def test_composite_score_matching_exe_in_process_category():
    a = make_rule("a1", "sigma", "uac_bypass_powershell_exec", ["powershell.exe"], ["process"])
    b = make_rule("b1", "elastic", "uac_bypass_powershell_exec", ["powershell.exe"], ["process"])
    composite, _ = composite_score(a, b)
    assert composite > 0.2


def test_composite_score_different_values_and_names():
    a = make_rule("a2", "sigma", "uac_bypass_alpha", ["powershell.exe"], ["process"])
    b = make_rule("b2", "elastic", "tunneling_exfil_beta", ["nslookup.exe"], ["network"])
    composite, _ = composite_score(a, b)
    assert composite < 0.1


def test_composite_score_same_mitre_boosts_mitre_signal():
    a = make_rule("a3", "sigma", "sigma_test_mitre", [], [], mitre=["attack.t1059.001"])
    b = make_rule("b3", "elastic", "elastic_test_mitre", [], [], mitre=["attack.t1059.001"])
    _, signals = composite_score(a, b)
    assert signals["mitre_score"] > 0


def test_composite_score_empty_mitre_no_penalty():
    a = make_rule("a4", "sigma", "uac_bypass_powershell_exec", ["powershell.exe"], ["process"])
    b = make_rule("b4", "elastic", "uac_bypass_powershell_exec", ["powershell.exe"], ["process"])
    composite, signals = composite_score(a, b)
    assert signals["mitre_score"] == pytest.approx(0.0)
    assert composite > 0.0  # value + name signals still drive the score


# ---------------------------------------------------------------------------
# _categories_compatible
# ---------------------------------------------------------------------------

def test_categories_compatible_same_category():
    a = make_rule("a", "sigma", "test_rule", [], ["process"])
    b = make_rule("b", "elastic", "test_rule", [], ["process"])
    assert _categories_compatible(a, b) is True


def test_categories_compatible_disjoint_categories():
    a = make_rule("a", "sigma", "test_rule", [], ["registry"])
    b = make_rule("b", "elastic", "test_rule", [], ["network"])
    assert _categories_compatible(a, b) is False


def test_categories_compatible_empty_a_is_compatible():
    a = make_rule("a", "sigma", "test_rule", [], [])
    b = make_rule("b", "elastic", "test_rule", [], ["process"])
    assert _categories_compatible(a, b) is True


def test_categories_compatible_partial_overlap():
    a = make_rule("a", "sigma", "test_rule", [], ["process", "network"])
    b = make_rule("b", "elastic", "test_rule", [], ["network"])
    assert _categories_compatible(a, b) is True


# ---------------------------------------------------------------------------
# compare_rules integration
# ---------------------------------------------------------------------------

def test_compare_rules_two_matching_pairs_one_unique():
    sigma_rules = [
        make_rule("s1", "sigma", "uac_bypass_powershell_exec", ["powershell.exe"], ["process"]),
        make_rule("s2", "sigma", "lolbin_certutil_downloader", ["certutil.exe"], ["process"]),
        make_rule("s3", "sigma", "wmiexec_lateral_movement_recon", ["wmiexec.exe"], ["process"]),
    ]
    elastic_rules = [
        make_rule("e1", "elastic", "uac_bypass_powershell_exec", ["powershell.exe"], ["process"]),
        make_rule("e2", "elastic", "lolbin_certutil_downloader", ["certutil.exe"], ["process"]),
    ]
    result = compare_rules(sigma_rules, elastic_rules, threshold=0.25)
    assert len(result.overlaps) == 2
    assert len(result.unique_a) == 1
    assert result.unique_a[0].id == "s3"


def test_compare_rules_category_mismatch_no_overlap():
    # Same names and values but incompatible categories
    sigma_rules = [
        make_rule("s1", "sigma", "uac_bypass_powershell_exec", ["powershell.exe"], ["process"]),
    ]
    elastic_rules = [
        make_rule("e1", "elastic", "uac_bypass_powershell_exec", ["powershell.exe"], ["network"]),
    ]
    result = compare_rules(sigma_rules, elastic_rules, threshold=0.25)
    assert result.overlaps == []


def test_compare_rules_empty_inputs_no_overlap():
    result = compare_rules([], [])
    assert len(result.overlaps) == 0
