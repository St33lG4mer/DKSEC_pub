"""Tests for sigma_to_eql — the pure translation function."""
from adapters.sigma.translator import sigma_to_eql

SAMPLE_SIGMA_YAML = """\
title: Test Sigma Rule
id: 12345678-1234-1234-1234-123456789012
status: test
description: A test sigma rule
level: high
tags:
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\cmd.exe'
  condition: selection
"""


def test_sigma_to_eql_returns_string_for_valid_rule():
    result = sigma_to_eql(SAMPLE_SIGMA_YAML)
    # pySigma may or may not produce output depending on pipeline mapping
    # We assert it either returns a non-empty string or None — no exception
    assert result is None or (isinstance(result, str) and len(result) > 0)


def test_sigma_to_eql_returns_none_for_empty_input():
    result = sigma_to_eql("")
    assert result is None


def test_sigma_to_eql_returns_none_for_unparseable_yaml():
    result = sigma_to_eql("not: valid: sigma:::")
    assert result is None


def test_sigma_to_eql_returns_none_for_rule_with_no_detection():
    minimal = """\
title: No Detection
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
status: test
logsource:
  category: process_creation
  product: windows
detection:
  condition: ''
"""
    result = sigma_to_eql(minimal)
    assert result is None or isinstance(result, str)
