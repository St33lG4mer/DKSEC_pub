#!/usr/bin/env python3
"""
Generates a rule decision list from the comparison report and AST files.

Decision logic:
  - "Add to SIEM" (1185): Sigma rules with no Elastic equivalent → ADD to Elastic
  - "Skip" (296): Elastic already covers these → KEEP Elastic, skip Sigma import
  - "Pick one" (280): Both cover similar things → ADD Sigma, DELETE the Elastic equivalent
  - "Weak Overlap" (429): Sigma adds value → ADD Sigma, KEEP Elastic too
  - "Uncompared" (38): → manual review
  - Elastic rules not mentioned in any section → KEEP (unique Elastic-only coverage)

Output: rule_ast/rule_decisions.md
"""

import json
import re
import sys
from pathlib import Path

REPORT = Path("rule_ast/comparison_report.md")
ELASTIC_AST_DIR = Path("rule_ast/elastic")
OUTPUT = Path("rule_ast/rule_decisions.md")


# ── Helpers ────────────────────────────────────────────────────────────────────

def load_elastic_rules():
    """Returns dict: normalised_name -> {slug, file, risk_score, name}"""
    rules = {}
    for f in ELASTIC_AST_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            slug = data.get("slug") or f.stem
            name = data.get("name", slug)
            norm = normalise(name)
            rules[norm] = {"slug": slug, "file": f.name, "risk_score": data.get("risk_score", 0), "name": name}
        except Exception:
            pass
    return rules


def normalise(s: str) -> str:
    """Lower-case, strip punctuation, collapse spaces — for loose matching."""
    s = s.lower()
    s = re.sub(r"[,\-\(\)/\\]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def match_elastic(raw_name: str, elastic_rules: dict) -> str | None:
    """
    raw_name may be:
      - "Rule Name, risk 47"  (from Skip/Pick-one sections)
      - "Rule Name"           (plain)
    Returns the matching normalised key or None.
    """
    # Strip ", risk N" suffix if present
    cleaned = re.sub(r",\s*risk\s*\d+\s*$", "", raw_name).strip()
    norm = normalise(cleaned)

    # Exact normalised match
    if norm in elastic_rules:
        return norm

    # Prefix match (report names sometimes truncate long titles)
    for key in elastic_rules:
        if key.startswith(norm) or norm.startswith(key):
            return key

    return None


# ── Section parsers ────────────────────────────────────────────────────────────

def parse_section(text: str, start_marker: str, end_marker: str) -> str:
    """Extract text between two markers."""
    start = text.find(start_marker)
    if start == -1:
        return ""
    end = text.find(end_marker, start + len(start_marker))
    return text[start: end if end != -1 else len(text)]


def extract_add_to_siem(section: str) -> list[str]:
    """Bold rule names from the Add to SIEM table."""
    return re.findall(r"\*\*([^*]+)\*\*", section)


def extract_skip(section: str) -> list[tuple[str, str]]:
    """
    Returns list of (sigma_name, elastic_name) from Skip table rows.
    Table: | Sigma Rule | Elastic Equivalent | Score | Notes |
    """
    pairs = []
    for line in section.splitlines():
        cells = [c.strip() for c in line.split("|") if c.strip()]
        if len(cells) >= 3 and cells[0] and not cells[0].startswith("Sigma") and not cells[0].startswith("-"):
            try:
                float(cells[2])  # score column sanity-check
                pairs.append((cells[0], cells[1]))
            except ValueError:
                pass
    return pairs


def extract_pick_one(section: str) -> list[tuple[str, str]]:
    """
    Returns list of (sigma_name, elastic_name) from Pick-one table rows.
    Table: | Score | Sigma Rule | Elastic Match | Risk | Sigma adds | Elastic adds |
    """
    pairs = []
    for line in section.splitlines():
        cells = [c.strip() for c in line.split("|") if c.strip()]
        if len(cells) >= 3:
            try:
                float(cells[0])  # first cell is score
                pairs.append((cells[1], cells[2]))
            except ValueError:
                pass
    return pairs


def extract_weak_overlap(section: str) -> list[str]:
    """
    Returns Sigma rule names from Weak Overlap table.
    Table: | Sigma Rule | Best Elastic Match | Score | Shared |
    """
    names = []
    for line in section.splitlines():
        cells = [c.strip() for c in line.split("|") if c.strip()]
        if len(cells) >= 3 and cells[0]:
            try:
                float(cells[2])  # score column
                names.append(cells[0])
            except ValueError:
                pass
    return names


def extract_uncompared(section: str) -> list[str]:
    """Rule names from Uncompared table (first column, not bold)."""
    names = []
    for line in section.splitlines():
        cells = [c.strip() for c in line.split("|") if c.strip()]
        if len(cells) >= 2 and cells[0] and not cells[0].startswith("Rule") and not cells[0].startswith("-"):
            # Skip header-like rows
            if not cells[0].startswith("These") and not cells[0].startswith("##"):
                names.append(cells[0])
    return names


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    text = REPORT.read_text(encoding="utf-8")
    elastic_rules = load_elastic_rules()  # norm_name -> info

    # Section boundaries
    add_sec    = parse_section(text, "## ✅ Add to SIEM",              "## ⏭️ Skip")
    skip_sec   = parse_section(text, "## ⏭️ Skip",                     "## ⚖️ Moderate Overlap")
    pick_sec   = parse_section(text, "## ⚖️ Moderate Overlap",         "## 🔍 Weak Overlap")
    weak_sec   = parse_section(text, "## 🔍 Weak Overlap",             "## ❓ Uncompared")
    uncomp_sec = parse_section(text, "## ❓ Uncompared",               "\n## ")  # last section

    # Parse each section
    sigma_add_names   = extract_add_to_siem(add_sec)
    skip_pairs        = extract_skip(skip_sec)
    pick_pairs        = extract_pick_one(pick_sec)
    sigma_weak_names  = extract_weak_overlap(weak_sec)
    sigma_uncomp      = extract_uncompared(uncomp_sec)

    # ── Elastic rule decisions ────────────────────────────────────────────────
    # "Pick one": DELETE the Elastic rule (replace with Sigma)
    elastic_delete_norm: dict[str, list[str]] = {}  # norm_elastic -> [sigma_names]
    pick_unmatched = []
    for sigma_name, elastic_raw in pick_pairs:
        norm = match_elastic(elastic_raw, elastic_rules)
        if norm:
            elastic_delete_norm.setdefault(norm, []).append(sigma_name)
        else:
            pick_unmatched.append((sigma_name, elastic_raw))

    # "Skip": KEEP the Elastic rule
    elastic_skip_norm: dict[str, list[str]] = {}
    for sigma_name, elastic_raw in skip_pairs:
        norm = match_elastic(elastic_raw, elastic_rules)
        if norm:
            elastic_skip_norm.setdefault(norm, []).append(sigma_name)

    # All Elastic rules not marked for deletion → KEEP
    elastic_keep_norm = {
        k: v for k, v in elastic_rules.items()
        if k not in elastic_delete_norm
    }

    # ── Sigma rules to import ─────────────────────────────────────────────────
    # Add to SIEM + Weak overlap + Pick one (they replace the deleted Elastic rules)
    sigma_import = sorted(set(sigma_add_names) | set(sigma_weak_names) | {s for s, _ in pick_pairs})
    sigma_skip   = sorted({s for s, _ in skip_pairs})
    sigma_manual = sorted(set(sigma_uncomp))

    # ── Write output ──────────────────────────────────────────────────────────
    lines = [
        "# Rule Decision List",
        "",
        "Generated from `rule_ast/comparison_report.md`.",
        "",
        "## Summary",
        "",
        "| Action | Count | Details |",
        "|--------|-------|---------|",
        f"| 🗑️ **Delete from Elastic** | **{len(elastic_delete_norm)}** | Replaced by their Sigma equivalents |",
        f"| ✅ **Keep in Elastic** | **{len(elastic_keep_norm)}** | No Sigma equivalent, or Elastic is superior |",
        f"| ➕ **Add Sigma rules to Elastic** | **{len(sigma_import)}** | New coverage + replacements for deleted rules |",
        f"| ⏭️ **Skip Sigma import** | **{len(sigma_skip)}** | Elastic already covers these |",
        f"| 🔍 **Manual review** | **{len(sigma_manual)}** | Unparseable Sigma conditions |",
        "",
        "---",
        "",
        "## 1. Elastic Rules to DELETE",
        "",
        "These are replaced by their Sigma equivalents from the 'Pick one' section.",
        "Delete these from Kibana after importing the corresponding Sigma rules.",
        "",
        "| Elastic Rule | Slug | Risk | Replaced by Sigma Rule(s) |",
        "|-------------|------|------|--------------------------|",
    ]

    for norm in sorted(elastic_delete_norm.keys()):
        info = elastic_rules[norm]
        sigma_str = ", ".join(f"`{s}`" for s in elastic_delete_norm[norm][:3])
        lines.append(f"| {info['name']} | `{info['slug']}` | {info['risk_score']} | {sigma_str} |")

    if pick_unmatched:
        lines += [
            "",
            "### Could Not Match to AST (verify manually)",
            "",
            "| Sigma Rule | Elastic Name from Report |",
            "|-----------|------------------------|",
        ]
        for sigma, elastic in pick_unmatched[:50]:
            lines.append(f"| `{sigma}` | {elastic} |")

    lines += [
        "",
        "---",
        "",
        "## 2. Elastic Rules to KEEP",
        "",
        f"**{len(elastic_keep_norm)} rules** — these stay in Elastic.",
        "Includes rules with no Sigma overlap and rules where Elastic coverage is superior.",
        "",
    ]
    for norm in sorted(elastic_keep_norm.keys()):
        info = elastic_keep_norm[norm]
        note = " *(Skip — Sigma equivalent exists but Elastic is better)*" if norm in elastic_skip_norm else ""
        lines.append(f"- `{info['slug']}` — {info['name']}{note}")

    lines += [
        "",
        "---",
        "",
        "## 3. Sigma Rules to ADD to Elastic",
        "",
        f"**{len(sigma_import)} rules** to import.",
        "",
        "Includes:",
        f"- {len(sigma_add_names)} rules with no Elastic equivalent ('Add to SIEM')",
        f"- {len(sigma_weak_names)} rules with weak/partial overlap ('Weak Overlap' — safe to add)",
        f"- {len([s for s,_ in pick_pairs])} replacements for deleted Elastic rules ('Pick one')",
        "",
    ]
    for name in sorted(sigma_import):
        lines.append(f"- `{name}`")

    lines += [
        "",
        "---",
        "",
        "## 4. Sigma Rules to SKIP (Elastic Already Covers)",
        "",
        f"**{len(sigma_skip)} Sigma rules** — do NOT import, Elastic has equivalent or better coverage.",
        "",
    ]
    for name in sigma_skip:
        lines.append(f"- `{name}`")

    if sigma_manual:
        lines += [
            "",
            "---",
            "",
            "## 5. Manual Review (Unparseable Sigma Conditions)",
            "",
            f"**{len(sigma_manual)} rules** — check these individually.",
            "",
        ]
        for name in sigma_manual:
            lines.append(f"- `{name}`")

    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Written: {OUTPUT}")
    print(f"  DELETE {len(elastic_delete_norm)} Elastic rules")
    print(f"  KEEP   {len(elastic_keep_norm)} Elastic rules")
    print(f"  ADD    {len(sigma_import)} Sigma rules")
    print(f"  SKIP   {len(sigma_skip)} Sigma imports")
    print(f"  REVIEW {len(sigma_manual)} manually")
    if pick_unmatched:
        print(f"  WARN   {len(pick_unmatched)} 'Pick one' Elastic names couldn't be matched to AST files")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
