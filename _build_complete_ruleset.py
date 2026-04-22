import re, json, shutil, sys
sys.stdout.reconfigure(encoding="utf-8")
from pathlib import Path

SIGMA_AST   = Path("rule_ast/sigma")
ELASTIC_AST = Path("rule_ast/elastic")
REPORT_PATH = Path("rule_ast/comparison_report.md")
DECISIONS_PATH = Path("rule_ast/rule_decisions.md")
OUT_SIGMA   = Path("complete_ruleset/sigma")
OUT_ELASTIC = Path("complete_ruleset/elastic")

# Clear and recreate
shutil.rmtree(OUT_SIGMA,   ignore_errors=True)
shutil.rmtree(OUT_ELASTIC, ignore_errors=True)
OUT_SIGMA.mkdir(parents=True)
OUT_ELASTIC.mkdir(parents=True)

report    = REPORT_PATH.read_text(encoding="utf-8")
decisions = DECISIONS_PATH.read_text(encoding="utf-8")

# ── Sigma: only "Add to SIEM" (1331) ─────────────────────────────────────────
start = report.find("## \u2705 Add to SIEM")
end   = report.find("\n## ", start + 1)
section = report[start:end]
add_names = {n.lower().replace(" ", "_") for n in re.findall(r"\*\*([^*]+)\*\*", section)}
print(f"ADD names parsed: {len(add_names)}")

sigma_files = {f.stem: f for f in SIGMA_AST.glob("*.json")}
suffix_index: dict[str, list[str]] = {}
for slug in sigma_files:
    # Index all progressive suffixes (strip one leading component at a time)
    parts = slug.split("_")
    for i in range(len(parts)):
        suffix = "_".join(parts[i:])
        if len(suffix) >= 4:  # skip trivially short suffixes
            suffix_index.setdefault(suffix, []).append(slug)

add_slugs: set[str] = set()
unmatched_sigma = []
for name in add_names:
    if name in sigma_files:
        add_slugs.add(name)
    elif name in suffix_index:
        add_slugs.update(suffix_index[name])
    else:
        unmatched_sigma.append(name)

for slug in sorted(add_slugs):
    shutil.copy2(sigma_files[slug], OUT_SIGMA / sigma_files[slug].name)

# ── Elastic: KEEP list (section 2 of rule_decisions.md) ──────────────────────
keep_slugs: set[str] = set()
in_keep = False
for line in decisions.splitlines():
    if "## 2. Elastic Rules to KEEP" in line:
        in_keep = True
        continue
    if in_keep and line.startswith("## "):
        break
    if in_keep:
        m = re.search(r"`([a-z0-9_]+)`", line)
        if m:
            keep_slugs.add(m.group(1))

e_copied = 0
for f in sorted(ELASTIC_AST.glob("*.json")):
    data = json.loads(f.read_text(encoding="utf-8"))
    slug = data.get("slug", f.stem)
    if slug in keep_slugs:
        shutil.copy2(f, OUT_ELASTIC / f.name)
        e_copied += 1

print(f"Sigma  copied: {len(add_slugs)}")
print(f"Elastic copied: {e_copied}")
print(f"Total: {len(add_slugs) + e_copied}")
if unmatched_sigma:
    print(f"Sigma unmatched ({len(unmatched_sigma)}): {unmatched_sigma[:5]}")
