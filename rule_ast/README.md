# Rule AST

Structured AST representations of detection rules from two sources:

| Folder | Source | Count |
|--------|--------|-------|
| `sigma/` | DKSec translated Sigma rules (EQL) | ~2228 |
| `elastic/` | Elastic detection-rules (all active) | ~1652 |

## File format

Each `.json` file contains:

```json
{
  "source": "sigma" | "elastic",
  "name": "rule name or slug",
  "category": "process | network | registry | file | ...",
  "raw_query": "original EQL/KQL query string",
  "conditions": [
    {
      "field": "normalised ECS field name",
      "raw_field": "original field name in the query",
      "operator": ": | == | like~ | in | wildcard",
      "values": ["normalised value", ...],
      "raw_values": ["original value from query", ...]
    }
  ]
}
```

Fields are normalised to canonical ECS names (e.g. `process.executable` → `process.name`,
`winlog.event_data.CommandLine` → `process.command_line`) so rules from both sources
can be compared directly.

## Comparison report

See `comparison_report.md` for a full overlap / unique / ambiguous breakdown.
