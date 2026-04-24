from core.ast_model import RuleAST

# Test what happens when id, catalog, name, and severity (which have no defaults) are missing

print("Test 1: Missing 'id' field")
try:
    rule = RuleAST.from_dict({
        "catalog": "sigma",
        "name": "Test",
        "severity": "high"
    })
    print(f"  Success: Created rule with id={rule.id}")
except Exception as e:
    print(f"  Error: {type(e).__name__}: {e}")

print()

print("Test 2: Missing 'catalog' field")
try:
    rule = RuleAST.from_dict({
        "id": "test123",
        "name": "Test",
        "severity": "high"
    })
    print(f"  Success: Created rule with catalog={rule.catalog}")
except Exception as e:
    print(f"  Error: {type(e).__name__}: {e}")

print()

print("Test 3: Missing 'name' field")
try:
    rule = RuleAST.from_dict({
        "id": "test123",
        "catalog": "sigma",
        "severity": "high"
    })
    print(f"  Success: Created rule with name={rule.name}")
except Exception as e:
    print(f"  Error: {type(e).__name__}: {e}")

print()

print("Test 4: Missing 'severity' field")
try:
    rule = RuleAST.from_dict({
        "id": "test123",
        "catalog": "sigma",
        "name": "Test"
    })
    print(f"  Success: Created rule with severity={rule.severity}")
except Exception as e:
    print(f"  Error: {type(e).__name__}: {e}")
