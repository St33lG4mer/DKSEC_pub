"""
Pure pySigma → EQL translation.
Isolated here so SigmaAdapter.translate() can be tested independently via mocking.
"""
from __future__ import annotations


def sigma_to_eql(yaml_text: str) -> str | None:
    """
    Convert a Sigma rule YAML string to EQL using pySigma's EqlBackend.

    Returns a non-empty EQL string on success, or None if:
    - yaml_text is empty or unparseable
    - pySigma produces no output (unsupported logsource/condition)
    - any exception is raised during translation
    """
    if not yaml_text or not yaml_text.strip():
        return None
    try:
        from sigma.backends.elasticsearch import EqlBackend
        from sigma.collection import SigmaCollection
        from sigma.pipelines.elasticsearch.windows import ecs_windows

        collection = SigmaCollection.from_yaml(yaml_text)
        backend = EqlBackend(processing_pipeline=ecs_windows())
        queries = backend.convert(collection)
        if not queries:
            return None
        return "\n\n".join(queries)
    except Exception:
        return None
