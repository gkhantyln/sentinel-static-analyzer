from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]


def scan_with_yara(file_path: Path, rules_dir: Optional[Path] = None) -> List[YaraMatch]:
    try:
        import yara  # type: ignore
    except ImportError:
        return []
    if rules_dir is None:
        return []
    rules_dir = rules_dir.expanduser().resolve()
    if not rules_dir.is_dir():
        return []
    rule_files = sorted(
        [p for p in rules_dir.iterdir() if p.suffix.lower() in {".yar", ".yara", ".txt"}]
    )
    if not rule_files:
        return []
    filepaths = {str(p.stem): str(p) for p in rule_files}
    rules = yara.compile(filepaths=filepaths)
    matches = rules.match(str(file_path))
    result: List[YaraMatch] = []
    for m in matches:
        meta = dict(getattr(m, "meta", {}))
        tags = list(getattr(m, "tags", []))
        result.append(
            YaraMatch(
                rule=m.rule,
                namespace=m.namespace,
                tags=tags,
                meta=meta,
            )
        )
    return result
