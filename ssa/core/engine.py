from pathlib import Path
from typing import Optional

from ssa.common.errors import FileValidationError
from ssa.core.features.anti_debug_vm import analyze_anti_debug_vm
from ssa.core.features.file_metadata import FileMetadata
from ssa.core.features.imports import analyze_imports
from ssa.core.features.sections import analyze_sections
from ssa.core.features.strings import analyze_strings
from ssa.core.file_validator import validate_pe_file
from ssa.core.pe_parser import load_pe
from ssa.core.report import AnalysisResult
from ssa.core.scoring import compute_score
from ssa.core.yara_scanner import scan_with_yara


def analyze(path: str | Path, yara_rules_dir: Optional[Path] = None) -> AnalysisResult:
    validated_path = validate_pe_file(path)
    try:
        pe = load_pe(validated_path)
    except Exception as exc:
        raise FileValidationError(f"PE dosyası yüklenemedi: {exc}") from exc
    try:
        metadata = FileMetadata.from_pe(validated_path, pe)
        imports = analyze_imports(pe)
        sections = analyze_sections(pe)
        anti_debug_vm = analyze_anti_debug_vm(imports)
        string_analysis = analyze_strings(validated_path)
        yara_matches = scan_with_yara(validated_path, rules_dir=yara_rules_dir)
        score = compute_score(
            metadata=metadata,
            imports=imports,
            sections=sections,
            anti_debug_vm=anti_debug_vm,
            strings=string_analysis,
            yara_matches=yara_matches,
        )
        return AnalysisResult(
            file_path=validated_path,
            metadata=metadata,
            imports=imports,
            sections=sections,
            anti_debug_vm=anti_debug_vm,
            strings=string_analysis,
            yara_matches=yara_matches,
            score=score,
        )
    finally:
        try:
            pe.close()
        except Exception:
            pass
