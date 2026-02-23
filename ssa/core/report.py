from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List

from ssa.core.features.anti_debug_vm import AntiDebugVMFeatures
from ssa.core.features.file_metadata import FileMetadata
from ssa.core.features.imports import ImportFeatureSummary
from ssa.core.features.sections import SectionsSummary
from ssa.core.features.strings import StringAnalysis
from ssa.core.scoring import ScoreBreakdown
from ssa.core.yara_scanner import YaraMatch


@dataclass
class AnalysisResult:
    file_path: Path
    metadata: FileMetadata
    imports: ImportFeatureSummary
    sections: SectionsSummary
    anti_debug_vm: AntiDebugVMFeatures
    strings: StringAnalysis
    yara_matches: List[YaraMatch]
    score: ScoreBreakdown

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": str(self.file_path),
            "metadata": asdict(self.metadata),
            "imports": asdict(self.imports),
            "sections": {
                "sections": [asdict(s) for s in self.sections.sections],
                "suspicious_sections": self.sections.suspicious_sections,
            },
            "anti_debug_vm": asdict(self.anti_debug_vm),
            "strings": asdict(self.strings),
            "yara_matches": [asdict(m) for m in self.yara_matches],
            "score": asdict(self.score),
        }
