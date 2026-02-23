from dataclasses import dataclass
from typing import List

from ssa.core.features.anti_debug_vm import AntiDebugVMFeatures
from ssa.core.features.file_metadata import FileMetadata
from ssa.core.features.imports import ImportFeatureSummary
from ssa.core.features.sections import SectionsSummary
from ssa.core.features.strings import StringAnalysis
from ssa.core.yara_scanner import YaraMatch


@dataclass
class ScoreBreakdown:
    privilege_escalation: int
    anti_debug_vm: int
    overlay: int
    sections: int
    yara: int
    strings: int
    total: int
    level: str


def clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


def compute_score(
    metadata: FileMetadata,
    imports: ImportFeatureSummary,
    sections: SectionsSummary,
    anti_debug_vm: AntiDebugVMFeatures,
    strings: StringAnalysis,
    yara_matches: List[YaraMatch],
) -> ScoreBreakdown:
    privilege_score = clamp(len(imports.privilege_apis) * 10, 0, 30)
    anti_debug_score = 0
    if anti_debug_vm.has_anti_debug_apis:
        anti_debug_score += 15
    if anti_debug_vm.has_vm_artifacts:
        anti_debug_score += 10
    anti_debug_score = clamp(anti_debug_score, 0, 25)
    overlay_score = 0
    if metadata.overlay_size > 0:
        overlay_score = 10
    if metadata.overlay_size > 1024 * 1024:
        overlay_score = 20
    overlay_score = clamp(overlay_score, 0, 20)
    sections_score = clamp(sections.suspicious_sections * 10, 0, 30)
    yara_score = clamp(len(yara_matches) * 5, 0, 25)
    indicator_count = (
        len(strings.urls)
        + len(strings.ips)
        + len(strings.registry_paths)
        + len(strings.suspicious_commands)
    )
    strings_score = clamp(indicator_count * 5, 0, 25)
    total = clamp(
        privilege_score
        + anti_debug_score
        + overlay_score
        + sections_score
        + yara_score
        + strings_score,
        0,
        100,
    )
    if total <= 20:
        level = "low"
    elif total <= 40:
        level = "medium"
    elif total <= 70:
        level = "high"
    else:
        level = "critical"
    return ScoreBreakdown(
        privilege_escalation=privilege_score,
        anti_debug_vm=anti_debug_score,
        overlay=overlay_score,
        sections=sections_score,
        yara=yara_score,
        strings=strings_score,
        total=total,
        level=level,
    )
