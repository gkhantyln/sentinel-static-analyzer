from dataclasses import dataclass

from ssa.core.features.imports import ImportFeatureSummary


VM_ARTIFACT_STRINGS = {
    "VMware",
    "VirtualBox",
    "VBOX",
}


@dataclass
class AntiDebugVMFeatures:
    has_anti_debug_apis: bool
    has_vm_artifacts: bool


def analyze_anti_debug_vm(imports: ImportFeatureSummary) -> AntiDebugVMFeatures:
    has_anti_debug = bool(imports.anti_debug_apis)
    has_vm = False
    return AntiDebugVMFeatures(
        has_anti_debug_apis=has_anti_debug,
        has_vm_artifacts=has_vm,
    )

