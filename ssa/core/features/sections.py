from dataclasses import dataclass, field
from typing import List

import pefile


@dataclass
class SectionInfo:
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: int
    is_executable: bool
    is_writable: bool


@dataclass
class SectionsSummary:
    sections: List[SectionInfo] = field(default_factory=list)
    suspicious_sections: int = 0


def analyze_sections(pe: pefile.PE) -> SectionsSummary:
    result = SectionsSummary()
    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip("\x00")
        entropy = section.get_entropy()
        characteristics = section.Characteristics
        is_executable = bool(characteristics & 0x20000000)
        is_writable = bool(characteristics & 0x80000000)
        info = SectionInfo(
            name=name,
            virtual_size=section.Misc_VirtualSize,
            raw_size=section.SizeOfRawData,
            entropy=entropy,
            characteristics=characteristics,
            is_executable=is_executable,
            is_writable=is_writable,
        )
        result.sections.append(info)
        if is_executable and is_writable:
            result.suspicious_sections += 1
    return result

