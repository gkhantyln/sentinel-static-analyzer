from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pefile

from ssa.core.pe_parser import compute_hashes, get_overlay_size


@dataclass
class FileMetadata:
    file_path: Path
    size: int
    md5: str
    sha1: str
    sha256: str
    timestamp: Optional[int]
    machine: Optional[str]
    overlay_size: int

    @classmethod
    def from_pe(cls, file_path: Path, pe: pefile.PE) -> "FileMetadata":
        size = file_path.stat().st_size
        hashes = compute_hashes(file_path)
        timestamp = getattr(pe.FILE_HEADER, "TimeDateStamp", None)
        machine_value = getattr(pe.FILE_HEADER, "Machine", None)
        machine = hex(machine_value) if machine_value is not None else None
        overlay_size = get_overlay_size(pe, size)
        return cls(
            file_path=file_path,
            size=size,
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            sha256=hashes["sha256"],
            timestamp=timestamp,
            machine=machine,
            overlay_size=overlay_size,
        )

