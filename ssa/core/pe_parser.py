from pathlib import Path
from hashlib import md5, sha1, sha256

import pefile


def load_pe(file_path: Path) -> pefile.PE:
    pe = pefile.PE(str(file_path), fast_load=True)
    pe.parse_data_directories()
    return pe


def compute_hashes(file_path: Path) -> dict[str, str]:
    data = file_path.read_bytes()
    return {
        "md5": md5(data).hexdigest(),
        "sha1": sha1(data).hexdigest(),
        "sha256": sha256(data).hexdigest(),
    }


def get_overlay_size(pe: pefile.PE, file_size: int) -> int:
    offset = pe.get_overlay_data_start_offset()
    if offset is None:
        return 0
    if offset >= file_size:
        return 0
    return file_size - offset

