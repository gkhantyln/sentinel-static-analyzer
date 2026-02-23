from pathlib import Path

from ssa.common.errors import FileValidationError

try:
    import magic  # type: ignore
except ImportError:
    magic = None  # type: ignore[assignment]


def _ensure_exists(file_path: Path) -> None:
    if not file_path.is_file():
        raise FileValidationError(f"Dosya bulunamadı: {file_path}")


def _has_mz_header(file_path: Path) -> bool:
    with file_path.open("rb") as f:
        header = f.read(2)
    return header == b"MZ"


def _is_executable_mime(file_path: Path) -> bool:
    if magic is None:
        return True
    mime = magic.from_file(str(file_path), mime=True)
    if mime is None:
        return False
    return "application/x-dosexec" in mime or "application/vnd.microsoft.portable-executable" in mime


def validate_pe_file(path: str | Path) -> Path:
    file_path = Path(path).expanduser().resolve()
    _ensure_exists(file_path)
    if not _has_mz_header(file_path):
        raise FileValidationError("Dosya MZ header içermiyor, muhtemelen geçerli bir PE değil.")
    if not _is_executable_mime(file_path):
        raise FileValidationError("Dosya MIME tipi exe/PE ile uyumlu değil.")
    return file_path
