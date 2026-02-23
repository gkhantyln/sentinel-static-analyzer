import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import requests

from ssa.common.errors import SSAError


@dataclass
class VirusTotalStats:
    harmless: int
    malicious: int
    suspicious: int
    undetected: int
    timeout: int


@dataclass
class VirusTotalResult:
    analysis_id: str
    status: str
    stats: VirusTotalStats
    permalink: Optional[str]


VT_API_URL = "https://www.virustotal.com/api/v3"
VT_MAX_FILE_SIZE = 32 * 1024 * 1024


def _load_vt_api_key() -> Optional[str]:
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parents[2] / ".env",
    ]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            text = candidate.read_text(encoding="utf-8")
        except OSError:
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key == "VT_API_KEY" and value:
                os.environ["VT_API_KEY"] = value
                return value
    existing = os.getenv("VT_API_KEY")
    if existing:
        return existing
    return None


def _extract_stats(attributes: Dict[str, Any]) -> VirusTotalStats:
    stats = attributes.get("stats") or {}
    return VirusTotalStats(
        harmless=int(stats.get("harmless", 0)),
        malicious=int(stats.get("malicious", 0)),
        suspicious=int(stats.get("suspicious", 0)),
        undetected=int(stats.get("undetected", 0)),
        timeout=int(stats.get("timeout", 0)),
    )


def scan_file_with_virustotal(file_path: Path, sha256: str, timeout_seconds: int = 60) -> VirusTotalResult:
    api_key = _load_vt_api_key()
    if not api_key:
        raise SSAError("VT_API_KEY ortam değişkeni tanımlı değil veya .env içinde bulunamadı.")
    size = file_path.stat().st_size
    if size > VT_MAX_FILE_SIZE:
        raise SSAError("VirusTotal ücretsiz API 32 MB üzerindeki dosyaları kabul etmez.")
    headers = {"x-apikey": api_key}
    with file_path.open("rb") as f:
        files = {"file": (file_path.name, f)}
        response = requests.post(f"{VT_API_URL}/files", headers=headers, files=files, timeout=30)
    if response.status_code >= 400:
        raise SSAError(f"VirusTotal dosya yükleme hatası: {response.status_code} {response.text}")
    try:
        data = response.json()
    except json.JSONDecodeError:
        raise SSAError("VirusTotal dosya yükleme yanıtı JSON formatında değil.")
    analysis_id = data.get("data", {}).get("id")
    if not analysis_id:
        raise SSAError("VirusTotal dosya yükleme yanıtında analiz kimliği bulunamadı.")
    deadline = time.time() + timeout_seconds
    last_attributes: Dict[str, Any] = {}
    status = "queued"
    while time.time() < deadline:
        poll = requests.get(
            f"{VT_API_URL}/analyses/{analysis_id}",
            headers=headers,
            timeout=30,
        )
        if poll.status_code >= 400:
            raise SSAError(f"VirusTotal analiz sorgu hatası: {poll.status_code} {poll.text}")
        payload = poll.json()
        attributes = payload.get("data", {}).get("attributes") or {}
        last_attributes = attributes
        status = attributes.get("status", "unknown")
        if status == "completed":
            break
        time.sleep(4)
    stats = _extract_stats(last_attributes)
    permalink = f"https://www.virustotal.com/gui/file/{sha256}/detection"
    return VirusTotalResult(
        analysis_id=analysis_id,
        status=status,
        stats=stats,
        permalink=permalink,
    )

