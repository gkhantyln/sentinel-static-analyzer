from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import re


@dataclass
class StringAnalysis:
    total_strings: int
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    registry_paths: List[str] = field(default_factory=list)
    suspicious_commands: List[str] = field(default_factory=list)


ASCII_MIN = 32
ASCII_MAX = 126


def _extract_ascii_strings(data: bytes, min_length: int = 4) -> List[str]:
    result: List[str] = []
    current = bytearray()
    for b in data:
        if ASCII_MIN <= b <= ASCII_MAX:
            current.append(b)
        else:
            if len(current) >= min_length:
                result.append(current.decode("ascii", errors="ignore"))
            current = bytearray()
    if len(current) >= min_length:
        result.append(current.decode("ascii", errors="ignore"))
    return result


URL_RE = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
REGISTRY_KEY_HINTS = [
    "hkey_local_machine",
    "hkey_current_user",
    "hklm\\",
    "hkcu\\",
    "\\software\\microsoft\\windows\\currentversion\\run",
    "\\software\\microsoft\\windows\\currentversion\\runonce",
]
COMMAND_KEYWORDS = [
    "cmd.exe",
    "powershell",
    "wscript.exe",
    "cscript.exe",
    "schtasks",
    "reg.exe",
    "sc.exe",
    "net user",
]


def analyze_strings(file_path: Path) -> StringAnalysis:
    data = file_path.read_bytes()
    strings = _extract_ascii_strings(data)
    urls: List[str] = []
    ips: List[str] = []
    registry_paths: List[str] = []
    suspicious_commands: List[str] = []
    for s in strings:
        lower = s.lower()
        if URL_RE.search(s):
            urls.append(s)
        if IP_RE.search(s):
            ips.append(s)
        if any(hint in lower for hint in REGISTRY_KEY_HINTS):
            registry_paths.append(s)
        if any(keyword in lower for keyword in COMMAND_KEYWORDS):
            suspicious_commands.append(s)
    urls = sorted(set(urls))[:50]
    ips = sorted(set(ips))[:50]
    registry_paths = sorted(set(registry_paths))[:50]
    suspicious_commands = sorted(set(suspicious_commands))[:50]
    return StringAnalysis(
        total_strings=len(strings),
        urls=urls,
        ips=ips,
        registry_paths=registry_paths,
        suspicious_commands=suspicious_commands,
    )

