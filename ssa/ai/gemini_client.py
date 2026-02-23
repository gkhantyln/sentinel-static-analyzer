import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import requests

from ssa.common.errors import SSAError


def _load_gemini_api_key() -> Optional[str]:
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
            if key == "GEMINI_API_KEY" and value:
                os.environ["GEMINI_API_KEY"] = value
                return value
    existing = os.getenv("GEMINI_API_KEY")
    if existing:
        return existing
    return None


def generate_ai_report(report: Dict[str, Any], language: str = "tr") -> str:
    api_key = _load_gemini_api_key()
    if not api_key:
        raise SSAError("GEMINI_API_KEY ortam değişkeni tanımlı değil veya .env içinde bulunamadı.")
    if language not in {"tr", "en"}:
        language = "en"
    if language == "tr":
        instruction = (
            "Aşağıdaki statik EXE analiz raporunu incele ve güvenlik odaklı, detaylı, teknik bir özet üret. "
            "Genel risk değerlendirmeni sayısal bir puan ile ifade et. "
            "İlk satırda yalnızca şu formatta genel risk skorunu yaz: "
            "RISK_SCORE=<0-100>/100;RISK_LEVEL=<low|medium|high|critical> "
            "Sonrasında bir boş satır bırak ve Türkçe olarak detaylı açıklamayı yaz. "
            "Açıklamanın en sonunda mutlaka 'Manuel Kontrol ve Çözüm Önerileri' başlıklı ayrı bir bölüm ekle. "
            "Bu bölümde Windows ortamında olay müdahale ve teyit için kullanılabilecek net komut örnekleri ver. "
            "Örneğin kullanıcı hesaplarını listelemek, şüpheli servisleri ve başlangıç programlarını görmek, "
            "ağ bağlantılarını ve açık portları incelemek, zamanlanmış görevleri kontrol etmek ve kayıt defteri "
            "autostart alanlarını incelemek için çalıştırılabilecek komutları (cmd veya PowerShell) yaz. "
            "Ayrıca örnek kayıt defteri yolları, event log kayıtlarının hangi loglarda aranacağı ve "
            "şüpheli bulgular tespit edilirse önerilen adımları (kullanıcı hesabını devre dışı bırakma, "
            "servisi durdurma, dosyayı karantinaya alma vb.) madde madde belirt."
        )
    else:
        instruction = (
            "Review the following static EXE analysis report and produce a detailed, security-focused summary. "
            "Express your overall risk assessment as a numeric score. "
            "On the first line, write only this format: "
            "RISK_SCORE=<0-100>/100;RISK_LEVEL=<low|medium|high|critical> "
            "Then add a blank line and continue with an English detailed explanation. "
            "At the very end of your answer, append a separate section titled 'Manual Triage and Remediation Guidance'. "
            "In that section, provide concrete Windows commands (cmd or PowerShell) that an analyst can run to verify "
            "suspicious behavior: listing user accounts, inspecting services and startup items, checking active network "
            "connections and listening ports, reviewing scheduled tasks, and inspecting common autorun registry keys. "
            "Also mention example registry paths, which Windows Event Logs to review, and step-by-step recommendations "
            "for what to do if malicious indicators are confirmed (disable accounts, stop services, quarantine files, etc.)."
        )
    report_json = json.dumps(report, ensure_ascii=False, indent=2, default=str)
    prompt = instruction + "\n\n=== JSON REPORT ===\n" + report_json
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": prompt
                    }
                ]
            }
        ]
    }
    try:
        response = requests.post(url, params={"key": api_key}, json=payload, timeout=60)
    except Exception as exc:
        raise SSAError(f"Gemini API isteği başarısız: {exc}") from exc
    if response.status_code != 200:
        raise SSAError(f"Gemini API hatası: {response.status_code} {response.text}")
    data = response.json()
    try:
        candidates = data["candidates"]
        content = candidates[0]["content"]
        parts = content["parts"]
        text = parts[0]["text"]
    except Exception as exc:
        raise SSAError(f"Gemini API yanıtı beklenen formatta değil: {exc}") from exc
    return text
