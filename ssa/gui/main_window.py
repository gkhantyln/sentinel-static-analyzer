from pathlib import Path
from typing import Any, Dict, Optional

import json
from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QPainter, QPixmap, QColor
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ssa.ai.gemini_client import generate_ai_report
from ssa.common.errors import SSAError
from ssa.common.logging import configure_logging
from ssa.core.engine import analyze
from ssa.core.report import AnalysisResult
from ssa.integrations.virustotal_client import scan_file_with_virustotal


STRINGS = {
    "tr": {
        "title": "Sentinel Static Analyzer",
        "initial_info": "Bir EXE dosyası seçin ve Analiz et'e basın",
        "btn_select": "Dosya Seç",
        "btn_scan": "Analiz et",
        "btn_export": "Raporu Dışa Aktar",
        "btn_ai": "Yapay Zeka Analizi",
        "btn_vt": "VirusTotal Analizi",
        "label_score_error": "Analiz sırasında hata oluştu",
        "msg_select_file_first": "Lütfen önce bir EXE dosyası seçin",
        "msg_run_analysis_first": "Önce bir analiz çalıştırın.",
        "msg_report_saved": "Rapor başarıyla kaydedildi.",
        "msg_report_save_error": "Rapor kaydedilirken hata oluştu.",
        "msg_ai_error_title": "Yapay Zeka Analizi",
        "msg_ai_error_body": "Yapay zeka analizi sırasında hata oluştu.",
        "msg_ai_header": "=== Yapay Zeka Destekli Analiz ===",
        "msg_ai_wait": "Yapay zeka analizi çalışıyor...",
        "msg_ai_done": "Yapay zeka analizi tamamlandı.",
        "lang_label": "Dil:",
        "ai_language_tr": "Türkçe",
        "ai_language_en": "İngilizce",
        "engine_score_title": "EXE Analiz Puanlaması",
        "ai_score_title": "Yapay Zeka Analiz Puanlaması",
        "ai_score_not_available": "Henüz çalıştırılmadı",
        "vt_status_initial": "VirusTotal analizi çalıştırılmadı.",
        "vt_status_running": "VirusTotal analizi çalışıyor...",
        "vt_status_done": "VirusTotal analizi tamamlandı.",
        "vt_status_error": "VirusTotal analizi sırasında hata oluştu.",
        "risk_low": "Düşük Risk",
        "risk_medium": "Orta Risk",
        "risk_high": "Yüksek Risk",
        "risk_critical": "Kritik Risk",
    },
    "en": {
        "title": "Sentinel Static Analyzer",
        "initial_info": "Select an EXE file and click Analyze",
        "btn_select": "Select File",
        "btn_scan": "Analyze",
        "btn_export": "Export Report",
        "btn_ai": "AI Analysis",
        "btn_vt": "VirusTotal Scan",
        "label_score_error": "An error occurred during analysis",
        "msg_select_file_first": "Please select an EXE file first.",
        "msg_run_analysis_first": "Run an analysis first.",
        "msg_report_saved": "Report saved successfully.",
        "msg_report_save_error": "Error occurred while saving report.",
        "msg_ai_error_title": "AI Analysis",
        "msg_ai_error_body": "An error occurred during AI analysis.",
        "msg_ai_header": "=== AI Assisted Analysis ===",
        "msg_ai_wait": "Running AI analysis...",
        "msg_ai_done": "AI analysis completed.",
        "lang_label": "Language:",
        "ai_language_tr": "Turkish",
        "ai_language_en": "English",
        "engine_score_title": "EXE Analysis Score",
        "ai_score_title": "AI Analysis Score",
        "ai_score_not_available": "Not run yet",
        "risk_low": "Low Risk",
        "risk_medium": "Medium Risk",
        "risk_high": "High Risk",
        "risk_critical": "Critical Risk",
        "vt_status_initial": "VirusTotal scan not run.",
        "vt_status_running": "VirusTotal scan in progress...",
        "vt_status_done": "VirusTotal scan completed.",
        "vt_status_error": "An error occurred during VirusTotal scan.",
    },
}


class _AiWorker(QObject):
    success = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, report: Dict[str, Any], language: str) -> None:
        super().__init__()
        self._report = report
        self._language = language

    def run(self) -> None:
        try:
            text = generate_ai_report(self._report, language=self._language)
        except SSAError as exc:
            self.error.emit(str(exc))
        else:
            self.success.emit(text)


class _VirusTotalWorker(QObject):
    success = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, result: AnalysisResult) -> None:
        super().__init__()
        self._result = result

    def run(self) -> None:
        try:
            vt_result = scan_file_with_virustotal(self._result.file_path, self._result.metadata.sha256)
        except SSAError as exc:
            self.error.emit(str(exc))
            return
        data = {
            "analysis_id": vt_result.analysis_id,
            "status": vt_result.status,
            "stats": {
                "harmless": vt_result.stats.harmless,
                "malicious": vt_result.stats.malicious,
                "suspicious": vt_result.stats.suspicious,
                "undetected": vt_result.stats.undetected,
                "timeout": vt_result.stats.timeout,
            },
            "permalink": vt_result.permalink,
        }
        self.success.emit(data)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.logger = configure_logging(name=__name__)
        self._lang = "tr"
        self._target: Optional[Path] = None
        self._last_result: Optional[AnalysisResult] = None
        self._ai_thread: Optional[QThread] = None
        self._vt_thread: Optional[QThread] = None
        self._engine_score_total: Optional[int] = None
        self._engine_score_level: Optional[str] = None
        self._ai_score_total: Optional[int] = None
        self._ai_score_level: Optional[str] = None
        self._build_ui()
        self._apply_language()
        self._apply_icon()

    def _build_ui(self) -> None:
        central = QWidget(self)
        layout = QVBoxLayout(central)
        lang_row = QHBoxLayout()
        self.lang_label = QLabel()
        self.lang_combo = QComboBox()
        self.lang_combo.addItem("Türkçe", "tr")
        self.lang_combo.addItem("English", "en")
        self.lang_combo.currentIndexChanged.connect(self.on_language_changed)
        lang_row.addWidget(self.lang_label)
        lang_row.addWidget(self.lang_combo)
        lang_row.addStretch()
        self.info_label = QLabel()
        self.info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        scores_row = QHBoxLayout()
        self.engine_score_title = QLabel()
        self.engine_score_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.engine_score_value = QLabel("")
        self.engine_score_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ai_score_title = QLabel()
        self.ai_score_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ai_score_value = QLabel("")
        self.ai_score_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        engine_box = QVBoxLayout()
        engine_box.addWidget(self.engine_score_title)
        engine_box.addWidget(self.engine_score_value)
        ai_box = QVBoxLayout()
        ai_box.addWidget(self.ai_score_title)
        ai_box.addWidget(self.ai_score_value)
        scores_row.addLayout(engine_box)
        scores_row.addLayout(ai_box)
        self.report_view = QPlainTextEdit()
        self.report_view.setReadOnly(True)
        self.report_view.setMinimumHeight(260)
        buttons_row = QHBoxLayout()
        self.select_button = QPushButton()
        self.scan_button = QPushButton()
        self.ai_button = QPushButton()
        self.vt_button = QPushButton()
        self.export_button = QPushButton()
        self.export_button.setEnabled(False)
        self.select_button.clicked.connect(self.on_select_file)
        self.scan_button.clicked.connect(self.on_scan)
        self.ai_button.clicked.connect(self.on_ai_analysis)
        self.vt_button.clicked.connect(self.on_virustotal_scan)
        self.export_button.clicked.connect(self.on_export_report)
        buttons_row.addWidget(self.select_button)
        buttons_row.addWidget(self.scan_button)
        buttons_row.addWidget(self.ai_button)
        buttons_row.addWidget(self.vt_button)
        buttons_row.addWidget(self.export_button)
        self.ai_status_label = QLabel("")
        self.ai_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ai_progress = QProgressBar()
        self.ai_progress.setTextVisible(False)
        self.ai_progress.setVisible(False)
        self.vt_status_label = QLabel("")
        self.vt_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addLayout(lang_row)
        layout.addWidget(self.info_label)
        layout.addLayout(scores_row)
        layout.addLayout(buttons_row)
        layout.addWidget(self.ai_status_label)
        layout.addWidget(self.ai_progress)
        layout.addWidget(self.vt_status_label)
        layout.addWidget(self.report_view)
        self.setCentralWidget(central)

    def _apply_language(self) -> None:
        s = STRINGS[self._lang]
        self.setWindowTitle(s["title"])
        if self._target is None:
            self.info_label.setText(s["initial_info"])
        self.lang_label.setText(s["lang_label"])
        self.select_button.setText(s["btn_select"])
        self.scan_button.setText(s["btn_scan"])
        self.ai_button.setText(s["btn_ai"])
        self.vt_button.setText(s["btn_vt"])
        self.export_button.setText(s["btn_export"])
        self.engine_score_title.setText(s["engine_score_title"])
        self.ai_score_title.setText(s["ai_score_title"])
        if self._engine_score_total is None:
            self.engine_score_value.setText("-/100")
        else:
            self.engine_score_value.setText(self._format_score_value(self._engine_score_total, self._engine_score_level))
        if self._ai_score_total is None:
            self.ai_score_value.setText(s["ai_score_not_available"])
        else:
            self.ai_score_value.setText(self._format_score_value(self._ai_score_total, self._ai_score_level))
        if not self.ai_status_label.text():
            self.ai_status_label.setText("")
        if not self.vt_status_label.text():
            self.vt_status_label.setText(s["vt_status_initial"])

    def _format_score_value(self, total: Optional[int], level: Optional[str]) -> str:
        if total is None:
            return "-/100"
        risk = self._format_risk_label(level)
        return f"{total}/100 - {risk}"

    def _format_risk_label(self, level: Optional[str]) -> str:
        if level is None:
            return ""
        s = STRINGS[self._lang]
        mapping = {
            "low": s["risk_low"],
            "medium": s["risk_medium"],
            "high": s["risk_high"],
            "critical": s["risk_critical"],
        }
        return mapping.get(level, level)

    def _apply_icon(self) -> None:
        pixmap = QPixmap(64, 64)
        pixmap.fill(QColor("#000000"))
        painter = QPainter(pixmap)
        painter.fillRect(8, 8, 48, 48, QColor("#00FF41"))
        painter.setPen(QColor("#000000"))
        font = QFont()
        font.setBold(True)
        font.setPointSize(16)
        painter.setFont(font)
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "SSA")
        painter.end()
        self.setWindowIcon(QIcon(pixmap))

    def set_initial_target(self, path: Path) -> None:
        self._target = path
        self.info_label.setText(str(path))

    def on_language_changed(self, index: int) -> None:
        code = self.lang_combo.itemData(index)
        if code in STRINGS:
            self._lang = code
            self._apply_language()

    def on_select_file(self) -> None:
        s = STRINGS[self._lang]
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            s["btn_select"],
            "",
            "Executable Files (*.exe);;All Files (*)",
        )
        if not file_path:
            return
        self._target = Path(file_path)
        self.info_label.setText(file_path)
        self._engine_score_total = None
        self._engine_score_level = None
        self._ai_score_total = None
        self._ai_score_level = None
        self._apply_language()
        self.report_view.clear()
        self._last_result = None
        self.export_button.setEnabled(False)

    def on_scan(self) -> None:
        s = STRINGS[self._lang]
        if self._target is None:
            self.info_label.setText(s["msg_select_file_first"])
            return
        try:
            result = analyze(self._target)
        except SSAError as exc:
            self.logger.error(str(exc))
            self._engine_score_total = None
            self._engine_score_level = None
            self._apply_language()
            self.report_view.setPlainText(str(exc))
            self._last_result = None
            self.export_button.setEnabled(False)
            return
        self._last_result = result
        score = result.score
        self._engine_score_total = score.total
        self._engine_score_level = score.level
        self._apply_language()
        self.vt_status_label.setText(s["vt_status_initial"])
        self.report_view.setPlainText(self._format_report_text(result))
        self.export_button.setEnabled(True)

    def on_ai_analysis(self) -> None:
        s = STRINGS[self._lang]
        if self._last_result is None:
            QMessageBox.information(self, s["msg_ai_error_title"], s["msg_run_analysis_first"])
            return
        report_dict = self._last_result.to_dict()
        self.ai_status_label.setText(s["msg_ai_wait"])
        self.ai_progress.setRange(0, 0)
        self.ai_progress.setVisible(True)
        self.ai_button.setEnabled(False)
        worker = _AiWorker(report_dict, self._lang)
        thread = QThread(self)
        self._ai_thread = thread
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.success.connect(self._on_ai_success)
        worker.error.connect(self._on_ai_error)
        worker.success.connect(lambda: self._cleanup_ai_thread(worker, thread))
        worker.error.connect(lambda: self._cleanup_ai_thread(worker, thread))
        thread.start()

    def _cleanup_ai_thread(self, worker: _AiWorker, thread: QThread) -> None:
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        if self._ai_thread is thread:
            self._ai_thread = None

    def _on_ai_success(self, ai_text: str) -> None:
        s = STRINGS[self._lang]
        score_total: Optional[int] = None
        score_level: Optional[str] = None
        lines_in = ai_text.splitlines()
        display_lines = []
        for idx, raw in enumerate(lines_in):
            line = raw.strip()
            if score_total is None and line.startswith("RISK_SCORE="):
                parts = line.split(";")
                for part in parts:
                    part = part.strip()
                    if part.startswith("RISK_SCORE="):
                        value = part[len("RISK_SCORE=") :].strip()
                        if "/" in value:
                            value = value.split("/", 1)[0]
                        try:
                            score_total = int(value)
                        except ValueError:
                            score_total = None
                    elif part.startswith("RISK_LEVEL="):
                        level_value = part[len("RISK_LEVEL=") :].strip().lower()
                        score_level = level_value
                continue
            display_lines.append(raw)
        self._ai_score_total = score_total
        self._ai_score_level = score_level
        current = self.report_view.toPlainText()
        added_text = "\n".join(display_lines).strip()
        lines = [current, "", s["msg_ai_header"], "", added_text]
        self.report_view.setPlainText("\n".join(lines))
        self._apply_language()
        self.ai_progress.setVisible(False)
        self.ai_button.setEnabled(True)
        self.ai_status_label.setText(s["msg_ai_done"])

    def _on_ai_error(self, message: str) -> None:
        s = STRINGS[self._lang]
        self.logger.error(message)
        QMessageBox.critical(self, s["msg_ai_error_title"], s["msg_ai_error_body"])
        self.ai_progress.setVisible(False)
        self.ai_button.setEnabled(True)
        self.ai_status_label.setText(s["msg_ai_error_body"])

    def on_virustotal_scan(self) -> None:
        s = STRINGS[self._lang]
        if self._last_result is None:
            QMessageBox.information(self, s["msg_ai_error_title"], s["msg_run_analysis_first"])
            return
        if self._vt_thread is not None:
            return
        self.vt_status_label.setText(s["vt_status_running"])
        worker = _VirusTotalWorker(self._last_result)
        thread = QThread(self)
        self._vt_thread = thread
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.success.connect(self._on_vt_success)
        worker.error.connect(self._on_vt_error)
        worker.success.connect(lambda: self._cleanup_vt_thread(worker, thread))
        worker.error.connect(lambda: self._cleanup_vt_thread(worker, thread))
        thread.start()

    def _cleanup_vt_thread(self, worker: _VirusTotalWorker, thread: QThread) -> None:
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        if self._vt_thread is thread:
            self._vt_thread = None

    def _on_vt_success(self, payload: Dict[str, Any]) -> None:
        s = STRINGS[self._lang]
        stats = payload.get("stats", {})
        harmless = int(stats.get("harmless", 0))
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        undetected = int(stats.get("undetected", 0))
        timeout = int(stats.get("timeout", 0))
        permalink = payload.get("permalink") or ""
        parts = [
            f"VirusTotal: malicious={malicious}",
            f"suspicious={suspicious}",
            f"harmless={harmless}",
            f"undetected={undetected}",
            f"timeout={timeout}",
        ]
        summary_text = " | ".join(parts)
        self.vt_status_label.setText(summary_text)
        self._append_text_to_report("")
        self._append_text_to_report("VirusTotal summary:")
        self._append_text_to_report(summary_text)
        if permalink:
            self._append_text_to_report(permalink)

    def _on_vt_error(self, message: str) -> None:
        s = STRINGS[self._lang]
        self.logger.error(message)
        self.vt_status_label.setText(s["vt_status_error"])
        QMessageBox.warning(self, "VirusTotal", message)

    def _append_text_to_report(self, text: str) -> None:
        current = self.report_view.toPlainText()
        if not text:
            new_value = current + "\n"
        else:
            if current.endswith("\n"):
                new_value = current + text + "\n"
            elif current:
                new_value = current + "\n" + text + "\n"
            else:
                new_value = text + "\n"
        self.report_view.setPlainText(new_value)

    def on_export_report(self) -> None:
        s = STRINGS[self._lang]
        if self._last_result is None:
            QMessageBox.information(self, s["btn_export"], s["msg_run_analysis_first"])
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            s["btn_export"],
            "",
            "JSON Files (*.json);;All Files (*)",
        )
        if not path:
            return
        try:
            data = self._last_result.to_dict()
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            self.logger.error(str(exc))
            QMessageBox.critical(self, s["btn_export"], s["msg_report_save_error"])
            return
        QMessageBox.information(self, s["btn_export"], s["msg_report_saved"])

    def _format_report_text(self, result: AnalysisResult) -> str:
        s = STRINGS[self._lang]
        lines = []
        lines.append(f"File: {result.file_path}")
        lines.append("")
        lines.append(f"Size: {result.metadata.size} bytes")
        lines.append(f"MD5: {result.metadata.md5}")
        lines.append(f"SHA256: {result.metadata.sha256}")
        lines.append(f"Machine: {result.metadata.machine}")
        lines.append(f"Overlay size: {result.metadata.overlay_size} bytes")
        lines.append("")
        lines.append(f"Risk score: {result.score.total} ({result.score.level})")
        lines.append(f"  Privilege escalation: {result.score.privilege_escalation}")
        lines.append(f"  Anti-debug/VM: {result.score.anti_debug_vm}")
        lines.append(f"  Overlay: {result.score.overlay}")
        lines.append(f"  Suspicious section count: {result.sections.suspicious_sections}")
        lines.append(f"  YARA matches: {len(result.yara_matches)}")
        lines.append(f"  String-based indicators: {result.score.strings}")
        lines.append("")
        lines.append("Important import categories:")
        lines.append(f"  Privilege APIs: {', '.join(result.imports.privilege_apis) or '-'}")
        lines.append(f"  Anti-debug APIs: {', '.join(result.imports.anti_debug_apis) or '-'}")
        lines.append(f"  Network APIs: {', '.join(result.imports.network_apis) or '-'}")
        lines.append(f"  File APIs: {', '.join(result.imports.file_apis) or '-'}")
        lines.append(f"  Registry APIs: {', '.join(result.imports.registry_apis) or '-'}")
        lines.append("")
        lines.append("String analysis:")
        lines.append(f"  Extracted strings: {result.strings.total_strings}")
        lines.append(f"  URL indicators: {len(result.strings.urls)}")
        lines.append(f"  IP indicators: {len(result.strings.ips)}")
        lines.append(f"  Registry indicators: {len(result.strings.registry_paths)}")
        lines.append(f"  Command indicators: {len(result.strings.suspicious_commands)}")
        if result.strings.urls:
            lines.append("  Example URLs:")
            for value in result.strings.urls[:5]:
                lines.append(f"    - {value}")
        if result.strings.registry_paths:
            lines.append("  Example registry strings:")
            for value in result.strings.registry_paths[:5]:
                lines.append(f"    - {value}")
        if result.strings.suspicious_commands:
            lines.append("  Example command strings:")
            for value in result.strings.suspicious_commands[:5]:
                lines.append(f"    - {value}")
        lines.append("")
        if result.yara_matches:
            lines.append("YARA matches:")
            for m in result.yara_matches:
                lines.append(f"  - {m.rule} [{m.namespace}] tags={','.join(m.tags)}")
        return "\n".join(lines)
