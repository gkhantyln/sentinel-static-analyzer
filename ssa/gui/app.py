import sys
from pathlib import Path
from typing import Optional

from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication

from ssa.gui.main_window import MainWindow


def _apply_dark_palette(app: QApplication) -> None:
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#E9ECEF"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#111111"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#E9ECEF"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#E9ECEF"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#111111"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#E9ECEF"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#00FF41"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#000000"))
    app.setPalette(palette)
    app.setStyleSheet(
        "QMainWindow { background-color: #000000; }"
        "QLabel { color: #E9ECEF; }"
        "QPushButton { background-color: #111111; color: #E9ECEF; border: 1px solid #00FF41; padding: 6px 10px; }"
        "QPushButton:hover { background-color: #00FF41; color: #000000; }"
        "QPlainTextEdit { background-color: #000000; color: #00FF41; font-family: Consolas, monospace; }"
        "QComboBox { background-color: #111111; color: #E9ECEF; border: 1px solid #00FF41; padding: 4px; }"
        "QComboBox QAbstractItemView { background-color: #000000; color: #E9ECEF; }"
        "QMessageBox { background-color: #000000; }"
        "QMessageBox QLabel { color: #E9ECEF; }"
        "QMessageBox QPushButton { background-color: #111111; color: #E9ECEF; border: 1px solid #00FF41; padding: 4px 8px; }"
        "QMessageBox QPushButton:hover { background-color: #00FF41; color: #000000; }"
    )


def run_gui(target: Optional[Path] = None) -> None:
    app = QApplication(sys.argv)
    _apply_dark_palette(app)
    window = MainWindow()
    if target is not None:
        window.set_initial_target(target)
    window.show()
    sys.exit(app.exec())
