#!/usr/bin/env python3
"""
Laravel Auditor – Secure Laravel Application Scanner
Author: T4Z4R
Version: 1.0
"""

import sys
import json
import re
import os
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import requests
from bs4 import BeautifulSoup
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QTableWidget, QTableWidgetItem,
    QTabWidget, QFileDialog, QMessageBox, QProgressBar, QHeaderView,
    QToolBar, QStatusBar, QComboBox, QGraphicsOpacityEffect, QDialog, QTextEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl, QEasingCurve, QTimer, QPropertyAnimation
from PyQt6.QtGui import QIcon, QFont, QDesktopServices, QPalette, QColor
import qtawesome as qta
from jinja2 import Template

# ======================================================================
# AUTHOR INFORMATION
# ======================================================================
__author__ = "T4Z4R"
__version__ = "1.0"
__description__ = "Secure Laravel Application Auditor"

# ======================================================================
# SCANNER THREAD
# ======================================================================
class ScannerThread(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, scanner_type: str, target: str):
        super().__init__()
        self.scanner_type = scanner_type
        self.target = target

    def run(self):
        try:
            if self.scanner_type == "web":
                report = WebScanner(self.target).scan()
            else:
                report = FileScanner(self.target).scan()
            self.finished.emit(report)
        except Exception as e:
            self.error.emit(str(e))

# ======================================================================
# WEB SCANNER
# ======================================================================
class WebScanner:
    def __init__(self, url: str, timeout: int = 12):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.timeout = timeout
        self.session.verify = False
        self.session.headers["User-Agent"] = f"LaravelAuditor/{__version__} (by {__author__})"

    def _get(self, path: str) -> requests.Response:
        try:
            return self.session.get(self.url + "/" + path.lstrip("/"), allow_redirects=True)
        except:
            return type("obj", (), {"ok": False, "text": "", "status_code": 0, "headers": {}, "cookies": []})

    def scan(self) -> Dict:
        r = {"Target": self.url, "Type": "Web", "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        resp = self._get("")
        cookies = resp.cookies
        headers = resp.headers
        r["Laravel"] = any(c.name == "laravel_session" for c in cookies) or \
                       any("laravel" in v.lower() for v in headers.values())

        if not r["Laravel"]:
            r["Note"] = "No Laravel detected"
            r["Issues"] = []
            r["Suggestions"] = []
            return r

        r["Laravel version"] = self._version()
        r["PHP version"] = self._php()
        r[".env exposure"] = self._env()
        r["Risk"] = self._risk(r)
        r["Issues"] = []
        r["Suggestions"] = []

        # Collect issues and suggestions
        if "EXPOSED" in r.get(".env exposure", ""):
            r["Issues"].append(".env file is exposed, potentially leaking sensitive information.")
            r["Suggestions"].append("Move .env file outside the web root directory and ensure proper access restrictions.")
        if r.get("Laravel version") != "Hidden":
            r["Issues"].append("Laravel version is disclosed, which could aid attackers.")
            r["Suggestions"].append("Disable version disclosure in production by removing or securing debug endpoints.")
        if r.get("PHP version") != "Hidden":
            r["Issues"].append("PHP version is disclosed.")
            r["Suggestions"].append("Configure server to hide PHP version in headers.")
        if r["Risk"] >= 50:
            r["Issues"].append("High risk score indicates multiple vulnerabilities.")
            r["Suggestions"].append("Review and address all identified issues immediately.")

        return r

    def _version(self):
        for p in ["", "/composer.json", "/debug"]:
            resp = self._get(p)
            if not resp.ok: continue
            if "laravel/framework" in resp.text:
                m = re.search(r'"laravel/framework":\s*"([^"]+)"', resp.text)
                if m: return m.group(1)
            if "Laravel" in resp.text:
                m = re.search(r"Laravel v?([\d\.]+)", resp.text)
                if m: return m.group(1)
        return "Hidden"

    def _php(self):
        resp = self._get("")
        hdr = resp.headers.get("X-Powered-By", "")
        if "PHP" in hdr: return hdr.split("/")[1] if "/" in hdr else hdr
        return "Hidden"

    def _env(self):
        for p in ["/.env", "/config/.env"]:
            resp = self._get(p)
            if resp.ok and ("DB_PASSWORD" in resp.text or "APP_KEY" in resp.text):
                return f"{p} EXPOSED"
            if resp.ok and resp.headers.get("Content-Type", "").startswith("text"):
                return f"{p} 200 OK"
        return "Secure"

    def _risk(self, r):
        score = 0
        if "EXPOSED" in r.get(".env exposure", ""): score += 50
        if r.get("Laravel version") != "Hidden": score += 15
        return min(score, 100)

# ======================================================================
# LOCAL FILE SCANNER
# ======================================================================
class FileScanner:
    def __init__(self, path: str):
        self.root = Path(path)

    def scan(self):
        r = {
            "Target": str(self.root),
            "Type": "Local",
            "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        if not (self.root / "artisan").exists() and not (self.root / "composer.json").exists():
            r["Note"] = "Not Laravel"
            r["Issues"] = []
            r["Suggestions"] = []
            return r

        r["Laravel"] = True
        r["Laravel version"] = self._laravel_version()
        r["PHP version"] = os.popen("php -v 2>/dev/null | head -n1").read().strip() or "Unknown"
        r[".env exposure"] = self._env_check()
        r["Risk"] = self._risk(r)
        r["Issues"] = []
        r["Suggestions"] = []

        # Collect issues and suggestions
        if "WORLD-READABLE" in r.get(".env exposure", ""):
            r["Issues"].append(".env file is world-readable, exposing sensitive data.")
            r["Suggestions"].append("Change file permissions to restrict access (e.g., chmod 600 .env).")
        if r.get("Laravel version") == "unknown":
            r["Issues"].append("Laravel version could not be determined.")
            r["Suggestions"].append("Ensure composer.json is present and up-to-date.")
        if r["Risk"] >= 50:
            r["Issues"].append("High risk score indicates potential security issues.")
            r["Suggestions"].append("Review file permissions, update dependencies, and follow Laravel security best practices.")

        return r

    def _laravel_version(self):
        c = self.root / "composer.json"
        if c.exists():
            try:
                data = json.loads(c.read_text())
                return data["require"].get("laravel/framework", "unknown")
            except: pass
        return "unknown"

    def _env_check(self):
        e = self.root / ".env"
        if not e.exists(): return "Not found"
        mode = e.stat().st_mode
        if mode & 0o004: return "WORLD-READABLE"
        return "Secure"

    def _risk(self, r):
        score = 0
        if "WORLD-READABLE" in r.get(".env exposure", ""): score += 60
        return min(score, 100)

# ======================================================================
# ANIMATED TAB WIDGET
# ======================================================================
class AnimatedTabWidget(QTabWidget):
    def __init__(self):
        super().__init__()
        self.opacity_effects = {}
        self.currentChanged.connect(self.animate_tab)

    def animate_tab(self, index):
        widget = self.widget(index)
        if not widget: return
        effect = QGraphicsOpacityEffect()
        widget.setGraphicsEffect(effect)
        self.opacity_effects[widget] = effect
        anim = QPropertyAnimation(effect, b"opacity")
        anim.setDuration(300)
        anim.setStartValue(0.3)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.start()

# ======================================================================
# MAIN WINDOW
# ======================================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"🔒 Laravel Auditor v{__version__} – by {__author__}")
        self.setGeometry(100, 100, 1300, 750)
        self.reports: List[Dict] = []
        self.dark_mode = True
        self.init_ui()
        self.apply_theme()

    def init_ui(self):
        toolbar = QToolBar()
        self.addToolBar(toolbar)

        self.theme_btn = QPushButton("🌙 Dark" if self.dark_mode else "☀️ Light")
        self.theme_btn.setText("🌙 Dark" if self.dark_mode else "☀️ Light")
        self.theme_btn.setIcon(qta.icon("fa5s.moon" if self.dark_mode else "fa5s.sun"))
        self.theme_btn.setToolTip("Toggle Dark/Light Mode")
        self.theme_btn.clicked.connect(self.toggle_theme)
        toolbar.addWidget(self.theme_btn)

        toolbar.addSeparator()

        export_menu = QComboBox()
        export_menu.addItems(["Export as...", "JSON", "HTML", "CSV"])
        export_menu.currentIndexChanged.connect(self.export_selected)
        toolbar.addWidget(export_menu)

        self.tabs = AnimatedTabWidget()
        self.setCentralWidget(self.tabs)

        web_tab = self.create_web_tab()
        self.tabs.addTab(web_tab, qta.icon("fa5s.globe"), "Web Scanner")

        local_tab = self.create_local_tab()
        self.tabs.addTab(local_tab, qta.icon("fa5s.folder-open"), "Local Scanner")

        results_tab = self.create_results_tab()
        self.tabs.addTab(results_tab, qta.icon("fa5s.chart-bar"), "Results")

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage(f"Laravel Auditor v{__version__} – Ready")

    def create_web_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        url_layout = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://your-laravel-app.com")
        self.url_glow = QGraphicsOpacityEffect(self.url_input)
        self.url_input.setGraphicsEffect(self.url_glow)

        scan_btn = QPushButton("Scan")
        scan_btn.setIcon(qta.icon("fa5s.search"))
        scan_btn.clicked.connect(self.start_web_scan)
        url_layout.addWidget(QLabel("URL:"))
        url_layout.addWidget(self.url_input, 1)
        url_layout.addWidget(scan_btn)
        layout.addLayout(url_layout)

        self.web_progress = QProgressBar()
        self.web_progress.setRange(0, 0)
        self.web_progress.setVisible(False)
        layout.addWidget(self.web_progress)

        tab.setLayout(layout)
        return tab

    def create_local_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        folder_layout = QHBoxLayout()
        self.folder_path = QLineEdit()
        self.folder_path.setPlaceholderText("Select Laravel project folder")
        browse_btn = QPushButton("Browse")
        browse_btn.setIcon(qta.icon("fa5s.folder"))
        browse_btn.clicked.connect(self.browse_folder)
        scan_local_btn = QPushButton("Scan")
        scan_local_btn.setIcon(qta.icon("fa5s.hdd"))
        scan_local_btn.clicked.connect(self.start_local_scan)
        folder_layout.addWidget(QLabel("Folder:"))
        folder_layout.addWidget(self.folder_path, 1)
        folder_layout.addWidget(browse_btn)
        folder_layout.addWidget(scan_local_btn)
        layout.addLayout(folder_layout)

        self.local_progress = QProgressBar()
        self.local_progress.setRange(0, 0)
        self.local_progress.setVisible(False)
        layout.addWidget(self.local_progress)

        tab.setLayout(layout)
        return tab

    def create_results_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Time", "Type", "Target", "Laravel", "Version", ".env", "Risk"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.itemDoubleClicked.connect(self.open_url)
        layout.addWidget(self.table)

        details_btn = QPushButton("View Details")
        details_btn.setIcon(qta.icon("fa5s.info-circle"))
        details_btn.clicked.connect(self.show_details)
        layout.addWidget(details_btn)

        tab.setLayout(layout)
        return tab

    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Laravel Project")
        if folder:
            self.folder_path.setText(folder)

    def start_web_scan(self):
        url = self.url_input.text().strip()
        if not url: return
        if not url.startswith("http"):
            url = "https://" + url

        glow = QPropertyAnimation(self.url_glow, b"opacity")
        glow.setDuration(800)
        glow.setKeyValues([(0, 0.5), (0.5, 1.0), (1.0, 0.5)])
        glow.setLoopCount(3)
        glow.start()

        self.web_progress.setVisible(True)
        self.status.showMessage("Scanning web target...")
        self.thread = ScannerThread("web", url)
        self.thread.finished.connect(self.on_scan_done)
        self.thread.error.connect(self.on_scan_error)
        self.thread.start()

    def start_local_scan(self):
        path = self.folder_path.text().strip()
        if not path or not os.path.isdir(path):
            QMessageBox.warning(self, "Invalid", "Select a valid folder")
            return
        self.local_progress.setVisible(True)
        self.status.showMessage("Scanning local project...")
        self.thread = ScannerThread("local", path)
        self.thread.finished.connect(self.on_scan_done)
        self.thread.error.connect(self.on_scan_error)
        self.thread.start()

    def on_scan_done(self, report: Dict):
        self.web_progress.setVisible(False)
        self.local_progress.setVisible(False)
        self.reports.insert(0, report)
        self.update_table_with_animation()
        risk = report.get("Risk", 0)
        self.status.showMessage(f"Scan complete! Risk: {risk}/100", 5000)
        if risk >= 50:
            self.pulse_status()

    def on_scan_error(self, msg: str):
        self.web_progress.setVisible(False)
        self.local_progress.setVisible(False)
        QMessageBox.critical(self, "Error", msg)
        self.status.showMessage("Scan failed")

    def update_table_with_animation(self):
        self.table.insertRow(0)
        r = self.reports[0]
        risk = r.get("Risk", 0)

        self.table.setItem(0, 0, QTableWidgetItem(r["Time"]))
        self.table.setItem(0, 1, QTableWidgetItem(r["Type"]))
        target_item = QTableWidgetItem(r["Target"])
        if r["Type"] == "Web":
            target_item.setData(Qt.ItemDataRole.UserRole, r["Target"])
            target_item.setForeground(QColor("#1e90ff"))
        self.table.setItem(0, 2, target_item)
        self.table.setItem(0, 3, QTableWidgetItem("Yes" if r.get("Laravel") else "No"))
        self.table.setItem(0, 4, QTableWidgetItem(r.get("Laravel version", "N/A")))
        env_item = QTableWidgetItem(r.get(".env exposure", "N/A"))
        if "EXPOSED" in env_item.text() or "READABLE" in env_item.text():
            env_item.setForeground(QColor("#ff4444"))
        self.table.setItem(0, 5, env_item)
        risk_item = QTableWidgetItem(str(risk))
        risk_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        if risk >= 50:
            risk_item.setBackground(QColor("#ff4444"))
            risk_item.setForeground(QColor("white"))
            self.pulse_risk_item(risk_item)
        elif risk >= 30:
            risk_item.setBackground(QColor("#ff8800"))
        self.table.setItem(0, 6, risk_item)

    def pulse_risk_item(self, item):
        # Animation removed as QTableWidgetItem does not support graphics effects
        pass

    def pulse_status(self):
        anim = QPropertyAnimation(self.status, b"windowOpacity")
        anim.setDuration(1000)
        anim.setKeyValues([(0, 1.0), (0.5, 0.7), (1.0, 1.0)])
        anim.start()

    def open_url(self, item):
        if item.column() == 2 and self.reports:
            url = item.data(Qt.ItemDataRole.UserRole)
            if url:
                QDesktopServices.openUrl(QUrl(url))

    def show_details(self):
        selected = self.table.currentRow()
        if selected < 0 or selected >= len(self.reports):
            QMessageBox.information(self, "No Selection", "Please select a report row to view details.")
            return
        report = self.reports[selected]

        dialog = QDialog(self)
        dialog.setWindowTitle(f"🔍 Details for {report['Target']}")
        dialog.setGeometry(200, 200, 700, 500)
        dialog.setModal(True)

        layout = QVBoxLayout()

        # Header with icon
        header_layout = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(qta.icon("fa5s.shield-alt", color="#007bff").pixmap(32, 32))
        header_layout.addWidget(icon_label)
        header_layout.addWidget(QLabel(f"<h2>Scan Details</h2>"))
        header_layout.addStretch()
        layout.addLayout(header_layout)

        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Consolas", 10))

        details = f"<b>Target:</b> {report['Target']}<br>"
        details += f"<b>Type:</b> {report['Type']}<br>"
        details += f"<b>Time:</b> {report['Time']}<br>"
        details += f"<b>Laravel Detected:</b> {'✅ Yes' if report.get('Laravel') else '❌ No'}<br>"
        if report.get('Laravel version'):
            details += f"<b>Laravel Version:</b> {report['Laravel version']}<br>"
        if report.get('PHP version'):
            details += f"<b>PHP Version:</b> {report['PHP version']}<br>"
        if report.get('.env exposure'):
            details += f"<b>.env Exposure:</b> {report['.env exposure']}<br>"
        risk = report.get('Risk', 0)
        risk_color = "#28a745" if risk < 30 else "#ffc107" if risk < 50 else "#dc3545"
        details += f"<b>Risk Score:</b> <span style='color: {risk_color}; font-weight: bold;'>{risk}/100</span><br><br>"

        if report.get('Issues'):
            details += "<h3 style='color: #dc3545;'>⚠️ Issues:</h3><ul>"
            for issue in report['Issues']:
                details += f"<li>{issue}</li>"
            details += "</ul><br>"

        if report.get('Suggestions'):
            details += "<h3 style='color: #28a745;'>💡 Suggestions:</h3><ul>"
            for suggestion in report['Suggestions']:
                details += f"<li>{suggestion}</li>"
            details += "</ul>"

        text_edit.setHtml(details)
        layout.addWidget(text_edit)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        export_btn = QPushButton("📄 Export Details")
        export_btn.clicked.connect(lambda: self.export_details(report))
        button_layout.addWidget(export_btn)

        close_btn = QPushButton("❌ Close")
        close_btn.setDefault(True)
        close_btn.clicked.connect(dialog.accept)
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout)

        dialog.setLayout(layout)
        dialog.exec()

    def export_selected(self, idx):
        if idx <= 0 or not self.reports: return
        format = ["", "json", "html", "csv"][idx]
        path, _ = QFileDialog.getSaveFileName(self, f"Export as {format.upper()}", "", f"{format.upper()} (*.{format})")
        if not path: return
        getattr(self, f"export_{format}")(path)
        self.animate_export_success()

    def animate_export_success(self):
        check = QLabel("Export successful!")
        check.setStyleSheet("color: #4CAF50; font-weight: bold;")
        check.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status.addWidget(check)
        QTimer.singleShot(3000, check.deleteLater)

    def export_json(self, path):
        with open(path, "w") as f:
            json.dump(self.reports, f, indent=2)

    def export_html(self, path):
        template = """
        <!DOCTYPE html><html><head><style>
        body {font-family: system-ui; margin: 2rem;}
        table {width:100%; border-collapse:collapse;}
        th, td {padding: 10px; border: 1px solid #ddd; text-align: left;}
        .critical {background: #ffebee;} .high {background: #fff3e0;}
        </style></head><body>
        <h1>Laravel Auditor Report – by T4Z4R</h1>
        <p>Generated on {{ now }}</p>
        <table><tr><th>Time</th><th>Type</th><th>Target</th><th>Risk</th></tr>
        {% for r in reports %}
        <tr class="{% if r.Risk >= 50 %}critical{% elif r.Risk >= 30 %}high{% endif %}">
            <td>{{ r.Time }}</td><td>{{ r.Type }}</td><td>{{ r.Target }}</td><td>{{ r.Risk }}</td>
        </tr>{% endfor %}</table></body></html>
        """
        html = Template(template).render(reports=self.reports, now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        Path(path).write_text(html)

    def export_csv(self, path):
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["Time","Type","Target","Laravel version",".env exposure","Risk"])
            writer.writeheader()
            for r in self.reports:
                writer.writerow({
                    "Time": r["Time"],
                    "Type": r["Type"],
                    "Target": r["Target"],
                    "Laravel version": r.get("Laravel version", ""),
                    ".env exposure": r.get(".env exposure", ""),
                    "Risk": r.get("Risk", 0)
                })

    def export_details(self, report):
        path, _ = QFileDialog.getSaveFileName(self, "Export Details", "", "Text Files (*.txt);;All Files (*)")
        if not path: return
        with open(path, "w") as f:
            f.write(f"Scan Details for {report['Target']}\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Target: {report['Target']}\n")
            f.write(f"Type: {report['Type']}\n")
            f.write(f"Time: {report['Time']}\n")
            f.write(f"Laravel Detected: {'Yes' if report.get('Laravel') else 'No'}\n")
            if report.get('Laravel version'):
                f.write(f"Laravel Version: {report['Laravel version']}\n")
            if report.get('PHP version'):
                f.write(f"PHP Version: {report['PHP version']}\n")
            if report.get('.env exposure'):
                f.write(f".env Exposure: {report['.env exposure']}\n")
            f.write(f"Risk Score: {report.get('Risk', 0)}/100\n\n")

            if report.get('Issues'):
                f.write("Issues:\n")
                for issue in report['Issues']:
                    f.write(f"- {issue}\n")
                f.write("\n")

            if report.get('Suggestions'):
                f.write("Suggestions:\n")
                for suggestion in report['Suggestions']:
                    f.write(f"- {suggestion}\n")

        QMessageBox.information(self, "Export Successful", f"Details exported to {path}")

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.apply_theme()
        self.theme_btn.setIcon(qta.icon("fa5s.moon" if self.dark_mode else "fa5s.sun"))

    def apply_theme(self):
        app = QApplication.instance()
        if self.dark_mode:
            palette = QPalette()
            palette.setColor(QPalette.ColorRole.Window, QColor(25, 25, 35))
            palette.setColor(QPalette.ColorRole.WindowText, QColor(220, 220, 220))
            palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 45))
            palette.setColor(QPalette.ColorRole.Text, QColor(220, 220, 220))
            palette.setColor(QPalette.ColorRole.Button, QColor(45, 45, 55))
            palette.setColor(QPalette.ColorRole.ButtonText, QColor(220, 220, 220))
            palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 123, 255))
            palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
            app.setPalette(palette)
            app.setFont(QFont("Segoe UI", 10))
            app.setStyleSheet("""
                QToolTip { color: white; background: #333; border: 1px solid #555; border-radius: 4px; padding: 4px; }
                QPushButton { border-radius: 6px; padding: 8px 16px; font-weight: 500; }
                QPushButton:hover { background-color: #4a4a5a; }
                QPushButton:pressed { background-color: #3a3a4a; }
                QLineEdit { border-radius: 4px; padding: 6px; border: 1px solid #555; }
                QLineEdit:focus { border-color: #007bff; }
                QTableWidget { gridline-color: #444; border-radius: 6px; }
                QTableWidget::item { padding: 8px; }
                QTableWidget::item:selected { background-color: #007bff; }
                QTabWidget::pane { border: 1px solid #444; border-radius: 6px; }
                QTabBar::tab { padding: 10px 20px; margin-right: 2px; border-radius: 6px 6px 0 0; }
                QTabBar::tab:selected { background-color: #007bff; color: white; }
                QProgressBar { border-radius: 4px; text-align: center; }
                QProgressBar::chunk { background-color: #007bff; border-radius: 4px; }
            """)
        else:
            app.setPalette(app.style().standardPalette())
            app.setFont(QFont("Segoe UI", 10))
            app.setStyleSheet("""
                QPushButton { border-radius: 6px; padding: 8px 16px; font-weight: 500; }
                QPushButton:hover { background-color: #e9ecef; }
                QPushButton:pressed { background-color: #dee2e6; }
                QLineEdit { border-radius: 4px; padding: 6px; border: 1px solid #ced4da; }
                QLineEdit:focus { border-color: #007bff; box-shadow: 0 0 0 0.2rem rgba(0, 123, 255, 0.25); }
                QTableWidget { border-radius: 6px; }
                QTableWidget::item { padding: 8px; }
                QTableWidget::item:selected { background-color: #007bff; color: white; }
                QTabWidget::pane { border: 1px solid #dee2e6; border-radius: 6px; }
                QTabBar::tab { padding: 10px 20px; margin-right: 2px; border-radius: 6px 6px 0 0; }
                QTabBar::tab:selected { background-color: #007bff; color: white; }
                QProgressBar { border-radius: 4px; text-align: center; }
                QProgressBar::chunk { background-color: #007bff; border-radius: 4px; }
            """)

# ======================================================================
# MAIN ENTRY
# ======================================================================
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Laravel Auditor")
    app.setWindowIcon(qta.icon("fa5s.shield-alt"))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()