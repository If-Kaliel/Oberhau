from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Callable
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Event
from typing import Any

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QAction, QFontDatabase, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from oberhau import __version__
from oberhau.backup import create_backup, restore_backup
from oberhau.core import Cancelled, OberhauError, Status, data_home, now
from oberhau.desktop.i18n import translate
from oberhau.desktop.theme import THEME
from oberhau.diagnostics import collect
from oberhau.engine import ASSETS, PROFILES, Engine
from oberhau.laboratory import validate_sql
from oberhau.reporting import export, generate
from oberhau.scheduler import add_schedule, take_due
from oberhau.scope import Policy
from oberhau.security import confined, local_ollama_url, redact
from oberhau.tooling import ECOSYSTEMS, PINNED, install_tool, refresh_osv_cache, refresh_trivy_cache

PAGES = [
    "Overview",
    "Projects",
    "Programs",
    "Scanner",
    "Investigations",
    "Laboratory",
    "Intelligence",
    "Reports",
    "Automation",
    "Analytics",
    "Settings",
]


def configure_fonts() -> None:
    # Qt's Windows offscreen plugin has no font database until a font is registered.
    if not QFontDatabase.families():
        font = Path(os.environ.get("SystemRoot", "C:/Windows")) / "Fonts/segoeui.ttf"
        if font.is_file():
            QFontDatabase.addApplicationFont(str(font))


class Worker(QThread):
    progress = Signal(str)
    result = Signal(object)
    failed = Signal(str)

    def __init__(self, operation: Callable, parent=None):
        super().__init__(parent)
        self.operation = operation
        self.cancel = Event()

    def run(self) -> None:
        try:
            self.result.emit(self.operation(self.cancel, self.progress.emit))
        except Cancelled:
            self.failed.emit("Cancelled")
        except Exception as error:
            logging.getLogger("oberhau").error("Worker failed: %s", redact(str(error)))
            self.failed.emit(redact(f"{type(error).__name__}: {error}"))


class Window(QMainWindow):
    def __init__(self, engine: Engine, first_run: bool = True):
        super().__init__()
        self.engine, self.db = engine, engine.db
        self.language = self.db.setting("language", "pt-BR")
        self.worker: Worker | None = None
        self.completion: Callable | None = None
        self.diagnostic_data: dict = {}
        self.diagnostics_attempted = False
        self.report_id: int | None = None
        self.setWindowTitle("OBERHAU · Security Research Workbench")
        self.setWindowIcon(QIcon(str(ASSETS / "emblem.svg")))
        self.resize(1380, 880)
        self.setMinimumSize(1000, 680)
        self.build()
        self.refresh()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(15000)
        if first_run and not self.db.setting("setup_complete", False):
            QTimer.singleShot(100, self.setup)
        else:
            QTimer.singleShot(150, self.diagnostics)

    def tr_label(self, text: str) -> str:
        return translate(text, self.language)

    def button(self, text: str, operation: Callable, primary: bool = False) -> QPushButton:
        widget = QPushButton(self.tr_label(text))
        widget.clicked.connect(lambda: self.guard(operation))
        if primary:
            widget.setObjectName("primary")
        return widget

    def guard(self, operation: Callable) -> None:
        try:
            operation()
        except Exception as error:
            message = redact(f"{type(error).__name__}: {error}")
            self.log_message(message)
            QMessageBox.warning(self, self.tr_label("Error"), message)

    def build(self) -> None:
        container = QWidget()
        self.setCentralWidget(container)
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        sidebar = QWidget()
        sidebar.setFixedWidth(218)
        self.sidebar = sidebar
        side = QVBoxLayout(sidebar)
        icon = QLabel()
        icon.setPixmap(QIcon(str(ASSETS / "emblem.svg")).pixmap(48, 48))
        side.addWidget(icon)
        brand = QLabel("OBERHAU")
        brand.setObjectName("brand")
        side.addWidget(brand)
        subtitle = QLabel("SECURITY RESEARCH WORKBENCH")
        subtitle.setObjectName("subtitle")
        side.addWidget(subtitle)
        self.navigation = QListWidget()
        self.navigation.setObjectName("navigation")
        self.navigation.addItems([self.tr_label(page) for page in PAGES])
        side.addWidget(self.navigation, 1)
        side.addWidget(QLabel(f"v{__version__} · LOCAL / OFFLINE"))
        layout.addWidget(sidebar)
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(26, 20, 26, 12)
        header = QHBoxLayout()
        self.title = QLabel()
        self.title.setObjectName("pageTitle")
        header.addWidget(self.title)
        header.addStretch()
        header.addWidget(QLabel("● " + self.tr_label("Offline research")))
        header.addWidget(self.button("Collapse sidebar", self.collapse))
        body_layout.addLayout(header)
        self.demo_banner = QLabel("DEMONSTRATION / LABORATORY data included in these records")
        self.demo_banner.setObjectName("muted")
        self.demo_banner.setVisible(False)
        body_layout.addWidget(self.demo_banner)
        self.stack = QStackedWidget()
        self.pages: dict[str, QVBoxLayout] = {}
        for name in PAGES:
            page = QWidget()
            self.pages[name] = QVBoxLayout(page)
            self.pages[name].setContentsMargins(0, 16, 0, 0)
            self.stack.addWidget(page)
        self.splitter = QSplitter(Qt.Orientation.Vertical)
        self.splitter.addWidget(self.stack)
        activity = QWidget()
        activity_layout = QVBoxLayout(activity)
        self.job_label = QLabel(self.tr_label("Idle"))
        job_bar = QHBoxLayout()
        job_bar.addWidget(self.job_label, 1)
        job_bar.addWidget(self.button("Stop", self.stop))
        activity_layout.addLayout(job_bar)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        activity_layout.addWidget(self.progress)
        self.activity = QPlainTextEdit()
        self.activity.setReadOnly(True)
        self.activity.setMaximumBlockCount(1500)
        activity_layout.addWidget(self.activity)
        self.splitter.addWidget(activity)
        self.splitter.setSizes([600, 140])
        body_layout.addWidget(self.splitter)
        layout.addWidget(body, 1)
        self.make_overview()
        self.make_projects()
        self.make_programs()
        self.make_scanner()
        self.make_investigations()
        self.make_laboratory()
        self.make_intelligence()
        self.make_reports()
        self.make_automation()
        self.make_analytics()
        self.make_settings()
        self.navigation.currentRowChanged.connect(self.navigate)
        self.navigation.setCurrentRow(0)
        for key, callback in [
            ("Ctrl+R", self.refresh),
            ("Ctrl+O", self.import_folder),
            ("Ctrl+F", self.focus_search),
            ("Escape", self.stop),
        ]:
            action = QAction(self)
            action.setShortcut(QKeySequence(key))
            action.triggered.connect(lambda checked=False, cb=callback: self.guard(cb))
            self.addAction(action)

    def navigate(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        self.title.setText(self.tr_label(PAGES[index]))

    def collapse(self) -> None:
        self.sidebar.setVisible(not self.sidebar.isVisible())

    def focus_search(self) -> None:
        widgets = self.stack.currentWidget().findChildren(QLineEdit)
        if widgets:
            widgets[0].setFocus()

    def note(self, page: str, text: str) -> None:
        label = QLabel(text)
        label.setObjectName("muted")
        label.setWordWrap(True)
        self.pages[page].addWidget(label)

    def table(self, page: str, headers: list[str]) -> QTableWidget:
        search = QLineEdit()
        search.setPlaceholderText(self.tr_label("Search…"))
        self.pages[page].addWidget(search)
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().hide()
        table.setSortingEnabled(True)
        search.textChanged.connect(lambda value: self.filter_table(table, value))
        table.setProperty("search", search)
        self.pages[page].addWidget(table, 1)
        return table

    @staticmethod
    def filter_table(table: QTableWidget, query: str) -> None:
        for row in range(table.rowCount()):
            table.setRowHidden(
                row,
                query.casefold()
                not in " ".join(
                    table.item(row, col).text()
                    for col in range(table.columnCount())
                    if table.item(row, col)
                ).casefold(),
            )

    @staticmethod
    def fill(table: QTableWidget, rows: list[list[Any]]) -> None:
        selected = table.item(table.currentRow(), 0)
        selected_id = selected.text() if selected else None
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value if value is not None else "—"))
                table.setItem(row, col, item)
                if col == 0 and item.text() == selected_id:
                    table.selectRow(row)
        table.resizeColumnsToContents()
        table.setSortingEnabled(True)
        search = table.property("search")
        if search:
            Window.filter_table(table, search.text())

    @staticmethod
    def selected(table: QTableWidget) -> int:
        item = table.item(table.currentRow(), 0)
        if not item:
            raise OberhauError("Select a row first")
        return int(item.text())

    def bar(self, page: str, buttons: list[tuple[str, Callable]]) -> None:
        row = QHBoxLayout()
        for text, operation in buttons:
            row.addWidget(self.button(text, operation))
        row.addStretch()
        self.pages[page].addLayout(row)

    def make_overview(self) -> None:
        self.note(
            "Overview",
            "Pesquisa local com evidências rastreáveis. Avisos estáticos exigem investigação humana."
            if self.language == "pt-BR"
            else "Local research with traceable evidence. Static warnings require human investigation.",
        )
        row = QHBoxLayout()
        self.metric_labels = {}
        for key, label in [
            ("projects", "Projects"),
            ("scans", "Scanner"),
            ("files", "Files"),
            ("reports", "Reports"),
        ]:
            card = QFrame()
            card.setObjectName("card")
            card_layout = QVBoxLayout(card)
            number = QLabel("0")
            number.setObjectName("metric")
            card_layout.addWidget(number)
            card_layout.addWidget(QLabel(self.tr_label(label)))
            self.metric_labels[key] = number
            row.addWidget(card)
        self.pages["Overview"].addLayout(row)
        self.bar("Overview", [("Import demonstration", self.demo), ("Refresh", self.refresh)])
        self.scan_history = self.table(
            "Overview", ["ID", "Project", "Profile", "Status", "Files", "Seconds", "Started"]
        )

    def make_projects(self) -> None:
        self.note(
            "Projects",
            "Local folders / ZIP / files → managed snapshots. Imported source is never executed.",
        )
        self.bar(
            "Projects",
            [
                ("Import folder", self.import_folder),
                ("Import file / ZIP", self.import_file),
                ("Refresh snapshot", self.refresh_snapshot),
                ("Scan selected project", self.scan_selected),
            ],
        )
        self.projects_table = self.table(
            "Projects", ["ID", "Name", "Languages", "Program", "Origin", "Type"]
        )
        self.bar(
            "Projects",
            [
                ("Relink source folder", self.relink_folder),
                ("Relink source file", self.relink_file),
            ],
        )

    def relink_folder(self) -> None:
        project_id = self.selected(self.projects_table)
        source = QFileDialog.getExistingDirectory(self, self.tr_label("Relink source folder"))
        if source:
            self.engine.ingestion.relink(project_id, Path(source))
            self.refresh()

    def relink_file(self) -> None:
        project_id = self.selected(self.projects_table)
        source, _ = QFileDialog.getOpenFileName(self, self.tr_label("Relink source file"))
        if source:
            self.engine.ingestion.relink(project_id, Path(source))
            self.refresh()

    def import_folder(self) -> None:
        source = QFileDialog.getExistingDirectory(
            self, self.tr_label("Import source for authorized offline research")
        )
        if source:
            self.import_source(source)

    def import_file(self) -> None:
        source, _ = QFileDialog.getOpenFileName(self, self.tr_label("Import file / ZIP"))
        if source:
            self.import_source(source)

    def import_source(self, source: str) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr_label("Project"))
        layout = QFormLayout(dialog)
        name = QLineEdit(Path(source).stem)
        program = QComboBox()
        program.addItem("Independent offline research", None)
        for row in self.db.query("SELECT id,name FROM programs"):
            program.addItem(row["name"], row["id"])
        layout.addRow(self.tr_label("Name"), name)
        layout.addRow("Program", program)
        accepted = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        accepted.accepted.connect(dialog.accept)
        accepted.rejected.connect(dialog.reject)
        layout.addRow(accepted)
        if dialog.exec():
            self.start(
                lambda cancel, progress: self.engine.ingestion.add(
                    Path(source), name.text(), program.currentData(), cancel=cancel
                ),
                lambda result: self.log_message(f"Imported project #{result}"),
            )

    def demo(self) -> None:
        def operation(cancel, progress):
            project = self.engine.ingestion.add(
                ASSETS / "demo", "DEMONSTRATION / LABORATORY", demo=True, cancel=cancel
            )
            self.engine.scan(project, "quick", cancel, progress)
            return project

        self.start(operation, lambda result: self.log_message(f"DEMONSTRATION project #{result}"))

    def refresh_snapshot(self) -> None:
        project_id = self.selected(self.projects_table)
        self.start(lambda cancel, progress: self.engine.ingestion.refresh(project_id, cancel))

    def make_programs(self) -> None:
        self.note(
            "Programs",
            "Policy records document authorization. External active testing is unavailable.",
        )
        self.bar("Programs", [("Add program", self.add_program)])
        self.programs_table = self.table(
            "Programs", ["ID", "Name", "Policy URL", "Revision", "Reviewed", "Updated"]
        )
        self.programs_table.cellDoubleClicked.connect(lambda *_: self.guard(self.edit_program))

    def add_program(self) -> None:
        self.program_dialog()

    def edit_program(self) -> None:
        row = self.db.query(
            "SELECT * FROM programs WHERE id=?", (self.selected(self.programs_table),)
        )[0]
        self.program_dialog(row)

    def program_dialog(self, record: dict | None = None) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr_label("Programs"))
        dialog.resize(600, 550)
        form = QFormLayout(dialog)
        name = QLineEdit(record["name"] if record else "")
        url = QLineEdit(record["policy_url"] if record else "")
        policy = QPlainTextEdit(record["policy"] if record else Policy().model_dump_json(indent=2))
        notes = QPlainTextEdit(record["notes"] if record else "")
        form.addRow(self.tr_label("Name"), name)
        form.addRow(self.tr_label("Policy URL"), url)
        form.addRow("Policy JSON (exact hosts, exclusions, categories, budgets)", policy)
        form.addRow(self.tr_label("Notes"), notes)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        form.addRow(buttons)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        if dialog.exec():
            if not name.text().strip():
                raise OberhauError("Program name required")
            parsed = Policy.model_validate_json(policy.toPlainText())
            if (
                record
                and parsed.model_dump_json()
                != Policy.model_validate_json(record["policy"]).model_dump_json()
            ):
                parsed.revision = Policy.model_validate_json(record["policy"]).revision + 1
                parsed.reviewed = False
            if record:
                self.db.execute(
                    "UPDATE programs SET name=?,policy_url=?,policy=?,notes=?,updated=? WHERE id=?",
                    (
                        name.text(),
                        url.text(),
                        parsed.model_dump_json(),
                        redact(notes.toPlainText()),
                        now(),
                        record["id"],
                    ),
                )
            else:
                self.db.execute(
                    "INSERT INTO programs(name,policy_url,policy,notes,updated) VALUES(?,?,?,?,?)",
                    (
                        name.text(),
                        url.text(),
                        parsed.model_dump_json(),
                        redact(notes.toPlainText()),
                        now(),
                    ),
                )
            self.db.audit("program.policy", {"name": name.text(), "revision": parsed.revision})
            self.refresh()

    def make_scanner(self) -> None:
        form = QFormLayout()
        self.scan_project = QComboBox()
        self.scan_profile = QComboBox()
        self.scan_profile.addItems(PROFILES)
        self.profile_note = QLabel()
        self.profile_note.setWordWrap(True)
        self.scan_profile.currentTextChanged.connect(
            lambda profile: self.profile_note.setText(PROFILES[profile][0])
        )
        self.profile_note.setText(PROFILES["quick"][0])
        form.addRow(self.tr_label("Project"), self.scan_project)
        form.addRow(self.tr_label("Profile"), self.scan_profile)
        self.pages["Scanner"].addLayout(form)
        self.pages["Scanner"].addWidget(self.profile_note)
        self.bar("Scanner", [("Run offline scan", self.run_scan), ("Stop", self.stop)])
        self.capabilities = self.table(
            "Scanner",
            [
                "Scanner",
                "Installed",
                "Version",
                "Offline cache",
                "License",
                "Network",
                "Executable",
            ],
        )
        setup = QHBoxLayout()
        self.tool_choice = QComboBox()
        self.tool_choice.addItems(PINNED)
        self.ecosystem_choice = QComboBox()
        self.ecosystem_choice.addItems(ECOSYSTEMS)
        setup.addWidget(self.tool_choice)
        install = QPushButton(self.tr_label("Download official scanner"))
        install.clicked.connect(lambda: self.guard(self.install_scanner))
        setup.addWidget(install)
        setup.addWidget(self.ecosystem_choice)
        cache = QPushButton(self.tr_label("Download OSV advisory cache"))
        cache.clicked.connect(lambda: self.guard(self.refresh_advisories))
        setup.addWidget(cache)
        self.pages["Scanner"].addLayout(setup)
        self.bar(
            "Scanner", [("Download Trivy advisory cache (~1.5 GB)", self.refresh_trivy_advisories)]
        )
        note = QLabel(
            self.tr_label(
                "Downloads require Internet and stay in the local data directory. Project scans use cached data only."
            )
        )
        note.setWordWrap(True)
        self.pages["Scanner"].addWidget(note)

    def install_scanner(self) -> None:
        tool = self.tool_choice.currentText()
        self.start(
            lambda cancel, progress: install_tool(self.engine.home, tool, cancel, progress),
            self.tool_ready,
        )

    def refresh_advisories(self) -> None:
        ecosystem = self.ecosystem_choice.currentText()
        self.start(
            lambda cancel, progress: refresh_osv_cache(
                self.engine.home, ecosystem, cancel, progress
            ),
            self.tool_ready,
        )

    def tool_ready(self, result) -> None:
        self.log_message(json.dumps(result, ensure_ascii=False))
        QTimer.singleShot(100, self.diagnostics)

    def refresh_trivy_advisories(self) -> None:
        self.start(
            lambda cancel, progress: refresh_trivy_cache(self.engine.home, cancel, progress),
            self.tool_ready,
        )

    def scan_selected(self) -> None:
        project_id = self.selected(self.projects_table)
        self.navigation.setCurrentRow(PAGES.index("Scanner"))
        self.scan_project.setCurrentIndex(self.scan_project.findData(project_id))

    def run_scan(self) -> None:
        project_id = self.scan_project.currentData()
        if project_id is None:
            raise OberhauError("Import a project first")
        profile = self.scan_profile.currentText()
        self.start(lambda cancel, progress: self.engine.scan(project_id, profile, cancel, progress))

    def make_investigations(self) -> None:
        self.note(
            "Investigations",
            "Confidence measures detection certainty; severity and demonstrated impact are separate. Double-click to inspect source and history.",
        )
        self.findings_table = self.table(
            "Investigations",
            ["ID", "Project", "Severity", "Confidence", "Status", "Scanner", "Title", "Location"],
        )
        self.findings_table.cellDoubleClicked.connect(lambda *_: self.guard(self.inspect))
        self.findings_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.findings_table.customContextMenuRequested.connect(self.finding_menu)
        self.investigation_text = QPlainTextEdit()
        self.investigation_text.setReadOnly(True)
        self.investigation_text.setMaximumHeight(230)
        self.pages["Investigations"].addWidget(self.investigation_text)
        form = QHBoxLayout()
        self.review_status = QComboBox()
        self.review_status.addItems(list(Status))
        self.review_status.setToolTip(
            "Local reproduction requires a laboratory record. Human verification requires written evidence."
        )
        self.review_notes = QLineEdit()
        self.review_notes.setPlaceholderText(self.tr_label("Notes"))
        form.addWidget(self.review_status)
        form.addWidget(self.review_notes, 1)
        form.addWidget(self.button("Save review", self.save_review))
        self.pages["Investigations"].addLayout(form)

    def finding_menu(self, position) -> None:
        menu = QMenu(self)
        menu.addAction(self.tr_label("Open investigation"), lambda: self.guard(self.inspect))
        menu.exec(self.findings_table.viewport().mapToGlobal(position))

    def inspect(self) -> None:
        finding_id = self.selected(self.findings_table)
        result = self.engine.investigate(finding_id)
        history = []
        for observation in result["observations"]:
            evidence = json.loads(observation["data"])
            history.append(
                f"Scan #{observation['scan_id']} · {evidence['scanner']} · {evidence['rule']} · {evidence['path']}:{evidence['line']}"
            )
        self.investigation_text.setPlainText(
            f"Finding #{finding_id} · {result['status']}\n"
            f"Source integrity: {'unchanged (SHA-256 verified)' if result['source_unchanged'] else 'CHANGED — reanalysis required'}\n\n"
            + result["context"]
            + "\n\nRelated finding IDs: "
            + str(result["related_ids"])
            + "\n\nObserved history\n"
            + "\n".join(history)
            + "\n\nInvestigation questions\n"
            + "\n".join(result["questions"])
            + "\n\nHuman notes\n"
            + result["notes"]
        )
        self.review_status.setCurrentText(result["status"])
        self.review_notes.setText(result["notes"])
        self.report_finding.setCurrentIndex(self.report_finding.findData(finding_id))

    def save_review(self) -> None:
        self.db.review(
            self.selected(self.findings_table),
            Status(self.review_status.currentText()),
            self.review_notes.text(),
        )
        self.refresh()

    def make_laboratory(self) -> None:
        self.note(
            "Laboratory",
            "Only the checksum-matched bundled SQL fixture can be reproduced automatically. A disposable in-memory database verifies the vulnerable query and corrected control. Imported code is never executed.",
        )
        self.lab_finding = QComboBox()
        self.pages["Laboratory"].addWidget(self.lab_finding)
        self.bar("Laboratory", [("Run bundled SQL regression", self.run_lab)])
        self.lab_results = self.table(
            "Laboratory", ["ID", "Finding", "Passed", "Observed rows", "Fixed rows", "Created"]
        )

    def run_lab(self) -> None:
        finding_id = self.lab_finding.currentData()
        if finding_id is None:
            raise OberhauError("Import the demonstration and select its SQL finding")
        self.start(
            lambda cancel, progress: validate_sql(self.db, finding_id),
            lambda result: self.log_message(json.dumps(result)),
        )

    def make_intelligence(self) -> None:
        self.note(
            "Intelligence",
            "Dependency advisories are known-version warnings. Reachability, exploitability and novelty require investigation. OSV / Trivy must be installed with cached databases for offline matching.",
        )
        self.dependencies_table = self.table(
            "Intelligence", ["ID", "Project", "Advisories", "Title", "Location"]
        )

    def make_reports(self) -> None:
        row = QHBoxLayout()
        self.report_finding = QComboBox()
        self.report_language = QComboBox()
        self.report_language.addItems(["en", "pt-BR"])
        row.addWidget(self.report_finding, 1)
        row.addWidget(self.report_language)
        self.pages["Reports"].addLayout(row)
        self.bar(
            "Reports",
            [
                ("Generate draft", lambda: self.make_report(False)),
                ("Generate with Qwen", lambda: self.make_report(True)),
                ("Export", self.export_report),
                ("Copy", self.copy_report),
            ],
        )
        self.report_editor = QPlainTextEdit()
        self.pages["Reports"].addWidget(self.report_editor, 2)
        self.reports_table = self.table(
            "Reports", ["ID", "Finding", "Language", "Generator", "Created"]
        )
        self.reports_table.cellDoubleClicked.connect(lambda *_: self.guard(self.load_report))

    def make_report(self, ai: bool) -> None:
        finding = self.report_finding.currentData()
        if finding is None:
            raise OberhauError("Select a finding first")
        language = self.report_language.currentText()
        self.start(
            lambda cancel, progress: generate(self.db, finding, language, ai, cancel),
            self.report_ready,
        )

    def report_ready(self, result) -> None:
        self.report_id, content = result
        self.report_editor.setPlainText(content)

    def load_report(self) -> None:
        self.report_id = self.selected(self.reports_table)
        self.report_editor.setPlainText(
            self.db.query("SELECT content FROM reports WHERE id=?", (self.report_id,))[0]["content"]
        )

    def export_report(self) -> None:
        if self.report_id is None:
            raise OberhauError("Generate or open a report first")
        destination, _ = QFileDialog.getSaveFileName(
            self,
            self.tr_label("Export"),
            "oberhau-report.md",
            "Reports (*.md *.html *.json *.sarif)",
        )
        if destination:
            export(self.db, self.report_id, Path(destination), self.report_editor.toPlainText())
            self.log_message(f"Exported {destination}")
            self.refresh()

    def copy_report(self) -> None:
        QApplication.clipboard().setText(redact(self.report_editor.toPlainText()))

    def make_automation(self) -> None:
        self.note(
            "Automation",
            "Schedules run offline snapshots while this application is open and idle. Refresh source copies explicitly before reanalysis. No startup service or external active scans.",
        )
        self.schedule_enabled = QCheckBox(self.tr_label("Enable offline schedules"))
        self.schedule_enabled.setChecked(self.db.setting("schedules_enabled", False))
        self.schedule_enabled.toggled.connect(
            lambda enabled: self.db.set_setting("schedules_enabled", enabled)
        )
        self.pages["Automation"].addWidget(self.schedule_enabled)
        self.bar(
            "Automation",
            [("Add schedule", self.schedule_dialog), ("Toggle schedule", self.toggle_schedule)],
        )
        self.schedules_table = self.table(
            "Automation", ["ID", "Project", "Profile", "Minutes", "Enabled", "Next UTC"]
        )

    def schedule_dialog(self) -> None:
        project = self.scan_project.currentData()
        if project is None:
            raise OberhauError("Choose a project on the Scanner page first")
        minutes, ok = QInputDialog.getInt(
            self, self.tr_label("Add schedule"), self.tr_label("Interval (minutes)"), 60, 1, 525600
        )
        if ok:
            add_schedule(self.db, project, self.scan_profile.currentText(), minutes)
            self.refresh()

    def toggle_schedule(self) -> None:
        self.db.execute(
            "UPDATE schedules SET enabled=1-enabled WHERE id=?",
            (self.selected(self.schedules_table),),
        )
        self.refresh()

    def tick(self) -> None:
        if self.worker is None and self.db.setting("schedules_enabled", False):
            self.guard(self.run_due)

    def run_due(self) -> None:
        due = take_due(self.db)
        if due:
            self.log_message(f"Offline schedule #{due['id']}: project {due['project_id']}")
            self.start(
                lambda cancel, progress: self.engine.scan(
                    due["project_id"], due["profile"], cancel, progress
                )
            )

    def make_analytics(self) -> None:
        self.note(
            "Analytics",
            "Metrics use persisted records only. Rewards are entered manually in BRL. Advertised bounties are never counted as revenue.",
        )
        self.analytics_text = QPlainTextEdit()
        self.analytics_text.setReadOnly(True)
        self.pages["Analytics"].addWidget(self.analytics_text, 1)
        self.bar("Analytics", [("Record reward / time", self.reward_dialog)])

    def reward_dialog(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr_label("Record reward / time"))
        form = QFormLayout(dialog)
        amount, hours = QDoubleSpinBox(), QDoubleSpinBox()
        amount.setRange(0, 100000000)
        hours.setRange(0, 100000)
        outcome = QComboBox()
        outcome.addItems(["time invested", "submitted manually", "accepted", "rejected"])
        form.addRow(self.tr_label("Rewards received (BRL)"), amount)
        form.addRow(self.tr_label("Hours invested"), hours)
        form.addRow(self.tr_label("Manual outcome"), outcome)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        form.addRow(buttons)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        if dialog.exec():
            self.db.execute(
                "INSERT INTO rewards(amount,hours,outcome,created) VALUES(?,?,?,?)",
                (amount.value(), hours.value(), outcome.currentText(), now()),
            )
            self.refresh()

    def make_settings(self) -> None:
        form = QFormLayout()
        self.ui_language = QComboBox()
        self.ui_language.addItems(["pt-BR", "en"])
        self.ui_language.setCurrentText(self.language)
        self.parallelism = QSpinBox()
        self.parallelism.setRange(1, 8)
        self.parallelism.setValue(self.engine.limits.parallelism)
        self.timeout = QSpinBox()
        self.timeout.setRange(1, 3600)
        self.timeout.setValue(self.engine.limits.timeout)
        self.ollama_url = QLineEdit(self.db.setting("ollama_url", "http://127.0.0.1:11434"))
        self.ollama_model = QLineEdit(self.db.setting("ollama_model", "qwen3.5:4b"))
        form.addRow(self.tr_label("Language") + " (restart)", self.ui_language)
        form.addRow(self.tr_label("Parallel scanners"), self.parallelism)
        form.addRow(self.tr_label("Scanner timeout (seconds)"), self.timeout)
        form.addRow("Ollama URL", self.ollama_url)
        form.addRow("Ollama model", self.ollama_model)
        self.pages["Settings"].addLayout(form)
        self.note(
            "Settings",
            self.tr_label(
                "Research backups include raw source, historical snapshots and the database. Keep the archive protected. Scanner binaries, caches and model weights are installed separately."
            ),
        )
        self.bar(
            "Settings",
            [
                ("Save settings", self.save_settings),
                ("System diagnostics", self.diagnostics),
                ("Export diagnostics", self.export_diagnostics),
            ],
        )
        self.bar(
            "Settings",
            [
                ("Backup research", self.backup),
                ("Restore research", self.restore),
                ("Open data directory", self.open_data_directory),
            ],
        )
        self.diagnostics_text = QPlainTextEdit()
        self.diagnostics_text.setReadOnly(True)
        self.pages["Settings"].addWidget(self.diagnostics_text, 1)

    def save_settings(self) -> None:
        if self.worker:
            raise OberhauError("Wait for the running job before changing resource settings")
        url = local_ollama_url(self.ollama_url.text())
        limits = self.engine.limits.model_copy(
            update={"parallelism": self.parallelism.value(), "timeout": self.timeout.value()}
        )
        self.db.set_setting("limits", limits.model_dump())
        self.db.set_setting("language", self.ui_language.currentText())
        self.db.set_setting("ollama_url", url)
        self.db.set_setting("ollama_model", self.ollama_model.text())
        self.engine.limits = limits
        self.engine.ingestion.limits = limits
        self.log_message("Preferences saved; language applies on restart")

    def diagnostics(self) -> None:
        if self.worker is None:
            self.diagnostics_attempted = True
            self.start(
                lambda cancel, progress: collect(home=self.engine.home), self.diagnostics_ready
            )

    def diagnostics_ready(self, result) -> None:
        self.diagnostic_data = result
        self.diagnostics_text.setPlainText(json.dumps(result, indent=2, ensure_ascii=False))
        self.fill(
            self.capabilities,
            [
                [
                    r["scanner"],
                    r["installed"],
                    r["version"],
                    self.scanner_cache_label(r["scanner"], result),
                    r["license"],
                    r["network"],
                    r["path"],
                ]
                for r in result["scanners"]
            ],
        )
        self.db.set_setting("last_diagnostics", result)

    @staticmethod
    def scanner_cache_label(scanner: str, result: dict) -> str:
        caches = result.get("offline_caches", {})
        if scanner == "osv-scanner":
            return "; ".join(
                f"{ecosystem}: "
                + (
                    "ready"
                    if caches.get(ecosystem, {}).get("checksum_valid")
                    else "missing/invalid"
                )
                for ecosystem in ECOSYSTEMS
            )
        if scanner == "trivy":
            return "Config: bundled; vulnerability DB: " + (
                "present" if caches.get("trivy_vulnerability_db", {}).get("present") else "missing"
            )
        return "Not required"

    def export_diagnostics(self) -> None:
        destination, _ = QFileDialog.getSaveFileName(
            self, self.tr_label("Export diagnostics"), "oberhau-diagnostics.json", "JSON (*.json)"
        )
        if destination:
            Path(destination).write_text(
                json.dumps(self.diagnostic_data, indent=2, ensure_ascii=False), encoding="utf-8"
            )

    def backup(self) -> None:
        destination, _ = QFileDialog.getSaveFileName(
            self,
            self.tr_label("Backup research"),
            "oberhau-backup.oberhau.zip",
            "Oberhau research backup (*.oberhau.zip)",
        )
        if destination:
            self.start(
                lambda cancel, progress: create_backup(
                    self.db, self.engine.home, Path(destination), cancel, progress
                ),
                lambda result: self.log_message(json.dumps(result, ensure_ascii=False)),
            )

    def restore(self) -> None:
        source, _ = QFileDialog.getOpenFileName(
            self, self.tr_label("Restore research"), "", "Oberhau research backup (*.oberhau.zip)"
        )
        if not source:
            return
        parent = QFileDialog.getExistingDirectory(
            self, self.tr_label("Choose the parent folder for restoration")
        )
        if not parent:
            return
        name, accepted = QInputDialog.getText(
            self,
            self.tr_label("Restore research"),
            self.tr_label("New data directory name"),
            text="Oberhau-Restored",
        )
        if accepted and name.strip():
            destination = confined(Path(parent), name.strip())
            self.start(
                lambda cancel, progress: restore_backup(
                    Path(source), destination, cancel, progress
                ),
                lambda result: self.log_message(
                    self.tr_label("Restored data directory")
                    + ": "
                    + result["restored"]
                    + ". "
                    + self.tr_label("Use Open data directory to view the restored research.")
                ),
            )

    def open_data_directory(self) -> None:
        if self.worker:
            raise OberhauError("Wait for the current operation before switching data directories")
        directory = QFileDialog.getExistingDirectory(self, self.tr_label("Open data directory"))
        if directory:
            path = Path(directory).resolve()
            if path == self.engine.home:
                return
            if not (path / "oberhau.sqlite3").is_file():
                raise OberhauError("Select an Oberhau data directory containing oberhau.sqlite3")
            self.replacement = Window(Engine(path), first_run=False)
            self.replacement.show()
            self.close()

    def start(self, operation: Callable, completion: Callable | None = None) -> None:
        if self.worker is not None:
            raise OberhauError("A background task is running; stop it or wait for completion")
        self.worker = Worker(operation, self)
        self.completion = completion
        self.worker.progress.connect(self.log_message)
        self.worker.result.connect(self.on_result)
        self.worker.failed.connect(self.on_failure)
        self.worker.finished.connect(self.on_finished)
        self.progress.setRange(0, 0)
        self.progress.setVisible(True)
        self.job_label.setText("Running…")
        self.worker.start()

    def on_result(self, result) -> None:
        if self.completion:
            self.guard(lambda: self.completion(result))

    def on_failure(self, message: str) -> None:
        self.log_message(message)
        if message != "Cancelled":
            QMessageBox.warning(self, self.tr_label("Error"), message)

    def on_finished(self) -> None:
        worker = self.worker
        self.worker = None
        self.completion = None
        if worker:
            worker.deleteLater()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setVisible(False)
        self.job_label.setText(self.tr_label("Idle"))
        self.refresh()
        if not self.diagnostics_attempted:
            QTimer.singleShot(0, self.diagnostics)

    def stop(self) -> None:
        if self.worker:
            self.worker.cancel.set()
            self.log_message("Cancellation requested")

    def log_message(self, message: str) -> None:
        clean = redact(message)
        self.job_label.setText(clean[:180])
        self.activity.appendPlainText(clean)
        logging.getLogger("oberhau").info(clean)

    def refresh(self) -> None:
        metrics = self.db.metrics()
        for key, label in self.metric_labels.items():
            label.setText(str(metrics[key]))
        scans = self.db.query("SELECT * FROM scans ORDER BY id DESC LIMIT 200")
        self.fill(
            self.scan_history,
            [
                [
                    r["id"],
                    r["project_id"],
                    r["profile"],
                    r["status"],
                    r["file_count"],
                    round(r["duration"], 2),
                    r["started"],
                ]
                for r in scans
            ],
        )
        projects = self.db.query("SELECT * FROM projects ORDER BY id")
        self.demo_banner.setVisible(any(p["demo"] for p in projects))
        self.fill(
            self.projects_table,
            [
                [
                    p["id"],
                    p["name"],
                    ", ".join(json.loads(p["metadata"])["languages"]),
                    p["program_id"],
                    p["origin"],
                    "DEMONSTRATION" if p["demo"] else "Research",
                ]
                for p in projects
            ],
        )
        chosen = self.scan_project.currentData()
        self.scan_project.clear()
        for project in projects:
            self.scan_project.addItem(f"#{project['id']} {project['name']}", project["id"])
        if chosen:
            self.scan_project.setCurrentIndex(self.scan_project.findData(chosen))
        programs = self.db.query("SELECT * FROM programs")
        self.fill(
            self.programs_table,
            [
                [
                    p["id"],
                    p["name"],
                    p["policy_url"],
                    json.loads(p["policy"])["revision"],
                    json.loads(p["policy"])["reviewed"],
                    p["updated"],
                ]
                for p in programs
            ],
        )
        findings = self.db.query("SELECT * FROM findings ORDER BY id DESC")
        rows = []
        dependencies = []
        selected_report = self.report_finding.currentData()
        selected_lab = self.lab_finding.currentData()
        self.report_finding.clear()
        self.lab_finding.clear()
        for record in findings:
            item = json.loads(record["data"])
            rows.append(
                [
                    record["id"],
                    record["project_id"],
                    item["severity"],
                    f"{item['confidence']:.0%}",
                    record["status"],
                    item["scanner"],
                    item["title"],
                    f"{item['path']}:{item['line']}",
                ]
            )
            self.report_finding.addItem(f"#{record['id']} {item['title']}", record["id"])
            if item["rule"] == "python-sql-format":
                self.lab_finding.addItem(
                    f"#{record['id']} {item['path']} (project {record['project_id']})", record["id"]
                )
            if item["category"] == "dependencies":
                dependencies.append(
                    [
                        record["id"],
                        record["project_id"],
                        ", ".join(item["advisories"]),
                        item["title"],
                        item["path"],
                    ]
                )
        if selected_report:
            self.report_finding.setCurrentIndex(self.report_finding.findData(selected_report))
        if selected_lab:
            self.lab_finding.setCurrentIndex(self.lab_finding.findData(selected_lab))
        self.fill(self.findings_table, rows)
        self.fill(self.dependencies_table, dependencies)
        validations = self.db.query("SELECT * FROM validations ORDER BY id DESC")
        self.fill(
            self.lab_results,
            [
                [
                    v["id"],
                    v["finding_id"],
                    json.loads(v["result"])["passed"],
                    json.loads(v["result"])["observed_rows"],
                    json.loads(v["result"])["fixed_rows"],
                    v["created"],
                ]
                for v in validations
            ],
        )
        self.fill(
            self.reports_table,
            [
                [r["id"], r["finding_id"], r["language"], r["generator"], r["created"]]
                for r in self.db.query("SELECT * FROM reports ORDER BY id DESC")
            ],
        )
        self.fill(
            self.schedules_table,
            [
                [
                    r["id"],
                    r["project_id"],
                    r["profile"],
                    r["interval_minutes"],
                    bool(r["enabled"]),
                    r["next_run"],
                ]
                for r in self.db.query("SELECT * FROM schedules")
            ],
        )
        total = len(findings)
        false = sum(r["status"] == Status.FALSE_POSITIVE for r in findings)
        metrics["false_positive_fraction_all_findings"] = false / total if total else None
        rewards = metrics["rewards"]
        metrics["hourly_return_BRL"] = (
            rewards["amount"] / rewards["hours"] if rewards["hours"] else None
        )
        self.analytics_text.setPlainText(json.dumps(metrics, indent=2, ensure_ascii=False))

    def setup(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("OBERHAU · " + self.tr_label("First run"))
        layout = QVBoxLayout(dialog)
        explanation = QLabel(
            "Bem-vindo ao Oberhau. A pesquisa offline não executa código importado.\n"
            "Use somente fontes cuja análise você está autorizado a realizar.\n"
            "Semgrep, OSV, Gitleaks, Trivy e Qwen são opcionais.\n"
            "Agendamentos ficam desativados até sua escolha explícita."
            if self.language == "pt-BR"
            else "Welcome to Oberhau. Offline research never executes imported code.\n"
            "Analyze only authorized sources. External scanners and Qwen are optional.\n"
            "Schedules remain disabled until explicitly enabled."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        parallel = QSpinBox()
        parallel.setRange(1, 8)
        parallel.setValue(self.engine.limits.parallelism)
        layout.addWidget(QLabel(self.tr_label("Parallel scanners")))
        layout.addWidget(parallel)
        demo = QCheckBox(self.tr_label("Import demonstration"))
        layout.addWidget(demo)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(dialog.accept)
        layout.addWidget(buttons)
        if dialog.exec():
            self.parallelism.setValue(parallel.value())
            self.save_settings()
            self.db.set_setting("setup_complete", True)
            if demo.isChecked():
                self.demo()
            else:
                self.diagnostics()

    def closeEvent(self, event) -> None:
        self.timer.stop()
        if self.worker and self.worker.isRunning():
            self.stop()
            event.ignore()
            self.log_message("Waiting for safe worker shutdown…")
            self.worker.finished.connect(self.close)
            return
        self.db.set_setting("window_size", [self.width(), self.height()])
        event.accept()


def main(home: Path | None = None) -> int:
    app = QApplication.instance() or QApplication(sys.argv[:1])
    configure_fonts()
    app.setStyle("Fusion")
    app.setStyleSheet(THEME)
    engine = Engine(home or data_home())
    logdir = engine.home / "logs"
    logdir.mkdir(exist_ok=True)
    handler = RotatingFileHandler(
        logdir / "oberhau.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    logging.getLogger("oberhau").addHandler(handler)
    logging.getLogger("oberhau").setLevel(logging.INFO)
    window = Window(engine)
    saved = engine.db.setting("window_size")
    if saved:
        window.resize(*saved)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
