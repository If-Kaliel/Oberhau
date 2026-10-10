"""Incremental research UI backed by real engine records, separate from the main window."""

from __future__ import annotations

import json

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from oberhau.benchmark import evaluate
from oberhau.core import OberhauError
from oberhau.local_validation import validate_local
from oberhau.research import research_queue
from oberhau.research_assistant import assist
from oberhau.research_models import ResearchLimits


class ResearchPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.engine = window.engine
        layout = QVBoxLayout(self)
        note = QLabel(
            "Pesquisa contextual offline · Hipóteses provisórias · Revisão humana obrigatória"
            if window.language == "pt-BR"
            else "Offline contextual research · Provisional hypotheses · Human review required"
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        controls = QHBoxLayout()
        controls.addWidget(window.button("Run contextual research", self.run))
        self.runs = QComboBox()
        self.runs.setMinimumWidth(230)
        controls.addWidget(self.runs, 1)
        controls.addWidget(window.button("Refresh", self.refresh))
        layout.addLayout(controls)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.views = {}
        for name in [
            "Investigation Workspace",
            "Code Flow Viewer",
            "AI Investigator",
            "Research Queue",
            "Git Intelligence",
            "Benchmark Dashboard",
            "Automation Control",
        ]:
            container = QWidget()
            tab_layout = QVBoxLayout(container)
            if name == "AI Investigator":
                row = QHBoxLayout()
                row.addWidget(window.button("Review questions", lambda: self.assistant(False)))
                row.addWidget(window.button("Investigate with Qwen", lambda: self.assistant(True)))
                tab_layout.addLayout(row)
            if name == "Benchmark Dashboard":
                tab_layout.addWidget(window.button("Run detection benchmark", self.benchmark))
            if name == "Investigation Workspace":
                row = QHBoxLayout()
                row.addWidget(
                    window.button("Validate local authorization", lambda: self.lab("authorization"))
                )
                row.addWidget(
                    window.button("Validate local inputs", lambda: self.lab("input-validation"))
                )
                tab_layout.addLayout(row)
            if name == "Automation Control":
                tab_layout.addWidget(window.button("Research limits", self.configure_limits))
            view = QPlainTextEdit()
            view.setReadOnly(True)
            self.views[name] = view
            tab_layout.addWidget(view, 1)
            self.tabs.addTab(container, window.tr_label(name))
        self.runs.currentIndexChanged.connect(self.show_run)

    def run(self):
        project = self.window.scan_project.currentData()
        if project is None:
            raise OberhauError("Choose an authorized project on the Scanner page first")
        self.window.start(
            lambda cancel, progress: self.engine.scan(project, "research", cancel, progress),
            lambda _: self.refresh(),
        )

    def configure_limits(self):
        values = ResearchLimits.model_validate(self.engine.db.setting("research_limits", {}))
        dialog = QDialog(self)
        dialog.setWindowTitle(self.window.tr_label("Research limits"))
        layout = QFormLayout(dialog)
        fields = {}
        for key, minimum, maximum in [
            ("max_nodes", 100, 100000),
            ("max_symbols", 1, 20000),
            ("max_depth", 1, 8),
            ("max_visits", 1, 256),
            ("max_index_bytes", 1000, 100000000),
        ]:
            spin = QSpinBox()
            spin.setRange(minimum, maximum)
            spin.setValue(getattr(values, key))
            fields[key] = spin
            layout.addRow(key.replace("_", " "), spin)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        if dialog.exec():
            configured = ResearchLimits.model_validate(
                {key: spin.value() for key, spin in fields.items()}
            )
            self.engine.db.set_setting("research_limits", configured.model_dump())
            self.refresh()

    def run_id(self):
        if self.runs.currentData() is None:
            raise OberhauError("Select a completed contextual research run")
        return self.runs.currentData()

    def assistant(self, ai):
        run_id = self.run_id()
        self.window.start(
            lambda cancel, progress: assist(self.engine, run_id, ai, cancel),
            lambda result: self.display("AI Investigator", result),
        )

    def benchmark(self):
        def done(result):
            self.engine.db.set_setting("last_research_benchmark", result)
            self.display("Benchmark Dashboard", result)

        self.window.start(lambda cancel, progress: evaluate(cancel), done)

    def lab(self, recipe):
        self.window.start(
            lambda cancel, progress: validate_local(self.engine.db, recipe, cancel),
            lambda result: self.display("Investigation Workspace", result),
        )

    def display(self, name, result):
        self.views[name].setPlainText(json.dumps(result, indent=2, ensure_ascii=False))

    def refresh(self):
        chosen = self.runs.currentData()
        self.runs.blockSignals(True)
        self.runs.clear()
        for row in self.engine.db.query(
            "SELECT id,project_id,commit_hash FROM research_runs WHERE status='completed' ORDER BY id DESC LIMIT 100"
        ):
            self.runs.addItem(
                f"#{row['id']} · project {row['project_id']} · {(row['commit_hash'] or 'local')[:12]}",
                row["id"],
            )
        if chosen is not None and self.runs.findData(chosen) >= 0:
            self.runs.setCurrentIndex(self.runs.findData(chosen))
        self.runs.blockSignals(False)
        self.show_run()
        benchmark = self.engine.db.setting("last_research_benchmark")
        self.views["Benchmark Dashboard"].setPlainText(
            json.dumps(benchmark, indent=2, ensure_ascii=False)
            if benchmark
            else "No benchmark execution recorded. Run the trusted evaluation to obtain actual metrics."
        )
        self.display("Research Queue", research_queue(self.engine.db))
        self.display(
            "Automation Control",
            {
                "execution": "One foreground job; existing offline schedules support the research profile while GUI is open and idle. Stop cancels the current worker. Toggle schedules pauses future jobs.",
                "scanner_limits": self.engine.limits.model_dump(),
                "research_limits": self.engine.db.setting("research_limits", {}),
                "schedules_enabled": self.engine.db.setting("schedules_enabled", False),
                "limits_note": "Index/graph budgets and deadlines are cooperative; OS memory quotas and GPU auto-pause are pending",
            },
        )

    def show_run(self, *_):
        if self.runs.currentData() is None:
            self.views["Investigation Workspace"].setPlainText(
                "No contextual research results. Choose a project and run research."
            )
            self.views["Code Flow Viewer"].clear()
            self.views["Git Intelligence"].clear()
            return
        row = self.engine.db.query(
            "SELECT * FROM research_runs WHERE id=?", (self.runs.currentData(),)
        )[0]
        data = json.loads(row["data"])
        self.display(
            "Investigation Workspace",
            {
                "run": row["id"],
                "hypotheses": data["hypotheses"],
                "coverage": data.get("coverage"),
                "index": data.get("index"),
                "limitations": data["limitations"],
                "trusted_lab_history": [
                    json.loads(row["result"])
                    for row in self.engine.db.query(
                        "SELECT result FROM validations WHERE finding_id IS NULL ORDER BY id DESC LIMIT 5"
                    )
                ],
            },
        )
        nodes = {n["id"]: n for n in data["graph"]["nodes"]}
        lines = []
        for hypothesis in data["hypotheses"]:
            lines.append(hypothesis["title"])
            for eid in hypothesis["execution_path"]:
                node = nodes[eid]
                lines.append(f"  → {node['kind']}: {node['label']} ({node['path']}:{node['line']})")
            lines.append("  Static syntactic path; runtime reachability and bindings unverified.\n")
        for edge in data["graph"]["edges"]:
            source, target = nodes[edge["source"]], nodes[edge["target"]]
            lines.append(f"{source['label']} → [{edge['relation']}] → {target['label']}")
        self.views["Code Flow Viewer"].setPlainText("\n".join(lines))
        self.display(
            "Git Intelligence",
            {
                "commit": row["commit_hash"],
                "changes": data.get("changes", []),
                "security_changes": data.get("git_intelligence", {}),
                "limitations": "Retained research snapshots only; local new observations do not establish novelty or exploitability",
            },
        )
        assistance = self.engine.db.query(
            "SELECT data FROM research_assistance WHERE run_id=? ORDER BY id DESC LIMIT 1",
            (row["id"],),
        )
        self.views["AI Investigator"].setPlainText(
            assistance[0]["data"]
            if assistance
            else "No AI investigation recorded. Structured read tools only; model output remains provisional."
        )
