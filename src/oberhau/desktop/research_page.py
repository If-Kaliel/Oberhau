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
from oberhau.desktop.research_results import ResearchResults, prose
from oberhau.local_validation import validate_local
from oberhau.maintenance import usage
from oberhau.research import research_queue
from oberhau.research_assistant import ResearchQuery, ResearchTools, assist
from oberhau.research_models import ResearchLimits


class ResearchPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.engine = window.engine
        self.last_cache_maintenance = None
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
                maintenance = QHBoxLayout()
                maintenance.addWidget(
                    window.button(
                        self.text("Limites de armazenamento", "Storage limits"),
                        self.configure_retention,
                    )
                )
                maintenance.addWidget(
                    window.button(
                        self.text("Prever limpeza do cache", "Preview cache cleanup"),
                        lambda: self.maintenance(False),
                    )
                )
                maintenance.addWidget(
                    window.button(
                        self.text("Limpar cache sem referências", "Clean unreferenced cache"),
                        lambda: self.maintenance(True),
                    )
                )
                tab_layout.addLayout(maintenance)
            view = ResearchResults(self, name)
            self.views[name] = view
            tab_layout.addWidget(view, 1)
            self.tabs.addTab(container, window.tr_label(name))
        self.runs.currentIndexChanged.connect(self.show_run)

    def text(self, portuguese, english):
        return portuguese if self.window.language == "pt-BR" else english

    def configure_retention(self):
        from oberhau.maintenance import RetentionLimits

        values = RetentionLimits.model_validate(self.engine.db.setting("retention_limits", {}))
        dialog = QDialog(self)
        dialog.setWindowTitle(self.text("Limites de armazenamento", "Storage limits"))
        layout = QFormLayout(dialog)
        fields = {}
        for key, label, minimum, maximum in [
            ("cache_bytes", self.text("Cache (bytes)", "Cache (bytes)"), 1000, 1_000_000_000),
            (
                "history_bytes",
                self.text("Histórico de pesquisa (bytes)", "Research history (bytes)"),
                1000,
                2_000_000_000,
            ),
            ("runs_per_project", self.text("Pesquisas por projeto", "Runs per project"), 1, 10000),
        ]:
            spin = QSpinBox()
            spin.setRange(minimum, maximum)
            spin.setValue(getattr(values, key))
            fields[key] = spin
            layout.addRow(label, spin)
        note = QLabel(
            self.text(
                "Ao atingir o limite, novas gravações de pesquisa param. Evidências e decisões humanas são preservadas. Faça backup completo antes de trocar o diretório de dados.",
                "At the limit, new research writes stop. Evidence and human decisions are preserved. Create a complete backup before changing data directories.",
            )
        )
        note.setWordWrap(True)
        layout.addRow(note)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        if dialog.exec():
            configured = RetentionLimits.model_validate(
                {key: spin.value() for key, spin in fields.items()}
            )
            self.engine.db.set_setting("retention_limits", configured.model_dump())
            self.refresh()

    def maintenance(self, apply):
        from oberhau.maintenance import maintain

        def done(result):
            self.last_cache_maintenance = result

        self.window.start(
            lambda cancel, progress: maintain(self.engine, apply, cancel),
            done,
        )

    def open_evidence(self, node):
        tools = ResearchTools(self.engine, self.run_id())
        result = tools.execute(ResearchQuery(action="excerpt", evidence_id=node["id"]))
        dialog = QDialog(self)
        dialog.setWindowTitle(f"{node['path']}:{node['line']} · SHA-256")
        dialog.resize(900, 550)
        layout = QVBoxLayout(dialog)
        layout.addWidget(
            QLabel(
                self.text(
                    "Trecho do snapshot verificado por SHA-256; segredos ocultados.",
                    "SHA-256 verified snapshot excerpt; secrets redacted.",
                )
            )
        )
        source = QPlainTextEdit(result["excerpt"])
        source.setReadOnly(True)
        source.setAccessibleName(self.text("Código verificado", "Verified source"))
        layout.addWidget(source)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()

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
            ("parser_timeout_seconds", 1, 60),
            ("parser_memory_mib", 128, 2048),
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
        rows = []
        summary = ""

        def add(columns, detail=None, node=None, children=None):
            rows.append((columns, detail, node, children or []))

        if name == "Investigation Workspace" and "hypotheses" in result:
            nodes = {n["id"]: n for n in self.current_data["graph"]["nodes"]}
            summary = self.text(
                "Hipóteses provisórias. Selecione uma linha e expanda suas evidências; ausência de controle visível exige revisão.",
                "Provisional hypotheses. Select a row and expand its evidence; absent visible controls require review.",
            )
            for hypothesis in result["hypotheses"]:
                evidence = [nodes[e] for e in hypothesis["evidence_ids"] if e in nodes]
                source_nodes = [n for n in evidence if n["path"] and n["sha256"]]
                children = [
                    (
                        [n["label"], n["kind"], f"{n['path']}:{n['line']}", "SHA-256"],
                        n,
                        n if n in source_nodes else None,
                    )
                    for n in evidence
                ]
                add(
                    [
                        self.window.tr_label(hypothesis["title"]),
                        hypothesis["rule"],
                        f"{hypothesis['path']}:{hypothesis['line']}",
                        f"{hypothesis['confidence']:.0%}",
                    ],
                    hypothesis,
                    source_nodes[0] if source_nodes else None,
                    children,
                )
            add(
                [self.text("Cobertura e limites", "Coverage and limits"), "", "", ""],
                {k: v for k, v in result.items() if k != "hypotheses"},
            )
        elif name == "Code Flow Viewer":
            nodes = {n["id"]: n for n in result["nodes"]}
            summary = self.text(
                "Relações sintáticas observadas; execução e vínculos em runtime não comprovados.",
                "Observed syntactic relations; runtime reachability and bindings unverified.",
            )
            for edge in result["edges"]:
                source, target = nodes[edge["source"]], nodes[edge["target"]]
                node = target if target["path"] and target["sha256"] else source
                add(
                    [
                        source["label"],
                        edge["relation"],
                        target["label"],
                        f"{node['path']}:{node['line']}",
                    ],
                    {"source": source, "relation": edge["relation"], "target": target},
                    node if node["path"] and node["sha256"] else None,
                )
        elif name == "Research Queue":
            summary = self.text(
                "Prioridade heurística; impacto e elegibilidade exigem revisão humana.",
                "Heuristic priority; impact and eligibility require human review.",
            )
            for item in result:
                add(
                    [
                        f"#{item['id']} · {item['title']}",
                        item["status"],
                        item["evidence_quality"],
                        item["priority"],
                    ],
                    item,
                )
        elif name == "Benchmark Dashboard" and isinstance(result, dict) and "cases" in result:
            summary = f"{result['dataset']} · TP {result['true_positives']} · FP {result['false_positives']} · FN {result['false_negatives']} · {result['seconds']:.2f}s"
            add(
                [self.text("Métricas e limites", "Metrics and limits"), "", "", ""],
                {k: v for k, v in result.items() if k != "cases"},
            )
            for case in result["cases"]:
                add(
                    [
                        case["id"],
                        case["framework"],
                        f"FP {case['false_positives']} · FN {case['false_negatives']}",
                        f"{case['seconds']:.3f}s",
                    ],
                    case,
                )
        elif name == "AI Investigator":
            summary = (
                self.text(
                    "Rascunho provisório; citações não comprovam as afirmações do modelo.",
                    "Provisional draft; citations do not prove model claims.",
                )
                + " · "
                + result.get("generator", "")
            )
            for claim in result.get("claims", []):
                add([claim["text"], claim["kind"], ", ".join(claim["evidence_ids"]), ""], claim)
            for question in result.get("questions", []):
                add(
                    [question, self.text("Pergunta de revisão", "Review question"), "", ""],
                    question,
                )
            add(
                [self.text("Limites e consultas", "Limits and queries"), "", "", ""],
                {k: v for k, v in result.items() if k not in {"claims", "questions"}},
            )
        else:
            for key, value in result.items():
                add([key.replace("_", " "), "", prose(value)[:150].replace("\n", " "), ""], value)
        self.views[name].render(result, rows, summary)

    def refresh(self):
        chosen = self.runs.currentData()
        self.runs.blockSignals(True)
        self.runs.clear()
        for row in self.engine.db.query(
            "SELECT id,project_id,commit_hash,status FROM research_runs ORDER BY id DESC LIMIT 100"
        ):
            self.runs.addItem(
                f"#{row['id']} · project {row['project_id']} · {row['status']} · {(row['commit_hash'] or 'local')[:12]}",
                row["id"],
            )
        if chosen is not None and self.runs.findData(chosen) >= 0:
            self.runs.setCurrentIndex(self.runs.findData(chosen))
        self.runs.blockSignals(False)
        self.show_run()
        benchmark = self.engine.db.setting("last_research_benchmark")
        if benchmark:
            self.display("Benchmark Dashboard", benchmark)
        else:
            self.views["Benchmark Dashboard"].setPlainText(
                self.text(
                    "Nenhuma avaliação registrada. Execute o benchmark para obter métricas.",
                    "No evaluation recorded. Run the benchmark to obtain metrics.",
                )
            )
        self.display("Research Queue", research_queue(self.engine.db))
        self.display(
            "Automation Control",
            {
                "execution": "One foreground job; existing offline schedules support the research profile while GUI is open and idle. Stop cancels the current worker. Toggle schedules pauses future jobs.",
                "scanner_limits": self.engine.limits.model_dump(),
                "research_limits": self.engine.db.setting("research_limits", {}),
                "schedules_enabled": self.engine.db.setting("schedules_enabled", False),
                "limits_note": "Parser runs in a separate process with a per-file deadline and a Windows committed-memory ceiling. Parent graph budgets are cooperative; global CPU/RAM quotas and GPU auto-pause are pending",
                "storage": usage(self.engine.db),
                "last_cache_maintenance": self.last_cache_maintenance,
            },
        )

    def show_run(self, *_):
        if self.runs.currentData() is None:
            self.views["Investigation Workspace"].setPlainText(
                self.text(
                    "Nenhuma pesquisa contextual concluída. Escolha um projeto na página Scanner e execute a pesquisa.",
                    "No completed contextual research. Choose a project on the Scanner page and run research.",
                )
            )
            self.views["Code Flow Viewer"].clear()
            self.views["Git Intelligence"].clear()
            self.views["AI Investigator"].clear()
            return
        row = self.engine.db.query(
            "SELECT * FROM research_runs WHERE id=?", (self.runs.currentData(),)
        )[0]
        if row["status"] != "completed":
            self.display(
                "Investigation Workspace",
                {
                    "run": row["id"],
                    "status": row["status"],
                    "errors": json.loads(row["errors"]),
                    "interpretation": self.text(
                        "Esta pesquisa não foi concluída. Execute uma nova pesquisa; os arquivos já indexados podem ser reutilizados.",
                        "This research did not complete. Start a new research run; previously indexed files can be reused.",
                    ),
                },
            )
            for name in ("Code Flow Viewer", "Git Intelligence", "AI Investigator"):
                self.views[name].clear()
            return
        data = json.loads(row["data"])
        self.current_data = data
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
        self.display("Code Flow Viewer", data["graph"])
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
        if assistance:
            self.display("AI Investigator", json.loads(assistance[0]["data"]))
        else:
            self.views["AI Investigator"].setPlainText(
                self.text(
                    "Nenhuma investigação assistida registrada. Use Perguntas de revisão ou Investigar com Qwen.",
                    "No assistance recorded. Use Review questions or Investigate with Qwen.",
                )
            )
