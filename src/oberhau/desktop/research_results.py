"""Readable, filterable research records with explicit optional technical JSON."""

from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from oberhau.desktop.i18n import translate


def prose(value, language="en"):
    """Plain text only: source/model strings are never interpreted as HTML."""
    if isinstance(value, dict):
        return "\n\n".join(
            f"{translate(key.replace('_', ' '), language)}\n{prose(item, language)}"
            for key, item in value.items()
        )
    if isinstance(value, list):
        return "\n".join("• " + prose(item, language) for item in value) or "—"
    return translate(str(value), language) if value is not None else "—"


class ResearchResults(QWidget):
    def __init__(self, page, name):
        super().__init__()
        self.page, self.name, self.raw = page, name, ""
        self.result = None
        self.rows, self.offset = [], 0
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.summary)
        bar = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText(
            page.text("Filtrar resultados ou arquivo", "Filter results or file")
        )
        self.filter.setAccessibleName(self.filter.placeholderText())
        bar.addWidget(self.filter, 1)
        self.technical = QCheckBox(page.text("JSON técnico", "Technical JSON"))
        bar.addWidget(self.technical)
        self.open = QPushButton(page.text("Ver código da evidência", "View evidence source"))
        self.open.clicked.connect(lambda: page.window.guard(self.open_selected))
        bar.addWidget(self.open)
        layout.addLayout(bar)
        pagination = QHBoxLayout()
        self.previous = QPushButton(page.text("Anterior", "Previous"))
        self.next = QPushButton(page.text("Próxima", "Next"))
        self.count = QLabel()
        self.previous.clicked.connect(lambda: self.turn(-200))
        self.next.clicked.connect(lambda: self.turn(200))
        pagination.addWidget(self.previous)
        pagination.addWidget(self.count, 1)
        pagination.addWidget(self.next)
        layout.addLayout(pagination)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(
            [
                page.text("Resultado", "Result"),
                page.text("Tipo / estado", "Type / status"),
                page.text("Arquivo / detalhe", "File / detail"),
                page.text("Confiança / medida", "Confidence / metric"),
            ]
        )
        self.tree.setRootIsDecorated(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.setAccessibleName(page.window.tr_label(name))
        self.tree.setColumnWidth(0, 260)
        self.tree.setColumnWidth(1, 170)
        self.tree.setColumnWidth(2, 240)
        split.addWidget(self.tree)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setAccessibleName(page.text("Detalhes e limitações", "Details and limitations"))
        split.addWidget(self.detail)
        split.setSizes([700, 350])
        layout.addWidget(split, 1)
        self.tree.currentItemChanged.connect(self.selected)
        self.tree.itemActivated.connect(lambda *_: page.window.guard(self.open_selected))
        self.filter.textChanged.connect(self.filter_rows)
        self.technical.toggled.connect(lambda _: self.selected())
        self.open.setEnabled(False)

    def row(self, columns, detail=None, node=None, parent=None):
        item = QTreeWidgetItem(parent or self.tree, [str(c) for c in columns])
        item.setData(0, Qt.ItemDataRole.UserRole, {"detail": detail, "node": node})
        for column in range(4):
            item.setToolTip(column, item.text(column))
        return item

    def render(self, result, rows, summary=""):
        self.result = result
        self.raw = json.dumps(result, indent=2, ensure_ascii=False)
        self.rows, self.offset = rows, 0
        self.summary.setText(summary)
        self.filter_rows()

    def turn(self, delta):
        self.offset = max(0, self.offset + delta)
        self.filter_rows(reset=False)

    def filter_rows(self, *_, reset=True):
        if reset:
            self.offset = 0
        text = self.filter.text().casefold().strip()
        matching = [
            row
            for row in self.rows
            if not text
            or text in " ".join(str(c) for c in row[0]).casefold()
            or any(text in " ".join(str(c) for c in child[0]).casefold() for child in row[3])
        ]
        self.tree.clear()
        for columns, detail, node, children in matching[self.offset : self.offset + 200]:
            item = self.row(columns, detail, node)
            for cols, child_detail, child_node in children:
                self.row(cols, child_detail, child_node, item)
        self.previous.setEnabled(self.offset > 0)
        self.next.setEnabled(self.offset + 200 < len(matching))
        start = self.offset + 1 if matching else 0
        self.count.setText(f"{start}–{min(self.offset + 200, len(matching))} / {len(matching)}")
        if self.tree.topLevelItemCount():
            self.tree.setCurrentItem(self.tree.topLevelItem(0))
        self.selected()

    def selected(self, *_):
        item = self.tree.currentItem()
        payload = item.data(0, Qt.ItemDataRole.UserRole) if item else {}
        self.open.setEnabled(bool(payload and payload.get("node")))
        self.detail.setPlainText(
            self.raw
            if self.technical.isChecked()
            else prose(
                payload.get("detail", self.result) if payload else self.result,
                self.page.window.language,
            )
        )

    def open_selected(self):
        item = self.tree.currentItem()
        payload = item.data(0, Qt.ItemDataRole.UserRole) if item else {}
        if payload and payload.get("node"):
            self.page.open_evidence(payload["node"])

    # Kept for QA/export consumers; visible default presentation is structured.
    def toPlainText(self):
        return self.raw

    def setPlainText(self, text):
        self.raw = text
        self.result = text
        self.rows, self.offset = [], 0
        self.tree.clear()
        self.summary.setText(text)
        self.detail.setPlainText(text)
        self.open.setEnabled(False)
        self.previous.setEnabled(False)
        self.next.setEnabled(False)
        self.count.setText("0 / 0")

    def clear(self):
        self.setPlainText("")
