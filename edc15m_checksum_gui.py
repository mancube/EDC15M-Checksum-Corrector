#!/usr/bin/env python3
"""
Graphical front end for the Bosch EDC15M "TDI V3.1" checksum corrector.

Same engine as edc15m_checksum.py, wrapped so a read can be dropped in, checked
and corrected in one place - what the original Windows tool did, minus the
dongle, the plugin DLLs and Windows itself.

    python3 edc15m_checksum_gui.py [file ...]

Needs PySide6 (Qt 6). The engine, edc15m_checksum.py, stays free of
dependencies and is what any script or batch job should use.
"""
import os
import sys

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor, QKeySequence, QPalette, QShortcut
from PySide6.QtWidgets import (QApplication, QButtonGroup, QFileDialog,
                               QHBoxLayout, QHeaderView, QLabel, QMainWindow,
                               QMessageBox, QPushButton, QRadioButton,
                               QTableView, QVBoxLayout, QWidget)

import edc15m_checksum as core

SIZES = (("256 kB full read", 0x40000), ("32 kB partial read", 0x8000))
SUFFIXES = (".bin", ".ori", ".mod", ".read")
OK_STATUS = ("OK", "corrected")


def human(n):
    return f"{n} B" if n < 1024 else f"{n // 1024} kB"


def size_kind(n):
    for label, size in SIZES:
        if n == size:
            return label
    return f"{n} bytes"


def expand(path):
    """A dropped folder contributes every file inside it."""
    if os.path.isdir(path):
        for root, _, names in os.walk(path):
            for name in sorted(names):
                yield os.path.join(root, name)
    elif os.path.isfile(path):
        yield path


def _contrast(a, b):
    """WCAG relative luminance contrast between two colours."""
    def lum(c):
        out = []
        for v in (c.red(), c.green(), c.blue()):
            v /= 255
            out.append(v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4)
        return 0.2126 * out[0] + 0.7152 * out[1] + 0.0722 * out[2]
    hi, lo = max(lum(a), lum(b)), min(lum(a), lum(b))
    return (hi + 0.05) / (lo + 0.05)


def row_colours():
    """Row colours that stay readable on whichever theme is active."""
    pal = QApplication.palette()
    bg = pal.color(QPalette.Base)          # rows are drawn on Base
    dark = bg.lightnessF() < 0.5
    muted = pal.color(QPalette.PlaceholderText)
    limit = pal.color(QPalette.Text)       # stop before it turns into body text
    while _contrast(muted, bg) < 4.5 and muted != limit:
        muted = muted.lighter(110) if dark else muted.darker(110)
    return (QColor("#5ec98c") if dark else QColor("#2f6f4f"),   # correct
            QColor("#f08080") if dark else QColor("#b03030"),   # wrong
            muted)                                                # no block


class ScanModel(QAbstractTableModel):
    """One row per file, holding the result of the last scan."""

    COLUMNS = ("File", "Size", "Read", "Checksum", "Stored", "Computed",
               "Status", "Output")
    FIELDS = ("file", "size", "kind", "offset", "stored", "computed", "status",
              "output")
    TOOLTIP = ("Read the ECU and keep the original somewhere safe.\n"
               "Only the checksum bytes are ever rewritten.")

    def __init__(self):
        super().__init__()
        self.paths = []
        self.rows = {}

    # -- Qt plumbing
    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.paths)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.COLUMNS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows.get(self.paths[index.row()])
        if row is None:
            return None
        if role in (Qt.DisplayRole, Qt.ForegroundRole, Qt.ToolTipRole):
            if role == Qt.ToolTipRole:
                return self.TOOLTIP if index.column() == 0 else None
            if role == Qt.ForegroundRole:
                ok, bad, muted = row_colours()
                return {"ok": ok, "bad": bad, "none": muted, "failed": bad}[row["tag"]]
            return row[self.FIELDS[index.column()]]
        if role == Qt.TextAlignmentRole and index.column() in (1, 3, 4, 5):
            return int(Qt.AlignRight | Qt.AlignVCenter)
        return None

    # -- content
    def add(self, path):
        path = os.path.abspath(path)
        if os.path.isfile(path) and path not in self.paths:
            self.paths.append(path)
            self.rows.pop(path, None)
            self.layoutChanged.emit()
            return True
        return False

    def add_paths(self, paths):
        added = 0
        for p in paths:
            for path in expand(p):
                added += self.add(path)
        if added:
            self.layoutChanged.emit()
        return added

    def remove(self, paths):
        keep = [p for p in self.paths if p not in set(paths)]
        if len(keep) != len(self.paths):
            self.layoutChanged.emit()
        self.paths = keep

    def scan(self, write=False, only=None, out=None):
        """Recompute every row. With write=True the wrong ones are corrected."""
        ok = bad = missing = failed = 0
        for path in self.paths:
            row = self._scan_one(path, write, only, out)
            self.rows[path] = row
            ok += row["tag"] == "ok"
            bad += row["tag"] == "bad"
            missing += row["tag"] == "none"
            failed += row["tag"] == "failed"
        self.layoutChanged.emit()
        return ok, bad, missing, failed

    def _scan_one(self, path, write, only, out):
        base = {"file": path, "size": "", "kind": "", "offset": "", "stored": "",
                "computed": "", "status": "", "output": "", "tag": "none"}
        try:
            buf = bytearray(open(path, "rb").read())
        except OSError as e:
            base.update(status=f"cannot read: {e.strerror}", tag="failed")
            return base

        base["size"], base["kind"] = human(len(buf)), size_kind(len(buf))
        blocks = core.analyse(buf)
        if not blocks:
            base["status"] = "no checksum block found"
            return base

        b = next((x for x in blocks if x["stored"] != x["computed"]), blocks[0])
        base["offset"] = f"0x{b['pos']:06X}" + (
            f"  (+{len(blocks) - 1} more)" if len(blocks) > 1 else "")
        base["stored"] = f"{b['stored']:08X}"
        base["computed"] = f"{b['computed']:08X}"

        good = all(x["stored"] == x["computed"] for x in blocks)
        if good:
            base.update(status="OK", tag="ok")
        elif not (write and (only is None or path in only)):
            base.update(status="wrong", tag="bad")
        else:
            core.process(buf, fix=True)
            dest = path if out == "inplace" else _beside(path)
            try:
                open(dest, "wb").write(buf)
            except OSError as e:
                base.update(status=f"write failed: {e.strerror}", tag="failed")
                return base
            base.update(status="corrected", output=dest, tag="ok")
        return base

    def summary(self):
        counts = {"ok": 0, "bad": 0, "none": 0, "failed": 0}
        for path in self.paths:
            counts[self.rows.get(path, {}).get("tag", "none")] += 1
        parts = [f"{len(self.paths)} file(s)", f"{counts['ok']} correct"]
        if counts["bad"]:
            parts.append(f"{counts['bad']} need correcting")
        if counts["none"]:
            parts.append(f"{counts['none']} without a checksum block")
        if counts["failed"]:
            parts.append(f"{counts['failed']} failed")
        return "   |   ".join(parts)


def _beside(path):
    base, ext = os.path.splitext(path)
    return (base + ".fixed" + ext) if ext else base + ".fixed.bin"


class Window(QMainWindow):
    def __init__(self, argv):
        super().__init__()
        self.setWindowTitle("EDC15M checksum corrector - Bosch TDI V3.1")
        self.resize(1180, 600)
        self.setAcceptDrops(True)

        self.model = ScanModel()

        body = QWidget()
        self.setCentralWidget(body)
        outer = QVBoxLayout(body)
        outer.setContentsMargins(10, 10, 10, 6)
        outer.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(6)
        for text, slot in (("Add files...", self.pick), ("Remove", self.remove),
                           ("Clear", self.clear)):
            b = QPushButton(text)
            b.clicked.connect(slot)
            top.addWidget(b)
        top.addSpacing(20)
        top.addWidget(QLabel("Output:"))
        self._out = {}
        group = QButtonGroup(self)
        for text, value in (("beside the file (.fixed.bin)", "beside"),
                            ("overwrite in place", "inplace")):
            rb = QRadioButton(text)
            rb.setChecked(value == "beside")
            group.addButton(rb)
            self._out[value] = rb
            top.addWidget(rb)
        top.addStretch()
        outer.addLayout(top)

        self.table = QTableView()
        self.table.setModel(self.model)
        # leave drops to the window: a child that accepts them would swallow
        # everything that lands on the table
        self.table.setAcceptDrops(False)
        self.table.viewport().setAcceptDrops(False)
        self.table.setDragDropMode(QTableView.NoDragDrop)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        head = self.table.horizontalHeader()
        head.setSectionResizeMode(QHeaderView.Interactive)
        head.setSectionResizeMode(0, QHeaderView.Stretch)
        for c in range(1, self.model.columnCount()):
            head.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        outer.addWidget(self.table, 1)

        bottom = QHBoxLayout()
        check = QPushButton("Check checksums")
        check.clicked.connect(self.check)
        correct = QPushButton("Correct checksums")
        correct.setStyleSheet("background:#2f6f4f;color:white;padding:4px")
        correct.clicked.connect(self.correct)
        bottom.addWidget(check)
        bottom.addWidget(correct)
        bottom.addStretch()
        bottom.addWidget(QLabel("Select rows to limit an action to those files."))
        outer.addLayout(bottom)

        self.statusBar().showMessage("Ready")
        QShortcut(QKeySequence.Open, self, self.pick)
        QShortcut(QKeySequence.Delete, self, self.remove)
        QApplication.instance().paletteChanged.connect(self.theme_changed)

        self.model.add_paths(argv)
        self.refresh()

    def theme_changed(self):
        """Repaint the rows when the desktop switches light/dark."""
        self.model.layoutChanged.emit()

    # ------------------------------------------------------------- actions
    @property
    def out_mode(self):
        return "inplace" if self._out["inplace"].isChecked() else "beside"

    def refresh(self):
        self.model.scan(out=self.out_mode)
        self.statusBar().showMessage(self.model.summary())

    def selected(self):
        rows = {i.row() for i in self.table.selectionModel().selectedRows()}
        return [self.model.paths[r] for r in sorted(rows)]

    def targets(self):
        return self.selected() or list(self.model.paths)

    def pick(self):
        patterns = " ".join(f"*{s}" for s in SUFFIXES)
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select EDC15M read files", "",
            f"Firmware reads ({patterns});;All files (*)")
        if self.model.add_paths(paths):
            self.refresh()

    def remove(self):
        self.model.remove(self.selected())
        self.refresh()

    def clear(self):
        self.model.paths.clear()
        self.model.rows.clear()
        self.model.layoutChanged.emit()
        self.refresh()

    def check(self):
        self.model.scan(out=self.out_mode)
        self.statusBar().showMessage(self.model.summary())

    def correct(self):
        if self.out_mode == "inplace" and QMessageBox.warning(
                self, "Overwrite in place",
                "This rewrites the original files and cannot be undone.\n\n"
                "Continue?", QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No) != QMessageBox.Yes:
            return
        self.model.scan(write=True, only=set(self.targets()), out=self.out_mode)
        self.statusBar().showMessage(self.model.summary())

    # ------------------------------------------------------------ drag/drop
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
        if self.model.add_paths(paths):
            self.refresh()
        event.acceptProposedAction()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Window(sys.argv[1:])
    win.show()
    sys.exit(app.exec())