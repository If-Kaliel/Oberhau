"""Render the vector brand for visual review and Windows executable icons."""

import struct
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QRectF
from PySide6.QtGui import QColor, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

ROOT = Path(__file__).resolve().parents[1]
SVG = ROOT / "src/oberhau/assets/emblem.svg"


def image(size):
    renderer = QSvgRenderer(str(SVG))
    if not renderer.isValid():
        raise RuntimeError("Invalid brand SVG")
    canvas = QImage(size, size, QImage.Format.Format_ARGB32)
    canvas.fill(QColor("transparent"))
    painter = QPainter(canvas)
    renderer.render(painter, QRectF(0, 0, size, size))
    painter.end()
    return canvas


def windows_icon(destination):
    entries, payloads = [], []
    sizes = [16, 24, 32, 48, 64, 128, 256]
    offset = 6 + 16 * len(sizes)
    for size in sizes:
        data = QByteArray()
        buffer = QBuffer(data)
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        if not image(size).save(buffer, "PNG"):
            raise RuntimeError("Unable to render executable icon")
        payload = bytes(data)
        entries.append(
            struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(payload), offset)
        )
        payloads.append(payload)
        offset += len(payload)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(struct.pack("<HHH", 0, 1, len(sizes)) + b"".join(entries + payloads))


def preview():
    destination = ROOT / "artifacts"
    destination.mkdir(exist_ok=True)
    image(384).save(str(destination / "oberhau-logo.png"))
    canvas = QImage(576, 224, QImage.Format.Format_ARGB32)
    canvas.fill(QColor("#141518"))
    painter = QPainter(canvas)
    painter.fillRect(288, 0, 288, 224, QColor("#f4f3ef"))
    for origin in [0, 288]:
        for size, x in [(32, 24), (48, 76), (96, 156)]:
            painter.drawImage(origin + x, (224 - size) // 2, image(size))
    painter.end()
    canvas.save(str(destination / "oberhau-logo-sizes.png"))


if __name__ == "__main__":
    windows_icon(ROOT / "build/emblem.ico")
    preview()
