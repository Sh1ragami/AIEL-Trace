from __future__ import annotations

from PySide6.QtWidgets import QWidget, QStyle
from PySide6.QtGui import QIcon, QPixmap, QPainter, QColor


def std_icon(widget: QWidget, sp: QStyle.StandardPixmap) -> QIcon:
    try:
        return widget.style().standardIcon(sp)
    except Exception:
        return QIcon()


def named_icon(widget: QWidget, name: str) -> QIcon:
    s = widget.style()
    mp = QStyle.StandardPixmap
    mapping = {
        'search': mp.SP_FileDialogContentsView,   # closest available
        'scan': mp.SP_MediaPlay,
        'save': mp.SP_DialogSaveButton,
        'results': mp.SP_FileDialogDetailedView,
        'scan_tab': mp.SP_DialogOpenButton,
        'results_tab': mp.SP_FileDialogDetailedView,
        'info': mp.SP_MessageBoxInformation,
        'warn': mp.SP_MessageBoxWarning,
        'critical': mp.SP_MessageBoxCritical,
        'ok': mp.SP_DialogApplyButton,
    }
    sp = mapping.get(name)
    return s.standardIcon(sp) if sp is not None else QIcon()


def severity_icon(widget: QWidget, severity: str) -> QIcon:
    sev = (severity or '').strip()
    if sev == '高':
        return named_icon(widget, 'critical')
    if sev == '中':
        return named_icon(widget, 'warn')
    if sev == '低':
        return named_icon(widget, 'ok')
    return named_icon(widget, 'info')


def colored_dot(color_hex: str, size: int = 16) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(QColor(0, 0, 0, 0))
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setBrush(QColor(color_hex))
    p.setPen(QColor(0, 0, 0, 0))
    margin = max(1, size // 8)
    p.drawEllipse(margin, margin, size - 2 * margin, size - 2 * margin)
    p.end()
    return QIcon(pm)

