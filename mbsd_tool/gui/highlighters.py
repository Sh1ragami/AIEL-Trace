from __future__ import annotations

from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PySide6.QtCore import QRegularExpression


class HtmlHighlighter(QSyntaxHighlighter):
    def __init__(self, document) -> None:  # document: QTextDocument
        super().__init__(document)

        def fmt(color: str, bold: bool = False, italic: bool = False) -> QTextCharFormat:
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Weight.Bold)
            if italic:
                f.setFontItalic(True)
            return f

        self.formats = {
            'tag': fmt('#1565c0', bold=True),            # blue
            'attr': fmt('#6a1b9a'),                      # purple
            'value': fmt('#2e7d32'),                     # green
            'comment': fmt('#757575', italic=True),      # gray
            'entity': fmt('#00838f'),                    # teal
        }

        # Regex rules
        self.re_tag = QRegularExpression(r"</?\b([A-Za-z][A-Za-z0-9:-]*)\b")
        self.re_attr = QRegularExpression(r"\b([A-Za-z_:][A-Za-z0-9_\-:\.]*)\s*=\s*")
        self.re_value_dq = QRegularExpression(r'"[^"\\]*(?:\\.[^"\\]*)*"')
        self.re_value_sq = QRegularExpression(r"'[^'\\]*(?:\\.[^'\\]*)*'")
        self.re_entity = QRegularExpression(r"&[A-Za-z#0-9]+;")

        # Multiline comment handling
        self.re_comment_start = QRegularExpression(r"<!--")
        self.re_comment_end = QRegularExpression(r"-->")

    def highlightBlock(self, text: str) -> None:  # type: ignore[override]
        # Handle multi-line comments
        state = self.previousBlockState()
        start = 0
        if state == 1:
            # In comment
            end_match = self.re_comment_end.match(text)
            if end_match.hasMatch():
                end = end_match.capturedEnd()
                self.setFormat(0, end, self.formats['comment'])
                start = end
                self.setCurrentBlockState(0)
            else:
                self.setFormat(0, len(text), self.formats['comment'])
                self.setCurrentBlockState(1)
                return

        # Find comments starting from 'start'
        i = start
        while i < len(text):
            m = self.re_comment_start.match(text, i)
            if not m.hasMatch():
                break
            s = m.capturedStart()
            e_match = self.re_comment_end.match(text, m.capturedEnd())
            if e_match.hasMatch():
                e = e_match.capturedEnd()
                self.setFormat(s, e - s, self.formats['comment'])
                i = e
            else:
                self.setFormat(s, len(text) - s, self.formats['comment'])
                self.setCurrentBlockState(1)
                return

        # Tags
        it = self.re_tag.globalMatch(text)
        while it.hasNext():
            m = it.next()
            self.setFormat(m.capturedStart(), m.capturedLength(), self.formats['tag'])

        # Attributes (name=) and values within the line
        it = self.re_attr.globalMatch(text)
        while it.hasNext():
            m = it.next()
            self.setFormat(m.capturedStart(1), m.capturedLength(1), self.formats['attr'])

        for rx in (self.re_value_dq, self.re_value_sq):
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), self.formats['value'])

        # Entities
        it = self.re_entity.globalMatch(text)
        while it.hasNext():
            m = it.next()
            self.setFormat(m.capturedStart(), m.capturedLength(), self.formats['entity'])
