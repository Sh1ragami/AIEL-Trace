from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Generic, TypeVar

from PySide6.QtCore import QObject, QRunnable, Signal, Slot


T = TypeVar("T")


class WorkerSignals(QObject):
    result = Signal(object)
    error = Signal(str)
    progress = Signal(object)


class FunctionWorker(QRunnable, Generic[T]):
    def __init__(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:
        try:
            result = self.fn(self.signals.progress.emit, *self.args, **self.kwargs)
            self.signals.result.emit(result)
        except Exception as e:  # pragma: no cover - surface errors to UI
            self.signals.error.emit(str(e))

