"""Incremental JSON Lines writer. Each batch is flushed (and fsynced) so a crash loses at most one batch."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from ..models import NetworkEvent


class JsonlEventStore:
    def __init__(self, path: Path, *, fsync: bool = True) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a", encoding="utf-8", newline="\n")
        self._fsync = fsync
        self.count = 0

    def append_events(self, events: Iterable[NetworkEvent]) -> None:
        n = 0
        for ev in events:
            self._fh.write(ev.model_dump_json() + "\n")
            n += 1
        self._fh.flush()
        if self._fsync:
            os.fsync(self._fh.fileno())
        self.count += n

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.flush()
            self._fh.close()
