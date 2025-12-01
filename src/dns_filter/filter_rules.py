import threading
from pathlib import Path
from typing import List


class FilterRules:
    """Load and check blocked domains from a plaintext file.

    Supports exact matches and suffix matches using leading '*.' in the list.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._exact: set[str] = set()
        self._suffix: set[str] = set()
        self.reload()

    def reload(self) -> None:
        """Reload rules from file."""
        exact = set()
        suffix = set()
        if not self.path.exists():
            with self._lock:
                self._exact = exact
                self._suffix = suffix
            return

        for line in self.path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith("*."):
                suffix.add(s[2:].lower())
            else:
                exact.add(s.lower())

        with self._lock:
            self._exact = exact
            self._suffix = suffix

    def add(self, domain: str) -> None:
        domain = domain.strip().lower()
        if not domain:
            return
        with self._lock:
            if domain.startswith("*."):
                self._suffix.add(domain[2:])
            else:
                self._exact.add(domain)
        self._persist()

    def remove(self, domain: str) -> None:
        domain = domain.strip().lower()
        with self._lock:
            if domain.startswith("*."):
                self._suffix.discard(domain[2:])
            else:
                self._exact.discard(domain)
        self._persist()

    def _persist(self) -> None:
        lines: List[str] = []
        with self._lock:
            for d in sorted(self._exact):
                lines.append(d)
            for s in sorted(self._suffix):
                lines.append(f"*.{s}")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def is_blocked(self, qname: str) -> bool:
        """Check whether `qname` should be blocked.

        Matches exact names and suffix entries (e.g. `*.example` blocks `a.example`).
        """
        n = qname.rstrip(".").lower()
        with self._lock:
            if n in self._exact:
                return True
            # check suffixes
            for s in self._suffix:
                if n == s or n.endswith("." + s):
                    return True
        return False


__all__ = ["FilterRules"]
