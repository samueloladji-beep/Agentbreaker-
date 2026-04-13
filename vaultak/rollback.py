import os
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger("vaultak.rollback")


class FileSnapshot:
    """Manages file snapshots for rollback."""

    def __init__(self):
        self._snapshots: Dict[str, bytes] = {}

    def snapshot(self, path: str):
        """Save current file state before a write."""
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    self._snapshots[path] = f.read()
                logger.debug(f"Snapshot saved: {path}")
            except Exception as e:
                logger.warning(f"Could not snapshot {path}: {e}")
        else:
            self._snapshots[path] = None  # File did not exist

    def restore(self, path: str) -> bool:
        """Restore file to its snapshotted state."""
        if path not in self._snapshots:
            return False
        try:
            original = self._snapshots[path]
            if original is None:
                # File did not exist before — delete it
                if os.path.exists(path):
                    os.remove(path)
                    logger.info(f"Rollback: deleted {path} (did not exist before)")
            else:
                with open(path, "wb") as f:
                    f.write(original)
                logger.info(f"Rollback: restored {path}")
            return True
        except Exception as e:
            logger.error(f"Rollback failed for {path}: {e}")
            return False

    def restore_all(self):
        """Restore all snapshotted files."""
        results = []
        for path in list(self._snapshots.keys()):
            results.append((path, self.restore(path)))
        return results

    def clear(self):
        self._snapshots.clear()
