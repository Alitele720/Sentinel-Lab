"""Shared runtime paths and in-memory state."""

from pathlib import Path
import threading


BASE_DIR = Path(__file__).resolve().parent.parent


class AppRuntime:
    """Centralize file paths and watcher state so tests can override them."""

    def __init__(self):
        self.base_dir = BASE_DIR
        self.data_dir = self.base_dir / "data"
        self.db_file = self.data_dir / "ids.db"
        self.log_file = self.data_dir / "access.log"
        self.bad_log_file = self.data_dir / "access.bad.log"
        self.log_offset = 0
        self.watcher_thread = None
        self.portscan_capture_thread = None
        self.portscan_capture_stop_event = threading.Event()
        self.watcher_lock = threading.Lock()
        self.portscan_capture_lock = threading.Lock()
        self.log_ingest_lock = threading.Lock()

    def configure(self, *, base_dir=None, data_dir=None, db_file=None, log_file=None, bad_log_file=None):
        """Redirect runtime files for tests without changing import paths."""
        if base_dir is not None:
            self.base_dir = Path(base_dir)
        if data_dir is not None:
            self.data_dir = Path(data_dir)
        elif base_dir is not None:
            self.data_dir = self.base_dir / "data"

        self.db_file = Path(db_file) if db_file is not None else self.data_dir / "ids.db"
        self.log_file = Path(log_file) if log_file is not None else self.data_dir / "access.log"
        self.bad_log_file = Path(bad_log_file) if bad_log_file is not None else self.data_dir / "access.bad.log"
        self.reset_ingest_state()

    def reset_ingest_state(self):
        """Reset the log cursor so ingestion starts from the beginning."""
        self.log_offset = 0


runtime = AppRuntime()
