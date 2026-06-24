import os
import threading


class FreezeWatcher(threading.Thread):
    """Background watcher for the freeze signal to trigger immediate lockout."""

    def __init__(self, check_path: str, interval: float = 1.0, callback=None):
        super().__init__(daemon=True, name="FreezeWatcher")
        self.check_path = check_path
        self.interval = interval
        self.callback = callback
        self._stop_event = threading.Event()
        self.is_frozen = False

    def run(self):
        while not self._stop_event.is_set():
            if os.path.exists(self.check_path):
                self.is_frozen = True
                if self.callback:
                    try:
                        self.callback()
                    except Exception:
                        pass
                break
            self._stop_event.wait(self.interval)

    def stop(self):
        self._stop_event.set()
