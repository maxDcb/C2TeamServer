from PyQt6.QtCore import QThread

from C2Client.refresh_worker import RefreshWorker


def test_refresh_worker_recovers_after_failed_fetch(qtbot):
    calls = 0

    def fetch():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("server unavailable")
        return ["restored"]

    thread = QThread()
    worker = RefreshWorker(fetch, 100)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    failures = []
    snapshots = []
    worker.failed.connect(failures.append)
    worker.ready.connect(snapshots.append)

    thread.start()
    try:
        qtbot.waitUntil(lambda: bool(snapshots), timeout=2000)
        assert failures == ["server unavailable"]
        assert snapshots[0] == ["restored"]
    finally:
        worker.quit()
        thread.quit()
        assert thread.wait(2000)
