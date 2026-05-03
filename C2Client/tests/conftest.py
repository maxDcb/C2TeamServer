import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ["C2_ENV_FILE"] = str(Path(__file__).resolve().parent / ".missing-test.env")
