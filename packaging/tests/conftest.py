from pathlib import Path
import sys


PACKAGING_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGING_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGING_ROOT))

