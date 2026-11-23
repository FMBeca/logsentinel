import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_access_log_matches_its_generator(tmp_path):
    # If samples/access.log is edited by hand, or the generator changes without
    # regenerating the sample, the two drift apart and this test fails.
    out = tmp_path / "access.log"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "gen_access_log.py"), str(out)], check=True)
    expected = (ROOT / "samples" / "access.log").read_text(encoding="utf-8")
    assert out.read_text(encoding="utf-8") == expected
