from pathlib import Path

import pytest

from lab_agent.tools.powershell import run_powershell


def test_arbitrary_powershell_requires_explicit_opt_in(tmp_path: Path) -> None:
    with pytest.raises(PermissionError, match="--allow-unsafe"):
        run_powershell(tmp_path, "Get-Location")
