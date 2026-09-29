from pathlib import Path

from fastapi.testclient import TestClient

from lab_agent.web import create_app


def test_dashboard_loads_without_assignments(tmp_path: Path) -> None:
    response = TestClient(create_app(tmp_path)).get("/")
    assert response.status_code == 200
    assert "Lab Agent" in response.text
