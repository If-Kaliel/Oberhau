from pathlib import Path

import pytest

from oberhau.engine import ASSETS, Engine


@pytest.fixture
def engine(tmp_path: Path):
    return Engine(tmp_path / "data")


@pytest.fixture
def project(engine):
    return engine.ingestion.add(ASSETS / "demo", "DEMONSTRATION", demo=True)


@pytest.fixture
def scanned(engine, project):
    engine.scan(project, "quick")
    return project
