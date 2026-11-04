from pathlib import Path

import pytest

from advisory_map.config import Settings, parse_duration


@pytest.mark.parametrize("text, seconds", [("90s", 90), ("15m", 900), ("24h", 86400), ("1d", 86400), (" 2h ", 7200)])
def test_parse_duration(text: str, seconds: int) -> None:
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "15", "1.5h", "1w", "h"])
def test_parse_duration_rejects(text: str) -> None:
    with pytest.raises(ValueError):
        parse_duration(text)


def test_defaults() -> None:
    settings = Settings.from_env({"PROMETHEUS_URL": "http://prometheus:9090/"})
    assert settings.prometheus_url == "http://prometheus:9090"
    assert settings.data_dir == Path("/data")
    assert settings.match_interval == 900
    assert settings.refresh_interval("debian") == 86400
    assert settings.mapping_file is None
    assert settings.cvelist_url == "https://github.com/CVEProject/cvelistV5.git"


def test_cvelist_mirror() -> None:
    settings = Settings.from_env({"PROMETHEUS_URL": "http://prometheus:9090", "CVELIST_URL": "https://mirror/cvelist"})
    assert settings.cvelist_url == "https://mirror/cvelist"


def test_per_feed_refresh() -> None:
    settings = Settings.from_env(
        {"PROMETHEUS_URL": "http://prometheus:9090", "FEED_REFRESH": "12h", "FEED_REFRESH_KEV": "1h"}
    )
    assert settings.refresh_interval("kev") == 3600
    assert settings.refresh_interval("debian") == 43200


def test_prometheus_url_is_required() -> None:
    with pytest.raises(ValueError, match="PROMETHEUS_URL"):
        Settings.from_env({})
