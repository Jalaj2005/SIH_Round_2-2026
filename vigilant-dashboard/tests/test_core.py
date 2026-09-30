import json

import config
from core import mock_feed
from core.alert_store import AlertStore
from core.schema import flatten, validate_alert


def test_mock_alerts_match_schema():
    for _ in range(200):
        a = validate_alert(mock_feed.generate_alert())
        assert a is not None and a["severity"] in config.SEVERITY_ORDER
        assert 0 <= a["confidence_score"] <= 1
        flatten(a)


def test_sample_alert_valid():
    raw = json.loads((config.BASE_DIR / "data" / "sample_alert.json").read_text())
    assert validate_alert(raw)["alert_id"] == "ALT-20260929-1094"


def test_protocol_values_are_normalized_to_arrow_safe_strings():
    raw = mock_feed.generate_alert()
    raw["flow_identifier"]["protocol"] = 6

    alert = validate_alert(raw)

    assert alert["flow_identifier"]["protocol"] == "TCP"
    assert isinstance(flatten(alert)["proto"], str)


def test_rejects_malformed():
    assert validate_alert({"alert_id": "x"}) is None
    assert validate_alert("nope") is None


def test_file_tail(tmp_path, monkeypatch):
    p = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(config, "ALERTS_FILE", p)
    monkeypatch.setattr(config, "TELEMETRY_FILE", tmp_path / "t.json")
    store = AlertStore(mode="file")
    p.write_text(json.dumps(mock_feed.generate_alert()) + "\nnot json\n")
    store.poll()
    assert len(store.alerts) == 1 and store.rejected == 1
    with open(p, "a") as fh:
        fh.write(json.dumps(mock_feed.generate_alert()) + "\n")
    store.poll()
    assert len(store.alerts) == 2
