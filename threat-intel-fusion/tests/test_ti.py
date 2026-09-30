from sentinel_ti import Fusion, IoCStore, TIEngine
from sentinel_ti.engine import domain_candidates


class Clock:
    t = 0.0
    def __call__(self): return self.t


def make(clock=None):
    s = IoCStore()
    s.bulk_add([("ip", "198.51.100.89", "C2", 0.98, "t"), ("domain", "evil.example", "C2 domain", 0.95, "t"),
                ("ja3", "abc123", "Malware", 0.6, "t"), ("ip", "203.0.113.50", "Scanner", 0.6, "t")])
    return s, TIEngine(s, pos_ttl=100, neg_ttl=10, clock=clock or Clock())


def test_positive_and_negative_cache():
    s, e = make()
    assert e.lookup("ip", "198.51.100.89") == (s.get("ip", "198.51.100.89"), False)   # disk
    assert e.lookup("ip", "198.51.100.89")[1] is True                                  # positive hit
    assert e.lookup("domain", "clean.example") == (None, False)
    assert e.lookup("domain", "clean.example") == (None, True)                         # negative hit
    assert e.stats() == {"hits": 1, "misses": 2, "negative_hits": 1}


def test_negative_ttl_expiry_and_flush():
    clk = Clock(); s, e = make(clk)
    e.lookup("domain", "new.example")
    s.bulk_add([("domain", "new.example", "C2", 0.9, "t")])
    assert e.lookup("domain", "new.example")[0] is None          # stale negative entry hides the new IoC
    clk.t = 11
    assert e.lookup("domain", "new.example")[0] is not None      # short TTL lets it through
    s.bulk_add([("domain", "other.example", "C2", 0.9, "t")])
    e.lookup("domain", "other.example"); e.flush()
    assert e.lookup("domain", "other.example")[0] is not None


def test_domain_candidates_and_records():
    assert domain_candidates("a.b.evil.example") == ["a.b.evil.example", "b.evil.example", "evil.example"]
    s, e = make()
    v = e.check_record({"record_type": "dns", "domain": "x.evil.example"})
    assert v.matched and v.early_exit and v.matches[0]["value"] == "evil.example"
    assert not e.check_record({"record_type": "dns", "domain": "good.example"}).matched
    assert e.check_record({"record_type": "window"}).lookups == 0
    v = e.check_record({"record_type": "flow", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.6"})
    assert v.lookups == 0                                          # private IPs skipped


def test_two_indicator_kinds_force_early_exit():
    _, e = make()
    v = e.check_record({"record_type": "tls_hello", "ja3": "abc123", "dst_ip": "203.0.113.50"})
    assert len(v.matches) == 2 and v.early_exit                    # each is only 0.6 but two kinds agree
    v = e.check_record({"record_type": "tls_hello", "ja3": "abc123", "dst_ip": "8.8.8.8"})
    assert v.matched and not v.early_exit


ALERT = {"alert_id": "A1", "timestamp": "t", "severity": "MEDIUM", "threat_class": "Botnet C2 Beaconing",
         "confidence_score": 0.48, "flow_identifier": {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.50", "src_port": 1,
                                                       "dst_port": 443, "protocol": "TCP"},
         "supporting_evidence": {"primary_metric": "x", "feature_attributions": {}}, "system_telemetry": {},
         "threat_intelligence": {}}


def test_fusion_early_exit_and_dedupe():
    _, e = make(); f = Fusion()
    rec = {"record_type": "flow", "src_ip": "10.0.0.5", "dst_ip": "198.51.100.89", "dst_port": 443, "proto": "TCP"}
    a = f.observe(e.check_record(rec), rec)
    assert a["severity"] == "CRITICAL" and a["system_telemetry"]["path_taken"] == "EARLY_EXIT_TI_OVERRIDE"
    assert f.observe(e.check_record(rec), rec) is None            # rate-limited


def test_fusion_boosts_borderline_alert():
    _, e = make(); f = Fusion()
    rec = {"record_type": "flow", "src_ip": "10.0.0.5", "dst_ip": "203.0.113.50"}
    assert f.observe(e.check_record(rec), rec) is None            # 0.6 alone: no standalone alert
    out = f.fuse(ALERT)
    assert out["confidence_score"] >= 0.75 and out["severity"] in ("HIGH", "CRITICAL")
    assert out["threat_intelligence"]["ti_override_applied"] and out["system_telemetry"]["path_taken"] == "FUSION_TI_OVERRIDE"
    assert ALERT["confidence_score"] == 0.48                      # original untouched
    clean = {**ALERT, "flow_identifier": {**ALERT["flow_identifier"], "dst_ip": "9.9.9.9"}}
    assert f.fuse(clean) is clean
