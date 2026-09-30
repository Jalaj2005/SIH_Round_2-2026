import random
import string
import sys
import tempfile
from pathlib import Path

from sentinel_dga import DGAConfig, DGADetector, split_domain

REQUIRED = ("alert_id", "timestamp", "severity", "threat_class", "confidence_score", "flow_identifier")


class Clock:
    t = 1000.0
    def __call__(self): return self.t


def rec(domain, src="10.0.0.5"):
    return {"record_type": "dns", "domain": domain, "src_ip": src, "dst_ip": "10.0.0.2"}


def rnd(rng, n=14):
    return "".join(rng.choices(string.ascii_lowercase, k=n))


def test_split_domain():
    assert split_domain("www.mail.google.com") == ("google", "com", "www.mail")
    assert split_domain("news.bbc.co.uk") == ("bbc", "co.uk", "news")
    assert split_domain("localhost") == ("localhost", "", "")


def test_benign_not_flagged_and_random_flagged():
    d = DGADetector()
    for name in ("wikipedia.org", "stackoverflow.com", "timesofindia.indiatimes.com", "microsoftonline.com", "mail.zoho.in"):
        assert d.process_dns(rec(name)) is None, name
    a = DGADetector().process_dns(rec("xkqzvtwpmrbnhd.com"))
    assert a and all(k in a for k in REQUIRED) and a["threat_class"] == "DGA Domain"
    assert a["supporting_evidence"]["reasons"] and a["flow_identifier"]["src_ip"] == "10.0.0.5"


def test_skips():
    d = DGADetector()
    for name in ("1.0.0.10.in-addr.arpa", "printer.local", "_dns-sd._udp.example.org", "xn--80ak6aa92e.com",
                 "abc.com", "xkqzvtwpmrbnhd.cloudfront.net", "nodots"):
        assert d.process_dns(rec(name)) is None, name
    assert d.stats["skipped"] >= 6


def test_burst_raises_confidence_and_severity():
    clk, rng = Clock(), random.Random(5)
    d = DGADetector(clock=clk)
    first = d.process_dns(rec(rnd(rng) + ".net", "10.9.9.9"))
    last = None
    for _ in range(8):
        clk.t += 1
        last = d.process_dns(rec(rnd(rng) + ".net", "10.9.9.9")) or last
    assert last["confidence_score"] >= first["confidence_score"] and last["severity"] in ("HIGH", "CRITICAL")
    assert last["supporting_evidence"]["feature_attributions"]["host_burst"] == 1.0


def test_burst_window_expires_and_hosts_isolated():
    clk, rng = Clock(), random.Random(6)
    d = DGADetector(DGAConfig(burst_window_s=10), clock=clk)
    for _ in range(6):
        d.process_dns(rec(rnd(rng) + ".org", "10.1.1.1"))
    clk.t += 60
    a = d.process_dns(rec(rnd(rng) + ".org", "10.1.1.1"))
    assert a["supporting_evidence"]["feature_attributions"]["host_burst"] <= 0.2       # old queries aged out
    b = d.process_dns(rec(rnd(rng) + ".org", "10.2.2.2"))
    assert b["supporting_evidence"]["feature_attributions"]["host_burst"] <= 0.2       # other host unaffected


def test_dedupe_same_domain():
    clk = Clock(); d = DGADetector(clock=clk)
    assert d.process_dns(rec("xkqzvtwpmrbnhd.com")) is not None
    assert d.process_dns(rec("mail.xkqzvtwpmrbnhd.com")) is None       # same registered domain, same host
    clk.t += 400
    assert d.process_dns(rec("xkqzvtwpmrbnhd.com")) is not None


def test_train_and_load_model():
    from sentinel_dga import train
    rng, tmp = random.Random(2), Path(tempfile.mkdtemp())
    benign = ["wikipedia", "stackoverflow", "microsoftonline", "hindustantimes", "makemytrip", "zerodha", "cloudflare",
              "timesofindia", "digilocker", "flipkart", "notification", "wordpress", "shopping", "university", "travelport"]
    (tmp / "b.txt").write_text("\n".join(f"{b}{i % 3 or ''}.com" for i in range(300) for b in [benign[i % len(benign)]]))
    (tmp / "d.txt").write_text("\n".join(rnd(rng, rng.randint(9, 18)) + ".net" for _ in range(300)))
    train.main(["--benign", str(tmp / "b.txt"), "--dga", str(tmp / "d.txt"), "--out", str(tmp / "m.joblib")])
    d = DGADetector(model_path=tmp / "m.joblib")
    assert d.model is not None
    assert d.process_dns(rec("xkqzvtwpmrbnhd.com")) is not None
    assert d.process_dns(rec("stackoverflow.com")) is None
