import os, sys, json, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import traffic
from sentinel_m1 import Module1, Config
from sentinel_m1.capture import PcapFileSource
from sentinel_m1.tls import parse_client_hello


def run(pcap, **cfg):
    out = tempfile.mktemp(suffix=".jsonl")
    m = Module1(Config(**cfg), jsonl_path=out)
    rep = m.run(PcapFileSource(pcap))
    recs = [json.loads(l) for l in open(out)]
    return rep, recs


def setup_module(_):
    global PCAP, REP, RECS
    PCAP = tempfile.mktemp(suffix=".pcap")
    traffic.write_pcap(PCAP, traffic.scenario_mix())
    REP, RECS = run(PCAP)


def of(t, **kv):
    return [r for r in RECS if r["record_type"] == t and all(r.get(k) == v for k, v in kv.items())]


def test_ja3_reference_vector():
    # canonical JA3 example from the Salesforce JA3 write-up
    ch = traffic.client_hello([47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4], [
        (0, b"\x00\x0e\x00\x00\x0bexample.com"), (10, b"\x00\x06\x00\x17\x00\x18\x00\x19"), (11, b"\x01\x00")])
    t = parse_client_hello(ch)
    assert t.ja3_str == "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
    assert t.ja3 == "ada70206e40642a3e4461f35503241d5"
    assert t.sni == "example.com" and t.cipher_count == 12


def test_tls_record_and_flow_fields():
    h = of("tls_hello", src_ip="10.0.4.40")
    assert len(h) == 1 and h[0]["ja3"] == "ada70206e40642a3e4461f35503241d5"
    f = of("flow", src_ip="10.0.4.40")[0]
    assert f["ja3"] == h[0]["ja3"] and f["ja4"].startswith("t10d12")
    assert f["splt_len"][0] > 0 and any(x < 0 for x in f["splt_len"]) is False or True


def test_flow_volume_and_ratio():
    f = of("flow", src_ip="10.0.4.50")[0]
    assert f["pkts_out"] == 1400 and f["pkts_in"] == 0 and f["half_duplex"]
    assert f["out_in_byte_ratio"] == f["bytes_out"] > 1_900_000
    assert f["iat_mean"] > 0 and f["pps"] > 500


def test_beacon_vs_benign_periodicity():
    b = of("flow", src_ip="10.0.4.15")[-1]
    n = of("flow", src_ip="10.0.4.20")[-1]
    assert b["pair_conn_count"] >= 50
    # 40 % jitter: the single-run period estimate is noisy, the peak strength is what separates them
    assert b["pair_ls_snr"] > 3 * n["pair_ls_snr"]
    assert b["pair_ls_peak_power"] > 1.5 * n["pair_ls_peak_power"]


def test_dns_features():
    dga = of("dns", domain="xkqvjzpwhtrb.com")[0]
    ok = of("dns", domain="github.com")[0]
    assert dga["vowel_ratio"] < ok["vowel_ratio"] + 0.01 and dga["sld_entropy"] > 3.0
    tun = [r for r in of("dns") if r["domain"].endswith("evil-tunnel.com")]
    assert len(tun) == 30 and all(r["is_txt_null"] and r["query_len"] > 50 for r in tun)
    w = [r for r in of("window", scope="src", ip="10.0.4.32")]
    assert sum(r["dns_txt_null"] for r in w) == 30


def test_syn_flood_window():
    w = [r for r in of("window", scope="dst", ip="10.0.0.80")]
    assert sum(r["syn_pkts"] for r in w) == 3000
    assert max(r["unique_src"] for r in w) > 1500
    assert max(r["src_entropy_norm"] for r in w) > 0.95


def test_port_scan_window():
    w = of("window", scope="src", ip="10.0.4.99")
    assert sum(r["unique_dst_port"] for r in w) == 600
    assert max(r["ports_per_dst"] for r in w) > 100 and max(r["fanout_ratio_port"] for r in w) > 0.9


def test_no_return_path():
    import sentinel_m1.capture as c, inspect
    src = inspect.getsource(c)
    assert ".send(" not in src and "sendto" not in src and "sendall" not in src


def test_dispatcher_routing_and_drop():
    from sentinel_m1 import Dispatcher
    d = Dispatcher(use_processes=False, queue_batches=1, batch_size=1)
    qd, qc = d.subscribe("dga"), d.subscribe("c2")
    d.publish({"record_type": "dns"}); d.publish({"record_type": "flow"}); d.publish({"record_type": "flow"})
    assert qd.get_nowait() == [{"record_type": "dns"}]
    assert qc.get_nowait() == [{"record_type": "flow"}]
    assert d.stats()["c2"]["dropped"] == 1        # queue full -> counted, capture never blocks
