from sentinel_dns_tunnel import DNSTunnelConfig, DNSTunnelDetector


def _query(index, source="10.0.0.1", domain="t.evil-tunnel.com", timestamp=None, **extra):
    label = f"{index:02x}" + "abcdef0123456789" * 3
    return {
        "record_type": "dns",
        "domain": f"{label}.{domain}",
        "src_ip": source,
        "dst_ip": "10.0.0.53",
        "src_port": 53000 + index,
        "dst_port": 53,
        "protocol": "UDP",
        "ts": 1000 + index * 0.1 if timestamp is None else timestamp,
        "is_txt_null": True,
        **extra,
    }


def test_detects_long_unique_steady_txt_subdomains():
    detector = DNSTunnelDetector()
    alert = None
    for index in range(12):
        alert = detector.process_dns(_query(index)) or alert

    assert alert is not None
    assert alert["threat_class"] == "DNS Tunnelling"
    assert alert["confidence_score"] >= 0.65
    assert alert["supporting_evidence"]["feature_attributions"]["unique_subdomain_ratio"] == 1.0


def test_ignores_short_normal_subdomains():
    detector = DNSTunnelDetector()
    for index in range(20):
        assert detector.process_dns({
            "domain": f"cdn{index}.popular.example",
            "src_ip": "10.0.0.1",
            "ts": 1000 + index * 0.1,
        }) is None
    assert detector.stats["alerts"] == 0


def test_popular_domain_confidence_is_reduced():
    detector = DNSTunnelDetector(DNSTunnelConfig(
        min_confidence=0.1,
        popular_source_threshold=2,
        cooldown_seconds=0,
    ))
    first_alert = None
    for index in range(10):
        first_alert = detector.process_dns(_query(
            index,
            domain="t.popular.example",
        )) or first_alert

    detector.process_dns({
        "domain": "www.popular.example",
        "src_ip": "10.0.0.2",
        "ts": 1000.0,
    })
    second_alert = None
    for index in range(10):
        second_alert = detector.process_dns(_query(
            index,
            source="10.0.0.2",
            domain="t.popular.example",
        )) or second_alert

    assert first_alert is not None and second_alert is not None
    assert second_alert["confidence_score"] < first_alert["confidence_score"]