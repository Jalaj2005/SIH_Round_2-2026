"""Synthetic traffic generator with ground truth (for testing / throughput demos).
Mixes: random web browsing, benign periodic pollers (NTP, update checks),
and infected hosts beaconing with jitter/dropped beats."""
from __future__ import annotations
import random
from typing import List, Set, Tuple
from .schema import Flow


def generate(duration=3600.0, n_hosts=300, n_infected=8, seed=7,
             browse_rate=0.05, t0=1_780_000_000.0) -> Tuple[List[Flow], Set[Tuple[str, str]]]:
    rnd = random.Random(seed)
    hosts = [f"10.0.{i // 250}.{i % 250 + 1}" for i in range(n_hosts)]
    web = [f"203.0.{i // 250}.{i % 250 + 1}" for i in range(600)]
    flows: List[Flow] = []
    truth: Set[Tuple[str, str]] = set()

    for h in hosts:                                   # benign browsing (Poisson)
        t = t0 + rnd.random() * 5
        while t < t0 + duration:
            t += rnd.expovariate(browse_rate)
            flows.append(Flow(t, h, rnd.choice(web), rnd.choice((80, 443, 443, 443)),
                              "TCP", rnd.randint(20000, 60000),
                              rnd.randint(300, 40000), rnd.randint(1000, 900000), rnd.randint(5, 400)))
    for h in hosts:                                   # NTP: periodic but popular dst
        t = t0 + rnd.random() * 64
        while t < t0 + duration:
            flows.append(Flow(t, h, "198.51.100.10", 123, "UDP", 123, 76, 76, 2))
            t += 64 + rnd.uniform(-1, 1)
    for h in rnd.sample(hosts, min(60, n_hosts)):     # update checks: periodic, popular dst
        t = t0 + rnd.random() * 600
        while t < t0 + duration:
            flows.append(Flow(t, h, "198.51.100.77", 443, "TCP", rnd.randint(30000, 60000),
                              rnd.randint(400, 500), rnd.randint(2000, 9000), 12))
            t += 600 + rnd.uniform(-30, 30)

    infected = rnd.sample(hosts, n_infected)          # C2 beacons
    for i, h in enumerate(infected):
        c2 = f"192.0.2.{10 + i}"
        period = rnd.choice((20, 30, 45, 60, 90, 120, 300))
        jitter = rnd.choice((0.0, 0.05, 0.1, 0.2))
        port = rnd.choice((443, 8080, 8443, 53))
        base = rnd.randint(150, 400)
        t = t0 + rnd.random() * period
        while t < t0 + duration:
            if rnd.random() > 0.05:                   # 5% beats missed
                flows.append(Flow(t, h, c2, port, "TCP", rnd.randint(30000, 60000),
                                  int(base * rnd.uniform(0.9, 1.1)), rnd.randint(100, 2000), 6))
            t += period * (1 + rnd.uniform(-jitter, jitter))
        truth.add((h, c2))

    flows.sort(key=lambda f: f.ts)
    return flows, truth
