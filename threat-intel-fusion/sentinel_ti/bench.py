"""python -m sentinel_ti.bench   -> real lookup latency for the demo."""
import os
import random
import tempfile
import time

from sentinel_ti.engine import TIEngine
from sentinel_ti.ioc_store import IoCStore

N_IOC, N_LOOKUPS = 200_000, 300_000
path = os.path.join(tempfile.mkdtemp(), "iocs.db")
store = IoCStore(path)
store.bulk_add((("domain", f"bad{i}.example", "C2", 0.9, "bench") for i in range(N_IOC)))
eng = TIEngine(store)
bad = [f"bad{random.randrange(N_IOC)}.example" for _ in range(500)]
clean = [f"site{i}.example" for i in range(2000)]


def run(name, gen):
    t0 = time.perf_counter()
    for kind, v in gen:
        eng.lookup(kind, v)
    dt = time.perf_counter() - t0
    print(f"{name:<34} {dt / N_LOOKUPS * 1e6:8.2f} us/lookup   {N_LOOKUPS / dt:>10,.0f} /s")


run("cold (every lookup hits disk)", (("domain", f"uniq{i}.example") for i in range(N_LOOKUPS)))
eng.flush()
mix = random.choices(bad, k=N_LOOKUPS // 4) + random.choices(clean, k=N_LOOKUPS * 3 // 4)
random.shuffle(mix)
run("warm mix (25% bad / 75% clean)", (("domain", v) for v in mix))
print(f"IoC rows: {store.count():,}   cache stats: {eng.stats()}")
