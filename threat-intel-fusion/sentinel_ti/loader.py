"""Offline IoC import.   python -m sentinel_ti.loader iocs.csv --db data/iocs.db
CSV header: kind,value,category,confidence,source   (kind = ip | domain | ja3 | ja4)"""
import argparse
import csv

from sentinel_ti.engine import TIEngine
from sentinel_ti.ioc_store import IoCStore


def load_csv(path: str, store: IoCStore, engine: TIEngine | None = None) -> int:
    with open(path, newline="", encoding="utf-8") as fh:
        rows = [(r["kind"].strip().lower(), r["value"], r.get("category") or "unknown",
                 r.get("confidence") or 0.9, r.get("source") or path) for r in csv.DictReader(fh)]
    n = store.bulk_add(rows)
    if engine:
        engine.flush()          # new intel must take effect immediately
    return n


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--db", default="data/iocs.db")
    a = ap.parse_args()
    store = IoCStore(a.db)
    print(f"imported {load_csv(a.csv, store)} IoCs; database now holds {store.count()}")
