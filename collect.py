#!/usr/bin/env python3
"""Collect one scan round's outputs into feed.jsonl (dedup + GoPlus enrich).

Reads factory_out.json / registry_out.json (stdout JSON of the two scanners),
appends one JSON line per NEW item to feed.jsonl:
  {"ts":..., "src":"factory"|"registry", "kind":..., "ca":..., ...scanner fields...,
   "goplus": {honeypot, open_source, buy_tax, sell_tax} | null}
Dedup: full CA against every CA already in feed.jsonl (same rule as the main
watch state file). GoPlus is a free keyless API; failures degrade to null.
"""
import json
import os
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FEED = os.path.join(HERE, "feed.jsonl")


def goplus(ca):
    url = ("https://api.gopluslabs.io/api/v1/token_security/56"
           f"?contract_addresses={ca}")
    try:
        out = subprocess.run(["curl", "-s", "-m", "20", url],
                             capture_output=True, text=True).stdout
        r = (json.loads(out).get("result") or {}).get(ca.lower()) or {}
        if not r:
            return None
        return {
            "is_honeypot": r.get("is_honeypot"),
            "is_open_source": r.get("is_open_source"),
            "buy_tax": r.get("buy_tax"),
            "sell_tax": r.get("sell_tax"),
            "holder_count": r.get("holder_count"),
        }
    except Exception:
        return None


def load_seen():
    seen = set()
    if os.path.exists(FEED):
        with open(FEED) as f:
            for line in f:
                try:
                    seen.add((json.loads(line).get("ca") or "").lower())
                except Exception:
                    pass
    return seen


def main():
    ts = int(time.time())
    seen = load_seen()
    lines = []

    def emit(src, ca, extra):
        key = (ca or "").lower()
        if not key or key in seen:
            return
        seen.add(key)
        row = {"ts": ts, "src": src, "ca": ca}
        row.update(extra)
        row["goplus"] = goplus(ca)
        lines.append(row)

    if os.path.exists(os.path.join(HERE, "factory_out.json")):
        data = json.load(open(os.path.join(HERE, "factory_out.json")))
        for c in data.get("creations") or []:
            emit("factory", c.get("token") or c.get("contract") or c.get("address"),
                 {"kind": "factory_creation", "platform": c.get("platform"),
                  "name": c.get("name"), "symbol": c.get("symbol"),
                  "creator": c.get("creator"), "block": c.get("block")})

    if os.path.exists(os.path.join(HERE, "registry_out.json")):
        data = json.load(open(os.path.join(HERE, "registry_out.json")))
        for h in data.get("hits") or []:
            emit("registry", h.get("contract"),
                 {"kind": "registry_ref", "name": h.get("name"),
                  "symbol": h.get("symbol"), "creator": h.get("creator"),
                  "block": h.get("block"), "registries": h.get("registries")})

    if lines:
        with open(FEED, "a") as f:
            for row in lines:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps({"new_items": len(lines)}))


if __name__ == "__main__":
    main()
