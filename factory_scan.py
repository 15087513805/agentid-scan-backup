#!/usr/bin/env python3
"""Factory creation-event scanner for BSC launchpads (four.meme / flap / gang.fun).

Reads new token-creation events incrementally via eth_getLogs on a free public
RPC that actually serves getLogs (rpc-bsc.48.club, verified 2026-11-01).
Per-platform watermark lives in factory-scan-state.json next to this script.
Optional: --state <path> overrides the watermark file (used by the
factory_service.sh resident service with its own factory-service-state.json);
default behavior is unchanged.
Output: one JSON object on stdout {latestBlock, latestTimestamp, scannedTo,
creations[], errors{}, partial}. See playbook section 10 for event specs.
"""
import json
import os
import subprocess
import sys
import time

RPC = "https://rpc-bsc.48.club"
HERE = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(HERE, "factory-scan-state.json")
CHUNK = 2000
OVERLAP = 50
TIME_BUDGET_S = 420
FIRST_RUN_LOOKBACK = 2000

PLATFORMS = {
    "four.meme": {
        "address": "0x5c952063c7fc8610FFDB798152D69F0B9550762b",
        "topic": "0x396d5e902b675b032348d3d2e9517ee8f0c4a926603fbc075d3d282ff00cad20",
    },
    "flap": {
        "address": "0xe2cE6ab80874Fa9Fa2aAE65D277Dd6B8e65C9De0",
        "topic": "0x504e7f360b2e5fe33cbaaae4c593bc55305328341bf79009e43e0e3b7f699603",
    },
    "gang.fun": {
        "address": "0x15CFD2dc8278Fb87a1783ef42111618E20874365",
        "topic": "0xe57a519fe6a031fac5d360f4b8ce246c86dd280b40dc37b68c0a7cc7394ef9c0",
    },
}


def rpc(method, params, timeout=90):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    last_err = None
    for attempt in range(3):
        out = subprocess.run(
            ["curl", "-s", "-m", str(timeout), RPC, "-H", "Content-Type: application/json", "-d", payload],
            capture_output=True, text=True,
        ).stdout
        try:
            return json.loads(out)
        except Exception as e:  # empty / non-JSON response from a flaky endpoint: retry
            last_err = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"rpc {method} failed after retries: {last_err}")


def get_logs(address, topic, frm, to):
    """One getLogs call; on RPC timeout error, retry once with half the span."""
    spans = [(frm, to)]
    if to - frm >= 1000:
        mid = (frm + to) // 2
        spans = [(frm, mid), (mid + 1, to)]
    logs = []
    for a, b in spans:
        r = rpc("eth_getLogs", [{"address": address, "topics": [topic],
                                 "fromBlock": hex(a), "toBlock": hex(b)}])
        if "error" in r:
            if len(spans) == 1:
                r2 = rpc("eth_getLogs", [{"address": address, "topics": [topic],
                                          "fromBlock": hex(a), "toBlock": hex((a + b) // 2)}])
                if "error" in r2:
                    raise RuntimeError(str(r2["error"])[:120])
                logs.extend(r2["result"])
                r3 = rpc("eth_getLogs", [{"address": address, "topics": [topic],
                                          "fromBlock": hex((a + b) // 2 + 1), "toBlock": hex(b)}])
                if "error" in r3:
                    raise RuntimeError(str(r3["error"])[:120])
                logs.extend(r3["result"])
            else:
                raise RuntimeError(str(r["error"])[:120])
        else:
            logs.extend(r["result"])
    return logs


def dec_str(data, byte_off):
    off = byte_off * 2
    ln = int(data[off:off + 64], 16)
    return bytes.fromhex(data[off + 64:off + 64 + ln * 2]).decode("utf-8", "replace")


def word(data, i):
    return data[i * 64:(i + 1) * 64]


def addr_word(data, i):
    return "0x" + word(data, i)[24:64]


def decode(platform, log):
    block = int(log["blockNumber"], 16)
    tx = log["transactionHash"]
    if platform == "gang.fun":
        token = "0x" + log["topics"][1][-40:]
        creator = "0x" + log["topics"][2][-40:]
        d = log["data"][2:]
        name = dec_str(d, int(word(d, 0), 16))
        symbol = dec_str(d, int(word(d, 1), 16))
        return {"platform": platform, "token": token, "creator": creator,
                "name": name, "symbol": symbol, "block": block, "tx": tx}
    d = log["data"][2:]
    if platform == "four.meme":
        # creator, token, requestId, name, symbol, totalSupply, launchTime, launchFee
        return {"platform": platform, "token": addr_word(d, 1), "creator": addr_word(d, 0),
                "name": dec_str(d, int(word(d, 3), 16)), "symbol": dec_str(d, int(word(d, 4), 16)),
                "block": block, "tx": tx}
    if platform == "flap":
        # ts, creator, nonce, token, name, symbol, meta
        return {"platform": platform, "token": addr_word(d, 3), "creator": addr_word(d, 1),
                "name": dec_str(d, int(word(d, 4), 16)), "symbol": dec_str(d, int(word(d, 5), 16)),
                "block": block, "tx": tx}
    return None


def main():
    started = time.time()
    state_path = STATE_PATH
    argv = sys.argv[1:]
    if "--state" in argv:  # optional override (resident service); default unchanged
        i = argv.index("--state")
        if i + 1 < len(argv):
            state_path = argv[i + 1]
    state = {}
    if os.path.exists(state_path):
        try:
            state = json.load(open(state_path))
        except Exception:
            state = {}
    head = rpc("eth_blockNumber", [])
    latest = int(head["result"], 16)
    try:
        blk = rpc("eth_getBlockByNumber", [hex(latest), False])
        latest_ts = int(blk["result"]["timestamp"], 16)
    except Exception:
        latest_ts = None  # informational only; never block the scan on it

    creations, errors, scanned_to = [], {}, {}
    partial = False
    for name, cfg in PLATFORMS.items():
        wm = state.get(name)
        if wm is None:
            wm = latest - FIRST_RUN_LOOKBACK
        frm = max(wm + 1 - OVERLAP, 0)
        done_to = wm
        try:
            cur = frm
            while cur <= latest:
                if time.time() - started > TIME_BUDGET_S:
                    partial = True
                    break
                end = min(cur + CHUNK - 1, latest)
                logs = get_logs(cfg["address"], cfg["topic"], cur, end)
                for lg in logs:
                    c = decode(name, lg)
                    if c:
                        creations.append(c)
                done_to = end
                cur = end + 1
            scanned_to[name] = done_to
            state[name] = done_to
        except Exception as e:  # keep prior watermark; report honestly
            errors[name] = str(e)[:160]
            scanned_to[name] = done_to
    # dedup by (platform, token), keep earliest sighting
    seen, uniq = set(), []
    for c in sorted(creations, key=lambda x: x["block"]):
        key = (c["platform"], c["token"].lower())
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    with open(state_path, "w") as f:
        json.dump(state, f)
    print(json.dumps({"latestBlock": latest, "latestTimestamp": latest_ts,
                      "scannedTo": scanned_to, "creations": uniq,
                      "errors": errors, "partial": partial}, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
