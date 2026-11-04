#!/usr/bin/env python3
"""Registry-reference scanner for BSC Agent ID projects (discovery channel).

Principle: independent Agent ID projects hardcode the identity-registry
address in their mint contract's runtime bytecode. Scan new contract
creations block by block and substring-match the registry addresses in
eth_getCode output:

  0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F  .ai identity NFT / registry
      (third-party registry most indie projects gate on)
  0x912cef0c3ae9ab6eb3ec87cab69371cfb317ab94  Four.Meme official registry

Method: eth_getBlockByNumber(full txs) -> creation txs (to == null) ->
contract address derived locally (CREATE: keccak256(rlp([sender,
nonce]))[-20:]; sender+nonce are in the block's tx data, so no per-tx
receipt call is needed) -> eth_getCode -> substring match. Hits get a
best-effort name()/symbol()/totalSupply() probe (null on failure). Only
direct deployments are visible this way; factory-created tokens are
covered by factory_scan.py instead.

Watermark in registry-scan-state.json ({"lastBlock": N}) next to this
script. No args: scan watermark+1 .. head, at most MAX_BLOCKS per run,
then advance the watermark. First run (no state file): initialise the
watermark to head and exit without back-scanning. Manual test window:
--from A --to B (watermark untouched). Positive control: --check 0xADDR
fetches that contract's code and reports which registries it references.
Output: one JSON object on stdout.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# Free public BSC RPC pool (all hosts already on the user's allow-list;
# verified reachable 2026-11-02). Requests rotate across the pool and a
# failing host is cooled down and skipped for a while.
RPCS = [
    "https://bsc-dataseed1.ninicoin.io",
    "https://bsc-dataseed2.ninicoin.io",
    "https://bsc-dataseed3.ninicoin.io",
    "https://bsc-dataseed4.ninicoin.io",
    "https://bsc-dataseed.bnbchain.org",
    "https://bsc-dataseed2.bnbchain.org",
    "https://bsc-dataseed3.bnbchain.org",
    "https://bsc-dataseed4.bnbchain.org",
    "https://bsc-rpc.publicnode.com",
    "https://bsc.drpc.org",
    "https://1rpc.io/bnb",
    "https://bsc-mainnet.public.blastapi.io",
    "https://api.zan.top/public/bsc-mainnet",
]
HERE = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(HERE, "registry-scan-state.json")
try:
    MAX_BLOCKS = int(os.environ.get("REGISTRY_SCAN_MAX_BLOCKS", "8500"))
except Exception:
    MAX_BLOCKS = 8500
try:
    WORKERS = max(1, int(os.environ.get("REGISTRY_SCAN_WORKERS", "6")))
except Exception:
    WORKERS = 6
SUBCHUNK = 250          # blocks per progress unit (watermark advances per subchunk)
try:
    BLOCK_BATCH = int(os.environ.get("REGISTRY_SCAN_BLOCK_BATCH", "25"))
except Exception:
    BLOCK_BATCH = 25        # eth_getBlockByNumber per JSON-RPC batch
RCPT_BATCH = 50
CODE_BATCH = 20         # runtime code can be ~48K hex chars per contract
SINGLE_CALL_PAUSE = 0.05

TARGETS = {
    "60b9262456de011f7d15a54cdd8c48baaa8b022f": "third-party .ai identity registry (0x60B9...022F)",
    "912cef0c3ae9ab6eb3ec87cab69371cfb317ab94": "four.meme official Agent ID registry (0x912c...ab94)",
}

sys.path.insert(0, HERE)
from eth_probe import keccak256 as _keccak256


def _rlp_bytes(b):
    if len(b) == 1 and b[0] < 0x80:
        return b
    if len(b) <= 55:
        return bytes([0x80 + len(b)]) + b
    lb = len(b).to_bytes((len(b).bit_length() + 7) // 8, "big")
    return bytes([0xB7 + len(lb)]) + lb + b


def _rlp_list(items):
    payload = b"".join(_rlp_bytes(i) for i in items)
    if len(payload) <= 55:
        return bytes([0xC0 + len(payload)]) + payload
    lp = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(lp)]) + lp + payload


def create_address(sender, nonce):
    """CREATE contract address for a top-level deployment tx:
    keccak256(rlp([sender, nonce]))[-20:]."""
    sb = bytes.fromhex(sender[2:] if sender.startswith("0x") else sender)
    nb = nonce.to_bytes((nonce.bit_length() + 7) // 8, "big") if nonce else b""
    return "0x" + _keccak256(_rlp_list([sb, nb]))[-20:].hex()

_rpc_lock = threading.Lock()
_rpc_rr = 0
_rpc_cooldown_until = {}
_batch_bad = set()
RPC_COOLDOWN_SEC = 45


def _pick_url(exclude=()):
    """Round-robin pick of a pool endpoint that is not excluded and not
    cooling down. If every candidate is cooling, returns the one whose
    cooldown ends soonest."""
    global _rpc_rr
    now = time.time()
    with _rpc_lock:
        n = len(RPCS)
        for _ in range(n):
            url = RPCS[_rpc_rr % n]
            _rpc_rr += 1
            if url in exclude:
                continue
            if _rpc_cooldown_until.get(url, 0) > now:
                continue
            return url
        cand = [u for u in RPCS if u not in exclude] or list(RPCS)
        return min(cand, key=lambda u: _rpc_cooldown_until.get(u, 0))


def _cool(url, sec=RPC_COOLDOWN_SEC):
    with _rpc_lock:
        _rpc_cooldown_until[url] = time.time() + sec


def _post_url(url, payload, timeout):
    out = subprocess.run(
        ["curl", "-s", "-m", str(timeout), url,
         "-H", "Content-Type: application/json", "-d", payload],
        capture_output=True, text=True,
    ).stdout
    return json.loads(out)  # raises on empty / non-JSON (flaky endpoint)


def _post(payload, timeout=90):
    """POST a JSON-RPC payload (single or batch), rotating across the
    endpoint pool; a host that fails is cooled down and skipped. Returns
    parsed JSON or raises after trying several hosts."""
    last_err = None
    tried = set()
    for attempt in range(len(RPCS) + 2):
        url = _pick_url(exclude=tried)
        tried.add(url)
        try:
            return _post_url(url, payload, timeout)
        except Exception as e:
            last_err = e
            _cool(url)
            time.sleep(0.3 * (attempt + 1) if attempt < 3 else 1.0)
    raise RuntimeError(f"rpc post failed after retries: {last_err}")


def rpc(method, params, timeout=90):
    r = _post(json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}), timeout)
    if isinstance(r, dict) and "error" in r:
        raise RuntimeError(f"{method}: {str(r['error'])[:120]}")
    return r["result"]


def _rpc_batch_once(calls, timeout, exclude=()):
    """One batch attempt series across pooled endpoints. Returns
    (results, url_used) or (None, None) if no endpoint took the batch.
    Per-item failures stay None in the results."""
    payload = json.dumps([{"jsonrpc": "2.0", "id": i, "method": m, "params": p}
                          for i, (m, p) in enumerate(calls)])
    tried = set(exclude)
    for _attempt in range(4):
        with _rpc_lock:
            bad = set(_batch_bad)
        url = _pick_url(exclude=tried | bad)
        if url in bad:
            return None, None
        tried.add(url)
        try:
            r = _post_url(url, payload, timeout)
        except Exception:
            _cool(url)
            continue
        if not isinstance(r, list):
            with _rpc_lock:
                _batch_bad.add(url)
            continue
        by_id = {item.get("id"): item for item in r if isinstance(item, dict)}
        out = []
        for i in range(len(calls)):
            item = by_id.get(i)
            if item is None or "error" in item or "result" not in item:
                out.append(None)
            else:
                out.append(item["result"])
        return out, url
    return None, None


def rpc_batch(calls, timeout=120):
    """calls: list of (method, params). Returns results aligned with calls;
    a failed item yields None. Batch support is tracked per endpoint: a
    host that rejects batch payloads is skipped for batches (not for
    single calls). Items a batch leaves as None are re-batched once on
    another endpoint, so one weak endpoint cannot silently drop a whole
    batch of blocks/contracts from the scan."""
    if not calls:
        return []
    out, used = _rpc_batch_once(calls, timeout)
    if out is None:
        return _batch_sequential(calls)
    missing = [i for i, v in enumerate(out) if v is None]
    if missing:
        # One bounded re-batch of just the missing items on a different
        # endpoint. (An earlier design retried items as singles; measured
        # 2026-11-02 that path could stall for minutes on hanging hosts,
        # so it was removed — remaining Nones behave like the original
        # script's per-item failures.)
        sub, _u2 = _rpc_batch_once([calls[i] for i in missing], timeout,
                                   exclude={used} if used else set())
        if sub is not None:
            for j, i in enumerate(missing):
                if sub[j] is not None:
                    out[i] = sub[j]
    return out


def _batch_sequential(calls):
    out = []
    for m, p in calls:
        try:
            out.append(rpc(m, p))
        except Exception:
            out.append(None)
        time.sleep(SINGLE_CALL_PAUSE)
    return out


def chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def dec_str(ret):
    """Decode an ABI dynamic string return (name/symbol); None if it is not
    a well-formed dynamic string."""
    if not ret or ret == "0x":
        return None
    d = ret[2:]
    try:
        if len(d) >= 128:
            off = int(d[:64], 16)
            ln = int(d[off * 2:off * 2 + 64], 16)
            return bytes.fromhex(d[off * 2 + 64:off * 2 + 64 + ln * 2]).decode("utf-8", "replace")
        # bytes32-style fixed string (some old tokens)
        raw = bytes.fromhex(d[:64]).rstrip(b"\x00")
        return raw.decode("utf-8", "replace") or None
    except Exception:
        return None


def match_registries(code_hex):
    if not code_hex:
        return []
    body = code_hex[2:] if code_hex.startswith("0x") else code_hex
    body = body.lower()
    return [label for addr, label in TARGETS.items() if addr in body]


def _map_batches(parts, timeout=120):
    """Run rpc_batch over independent call groups concurrently (result
    order preserved); the round-robin picker spreads the groups across
    the endpoint pool."""
    if not parts:
        return []
    if len(parts) == 1 or WORKERS == 1:
        return [rpc_batch(p, timeout) for p in parts]
    with ThreadPoolExecutor(max_workers=min(WORKERS, len(parts))) as ex:
        return list(ex.map(lambda p: rpc_batch(p, timeout), parts))


def scan_range(frm, to):
    """Scan blocks [frm, to]. Returns (creations_checked, hits, done_to).
    done_to advances per completed subchunk so a mid-range failure keeps
    honest partial progress."""
    hits, creations = [], 0
    done_to = frm - 1
    cur = frm
    while cur <= to:
        end = min(cur + SUBCHUNK - 1, to)
        calls = [("eth_getBlockByNumber", [hex(b), True]) for b in range(cur, end + 1)]
        blocks = []
        for res in _map_batches(list(chunked(calls, BLOCK_BATCH))):
            blocks.extend(res)
        contracts = []  # (block, address, creator); CREATE address derived
        # locally from (sender, nonce) — no per-tx receipt call needed.
        for bnum, blk in zip(range(cur, end + 1), blocks):
            if not blk:
                continue
            for tx in blk.get("transactions", []):
                if tx.get("to") is None:
                    try:
                        addr = create_address(tx.get("from"),
                                              int(tx.get("nonce", "0x0"), 16))
                    except Exception:
                        continue
                    contracts.append((bnum, addr, tx.get("from")))
        creations += len(contracts)
        matched = []  # (block, address, creator, registries, code_len_bytes)
        code_parts = list(chunked(contracts, CODE_BATCH))
        code_calls = [[("eth_getCode", [a, "latest"]) for _, a, _ in part]
                      for part in code_parts]
        for part, codes in zip(code_parts, _map_batches(code_calls)):
            for (bnum, addr_c, creator), code in zip(part, codes):
                regs = match_registries(code)
                if regs:
                    chash = None
                    if code:
                        try:
                            chash = hashlib.sha256(bytes.fromhex(code[2:])).hexdigest()[:16]
                        except Exception:
                            chash = None
                    matched.append((bnum, addr_c, creator, regs,
                                    (len(code) - 2) // 2 if code else 0, chash))
        if matched:
            probes = []
            for _b, addr_c, _c, _r, _l, _h in matched:
                probes += [("eth_call", [{"to": addr_c, "data": "0x06fdde03"}, "latest"]),
                           ("eth_call", [{"to": addr_c, "data": "0x95d89b41"}, "latest"]),
                           ("eth_call", [{"to": addr_c, "data": "0x18160ddd"}, "latest"])]
            res = rpc_batch(probes)
            for i, (bnum, addr_c, creator, regs, clen, chash) in enumerate(matched):
                name = dec_str(res[i * 3])
                symbol = dec_str(res[i * 3 + 1])
                ts_raw = res[i * 3 + 2]
                total = None
                if ts_raw and ts_raw != "0x":
                    try:
                        total = int(ts_raw, 16)
                    except Exception:
                        total = None
                hits.append({"block": bnum, "contract": addr_c, "creator": creator,
                             "registries": regs, "codeBytes": clen, "codeHash": chash,
                             "name": name, "symbol": symbol, "totalSupply": total})
        done_to = end
        cur = end + 1
    return creations, hits, done_to


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="frm", type=int, default=None)
    ap.add_argument("--to", dest="to", type=int, default=None)
    ap.add_argument("--check", dest="check", default=None,
                    help="positive control: report registry refs of one contract")
    ap.add_argument("--max-blocks", dest="max_blocks", type=int, default=None,
                    help="override the per-run block cap (default: env "
                         "REGISTRY_SCAN_MAX_BLOCKS or 8500)")
    ap.add_argument("--catch-up", dest="catch_up", action="store_true",
                    help="scan the whole gap to head in one run (no cap)")
    args = ap.parse_args()
    started = time.time()

    if args.check:
        code = rpc("eth_getCode", [args.check, "latest"])
        print(json.dumps({"check": args.check,
                          "codeBytes": (len(code) - 2) // 2 if code else 0,
                          "registries": match_registries(code),
                          "elapsedSec": round(time.time() - started, 2)},
                         ensure_ascii=False))
        return 0

    head = int(rpc("eth_blockNumber", []), 16)

    if args.frm is not None and args.to is not None:
        creations, hits, done_to = scan_range(args.frm, args.to)
        print(json.dumps({"mode": "manual", "latestBlock": head,
                          "scannedFrom": args.frm, "scannedTo": done_to,
                          "blocksScanned": done_to - args.frm + 1,
                          "creationsChecked": creations, "hits": hits,
                          "errors": {}, "partial": done_to < args.to,
                          "elapsedSec": round(time.time() - started, 2)},
                         ensure_ascii=False))
        return 0

    state = {}
    if os.path.exists(STATE_PATH):
        try:
            state = json.load(open(STATE_PATH))
        except Exception:
            state = {}
    wm = state.get("lastBlock")
    if wm is None:
        with open(STATE_PATH, "w") as f:
            json.dump({"lastBlock": head}, f)
        print(json.dumps({"mode": "init", "latestBlock": head, "lastBlock": head,
                          "note": "watermark initialised; no back-scan on first run",
                          "hits": [], "elapsedSec": round(time.time() - started, 2)},
                         ensure_ascii=False))
        return 0

    limit = MAX_BLOCKS
    if args.max_blocks is not None:
        limit = args.max_blocks
    if args.catch_up:
        limit = head - wm
    frm = wm + 1
    to = min(head, wm + max(limit, 0))
    if frm > to:
        print(json.dumps({"mode": "incremental", "latestBlock": head,
                          "scannedFrom": frm, "scannedTo": wm, "blocksScanned": 0,
                          "creationsChecked": 0, "hits": [], "errors": {},
                          "partial": False,
                          "elapsedSec": round(time.time() - started, 2)},
                         ensure_ascii=False))
        return 0
    errors = {}
    try:
        creations, hits, done_to = scan_range(frm, to)
    except Exception as e:  # keep old watermark; report honestly
        errors["scan"] = str(e)[:160]
        creations, hits, done_to = 0, [], wm
    state["lastBlock"] = done_to
    with open(STATE_PATH, "w") as f:
        json.dump(state, f)
    print(json.dumps({"mode": "incremental", "latestBlock": head,
                      "scannedFrom": frm, "scannedTo": done_to,
                      "blocksScanned": max(done_to - frm + 1, 0),
                      "creationsChecked": creations, "hits": hits,
                      "errors": errors, "partial": done_to < to,
                      "elapsedSec": round(time.time() - started, 2)},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
