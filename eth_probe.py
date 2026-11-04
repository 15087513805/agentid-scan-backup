#!/usr/bin/env python3
"""Minimal BSC eth_call / eth_getLogs helper via https://rpc-bsc.48.club (allow-listed).
Pure-python keccak256 (Keccak-f1600) so no web3 dependency."""
import json, sys, urllib.request

RPC = "https://rpc-bsc.48.club"
WALLET = "0xCd710a311aedb31068661B6c8dfcdAff555b806a"

# --- keccak256 ---
RC = [0x0000000000000001,0x0000000000008082,0x800000000000808a,0x8000000080008000,
      0x000000000000808b,0x0000000080000001,0x8000000080008081,0x8000000000008009,
      0x000000000000008a,0x0000000000000088,0x0000000080008009,0x000000008000000a,
      0x000000008000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,
      0x8000000000008002,0x8000000000000080,0x000000000000800a,0x800000008000000a,
      0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
R = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
MASK = (1 << 64) - 1
def _rol(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK if n else x
def keccak256(data: bytes) -> bytes:
    rate = 136
    state = [0] * 25
    # pad10*1, domain 0x01
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i*8:(i+1)*8], 'little')
        for rnd in range(24):
            # Theta
            C = [state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20] for x in range(5)]
            D = [C[(x+4) % 5] ^ _rol(C[(x+1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x + 5*y] ^= D[x]
            # Rho + Pi
            B = [0] * 25
            for x in range(5):
                for y in range(5):
                    B[y + 5*((2*x + 3*y) % 5)] = _rol(state[x + 5*y], R[x][y])
            # Chi
            for x in range(5):
                for y in range(5):
                    state[x + 5*y] = B[x + 5*y] ^ ((~B[(x+1) % 5 + 5*y]) & B[(x+2) % 5 + 5*y])
            # Iota
            state[0] ^= RC[rnd]
    out = b''
    for i in range(4):
        out += state[i].to_bytes(8, 'little')
    return out

def sel(sig: str) -> str:
    return '0x' + keccak256(sig.encode()).hex()[:8]

def rpc(method, params):
    req = urllib.request.Request(RPC, data=json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def call(to, data, frm=WALLET):
    return rpc("eth_call", [{"to": to, "from": frm, "data": data}, "latest"])

def enc_addr(a):
    return (a[2:].lower()).rjust(64, '0')

def show(label, res):
    if 'error' in res:
        print(f"{label}: ERROR {res['error'].get('message', res['error'])}")
    else:
        v = res['result']
        try:
            print(f"{label}: {v} (int={int(v, 16)})")
        except Exception:
            print(f"{label}: {v}")

if __name__ == '__main__':
    # sanity: known selectors
    assert sel('balanceOf(address)') == '0x70a08231', sel('balanceOf(address)')
    assert sel('totalSupply()') == '0x18160ddd'
    print('keccak sanity OK; freeMint()=', sel('freeMint()'), 'mint()=', sel('mint()'),
          'claim()=', sel('claim()'), 'publicMint()=', sel('publicMint()'),
          'mint(uint256)=', sel('mint(uint256)'))
    if len(sys.argv) > 1 and sys.argv[1] == 'probe':
        W = WALLET
        bal = '0x70a08231' + enc_addr(W)
        ts = '0x18160ddd'
        targets = {
            'Ptah': '0xD87ADb2E47979d6cb323896B1A9320E0dd132213',
            'Agentlings': '0xbf3488e453c68e9771c26d448e99d0ec5395135f',
            'AgentImps': '0x5b68ea4f58fc46739d1a02a80e2680d25448cd45',
            'AnthroBit': '0xc7b7593Aa572701d26301D9707E93b0c511e636A',
            'HashDroids': '0x0EED2C5e866A3792f587CAf0839941EA57fe6915',
            'Nemotron': '0xDd8BdfC91cbD572935B09863A742d8296fed0ACf',
            'GSEED': '0xE9522648503C626AD84E5bc7445D1e26c89f6FEc',
            'ENIG': '0x213A879D11a85b54483CEA2cdEC5D9026958Add3',
            'BLOB': '0x4ADDBd796eDF3d4d186Fb5AA314cAfF3F98984A6',
            'Worldygg': '0x2ED9E0a6992BA22B48c2fc2def6bB2365301A0D0',
            'BNFile': '0x6B1719EEFcb271778c40f0CFd71c8651Adbde5d1',
            'AgentGenesis': '0x02A3aC26012cc7017F5cf4e4d481Ee243f9CcEB4',
            'PixelVulpes': '0x9134AE94Ab0739CF0E0F4F5e9CacFa5e1D029b0C',
            'Hallowed': '0x096243e665083c7628923d7db71805b15c4a6054',
            'SOLVED': '0x4f1be6e4c73138d706853584ba0fa4cb923dcd95',
            'HarvestLand': '0xacf150d9eC909E3d339Bf4c6D090b18495674E66',
            'AgentsEstates': '0x7ecdcf20a6e7bb10f76f910d01f508395cda9ad0',
        }
        for name, ca in targets.items():
            try:
                show(f'{name} balanceOf', call(ca, bal))
            except Exception as e:
                print(f'{name} balanceOf: RPC EXC {e}')
            try:
                show(f'{name} totalSupply', call(ca, ts))
            except Exception as e:
                print(f'{name} totalSupply: RPC EXC {e}')
