#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace std;
using u32 = uint32_t;
using u64 = uint64_t;
using Keys = array<u32, 6>;

static inline uint8_t g(unsigned a, unsigned b, unsigned c) {
    unsigned v = (a + b + c) & 255;
    return uint8_t((v << 2 | v >> 6) & 255);
}

static inline u32 f(u32 x) {
    unsigned a = x >> 24, b = (x >> 16) & 255, c = (x >> 8) & 255, d = x & 255;
    unsigned y1 = g(a ^ b, c ^ d, 1);
    unsigned y0 = g(a, y1, 0), y2 = g(c ^ d, y1, 0);
    return y0 << 24 | y1 << 16 | y2 << 8 | g(d, y2, 1);
}

static inline u64 enc(u64 p, const Keys &k) {
    u32 l = u32(p >> 32) ^ k[4], r = u32(p) ^ k[5];
    u32 x = l ^ r, y = l ^ f(x ^ k[0]);
    for (int i = 1; i <= 2; ++i) {
        u32 t = x ^ f(y ^ k[i]);
        x = y; y = t;
    }
    u32 z = x ^ f(y ^ k[3]);
    return u64(z) << 32 | (z ^ y);
}

struct Record { u64 p, c; };
struct Pair { u32 x0, x1, expected; };
struct Dataset { vector<Record> records; vector<array<size_t, 2>> pairs; };

static inline u32 middle(u32 x, unsigned a, unsigned b) {
    unsigned y1 = g((((x >> 24) ^ (x >> 16)) & 255) ^ a,
                    (((x >> 8) ^ x) & 255) ^ b, 1);
    unsigned y2 = g((((x >> 8) ^ x) & 255) ^ b, y1, 0);
    return y1 << 16 | y2 << 8;
}

static vector<u32> solve(const vector<Pair> &pairs) {
    vector<u32> result;
    if (pairs.empty()) return result;
    const auto &p = pairs[0];
    for (unsigned a = 0; a < 256; ++a) for (unsigned b = 0; b < 256; ++b) {
        if ((middle(p.x0, a, b) ^ middle(p.x1, a, b)) != (p.expected & 0x00ffff00)) continue;
        bool ok = true;
        for (size_t i = 1; i < pairs.size(); ++i) {
            const auto &q = pairs[i];
            if ((middle(q.x0, a, b) ^ middle(q.x1, a, b)) != (q.expected & 0x00ffff00)) { ok = false; break; }
        }
        if (!ok) continue;
        for (unsigned c = 0; c < 256; ++c) for (unsigned d = 0; d < 256; ++d) {
            u32 k = c << 24 | (a ^ c) << 16 | (b ^ d) << 8 | d;
            bool valid = true;
            for (const auto &q : pairs) {
                if ((f(q.x0 ^ k) ^ f(q.x1 ^ k)) != q.expected) { valid = false; break; }
            }
            if (valid) result.push_back(k);
        }
    }
    return result;
}

static pair<u32, u32> peel(u64 ct, const vector<u32> &known) {
    u32 l = u32(ct >> 32), r = u32(ct) ^ l;
    for (u32 k : known) { u32 t = l ^ f(r ^ k); l = r; r = t; }
    return {l, r};
}

static vector<Pair> round_pairs(const Dataset &ds, const vector<u32> &known, u32 differential) {
    vector<Pair> out;
    for (auto indices : ds.pairs) {
        auto [l0, r0] = peel(ds.records[indices[0]].c, known);
        auto [l1, r1] = peel(ds.records[indices[1]].c, known);
        out.push_back({r0, r1, l0 ^ l1 ^ differential});
    }
    return out;
}

static bool recover_first(const Dataset &ds, const vector<u32> &known, Keys &out,
                          const vector<Record> &all) {
    vector<pair<u32, u32>> state;
    for (const auto &rec : ds.records) state.push_back(peel(rec.c, known));
    vector<Pair> relations;
    for (size_t i = 1; i < ds.records.size(); ++i) {
        relations.push_back({state[0].second, state[i].second,
                             state[0].first ^ state[i].first ^
                             u32(ds.records[0].p >> 32) ^ u32(ds.records[i].p >> 32)});
    }
    auto candidates = solve(relations);
    for (u32 k0 : candidates) {
        u32 initial_left = state[0].first ^ f(state[0].second ^ k0);
        Keys k = {k0, known[2], known[1], known[0],
                  initial_left ^ u32(ds.records[0].p >> 32),
                  initial_left ^ state[0].second ^ u32(ds.records[0].p)};
        bool good = true;
        for (const auto &rec : all) if (enc(rec.p, k) != rec.c) { good = false; break; }
        if (good) { out = k; return true; }
    }
    return false;
}

static bool attack(const array<Dataset, 3> &ds, Keys &out) {
    vector<Record> all;
    for (const auto &d : ds) all.insert(all.end(), d.records.begin(), d.records.end());
    auto k3s = solve(round_pairs(ds[0], {}, 0x02000000));
    for (u32 k3 : k3s) {
        auto k2s = solve(round_pairs(ds[1], {k3}, 0x02000000));
        for (u32 k2 : k2s) {
            auto k1s = solve(round_pairs(ds[2], {k3, k2}, 0x02000000));
            for (u32 k1 : k1s) if (recover_first(ds[2], {k3, k2, k1}, out, all)) return true;
        }
    }
    return false;
}

static unsigned nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw runtime_error("invalid hex digit");
}

static u64 hex_block(const string &s) {
    if (s.size() != 16) throw runtime_error("pair blocks must be 16 hex digits");
    u64 value = 0;
    for (char c : s) value = (value << 4) | nibble(c);
    return value;
}

static u64 dec(u64 ct, const Keys &keys) {
    u32 x = u32(ct >> 32), y = u32(ct) ^ x;
    for (int i = 3; i >= 1; --i) {
        u32 t = x ^ f(y ^ keys[i]);
        x = y; y = t;
    }
    u32 initial = x ^ f(y ^ keys[0]);
    return u64(initial ^ keys[4]) << 32 | (initial ^ y ^ keys[5]);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        cerr << "usage: " << argv[0] << " TARGET_CIPHERTEXT_HEX < pairs.txt\n";
        return 2;
    }
    try {
        string target = argv[1];
        if (target.empty() || target.size() % 16) throw runtime_error("invalid target ciphertext length");
        for (char c : target) nibble(c);

        constexpr array<u64, 3> diffs = {0x8080000080800000ULL, 0x0000000080800000ULL,
                                          0x0000000002000000ULL};
        array<Dataset, 3> ds;
        for (size_t group = 0; group < ds.size(); ++group) {
            for (int pair = 0; pair < 12; ++pair) {
                array<u64, 2> p;
                for (int half = 0; half < 2; ++half) {
                    string label, plain, cipher;
                    if (!(cin >> label >> plain >> cipher) || label != to_string(group))
                        throw runtime_error("expected 12 ordered pairs for each group 0, 1, 2");
                    p[half] = hex_block(plain);
                    ds[group].records.push_back({p[half], hex_block(cipher)});
                }
                if ((p[0] ^ p[1]) != diffs[group]) throw runtime_error("incorrect pair difference");
                size_t i = ds[group].records.size() - 2;
                ds[group].pairs.push_back({i, i + 1});
            }
        }
        string extra;
        if (cin >> extra) throw runtime_error("unexpected rows after group 2");

        Keys keys;
        if (!attack(ds, keys)) throw runtime_error("could not recover keys from pairs");

        string plain;
        plain.reserve(target.size());
        for (size_t i = 0; i < target.size(); i += 16) {
            u64 block = dec(hex_block(target.substr(i, 16)), keys);
            for (int shift = 56; shift >= 0; shift -= 8) {
                unsigned byte = (block >> shift) & 255;
                constexpr char digits[] = "0123456789abcdef";
                plain += digits[byte >> 4];
                plain += digits[byte & 15];
            }
        }
        unsigned pad = nibble(plain[plain.size() - 2]) * 16 + nibble(plain.back());
        if (pad < 1 || pad > 8) throw runtime_error("invalid PKCS7 padding");
        for (unsigned i = 0; i < pad; ++i) {
            if (plain.substr(plain.size() - 2 * (i + 1), 2) != plain.substr(plain.size() - 2, 2))
                throw runtime_error("invalid PKCS7 padding");
        }
        cout << plain << '\n';
    } catch (const exception &e) {
        cerr << e.what() << '\n';
        return 1;
    }
}
