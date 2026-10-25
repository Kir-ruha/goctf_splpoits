# Greenhouse author notes

Keep this directory private from teams. Each script takes a host and a public flag ID.

1. `pwn.py`: `DROP` frees an `Observation` but leaves a typed handle. A same sized `PollenPacket` reclaims it. `VIEW` then interprets packet bytes as the old observation. A valid frame dump, the atlas, and the executable cultivar transform table recover the session nonce; the packet also needs valid lineage and canopy tags.
2. `web.py`: the projection handler authorizes the anchor before `#` but renders the focus after `#`. `public#<private-id>` with the visitor capability reveals a biometric note.
3. `misc.py`: the public spectrum is a reversible linear recurrence of archive bytes. The calibration mask is deterministic from the public plot ID; invert modulo 257.
