# Cabal Online DPS overlay

A small overlay that reads combat off the network (Npcap) and shows DPS next
to the game window. It does not write to the client.

**Currently supported:** PlayCabal (EP36)

Official Cabal uses a different client build; this overlay is not for that.

## Run

1. Install [Npcap](https://npcap.com/).
2. Build (below) or place `PlayCabalWire.exe` next to `keychain.bin`.
3. Start the exe. Windows will ask for Administrator so capture can bind.

If last skill stays at `0` while you are hitting: Npcap is missing, UAC was
declined, or the client was patched. After a client patch, replace
`keychain.bin` next to the exe.

`F8` click-through. `F9` reset. Drag the left grip. Click the strip to expand
(30s graph, skill mix, Lock / Reset). The overlay docks to `CabalMain.exe` and
hides if that window is minimized.

DPS is session total / time since first hit. Peak is the highest completed
1-second damage bucket. Skill mix is this session, with skill names and
average ms between hits of the same skill (gaps over 4s ignored).

Log file: `playcabal-wire.log` next to the exe.

## Build

Visual Studio C++ x64 tools. Npcap runtime; no Npcap SDK.

```powershell
cmd /c build.bat
```

Output: `build\PlayCabalWire.exe` and `build\pw-decrypt.exe`.

```powershell
python tools\wire_probe.py path\to.pcapng
```

## This build

Codebook: `data/keychain.bin` (per client build). Header XOR `0xD15FA427`.
Leftover combat is cmd `0xAE` (137 bytes one target, +39 per extra). World
TCP ports move; the overlay follows `CabalMain.exe` sockets.

## Layout

- `src/` — decrypt, combat parse, capture, overlay
- `src/skill_names.c` — generated names (do not edit)
- `data/keychain.bin` — codebook for the current supported client
- `tools/wire_probe.py` — tshark pcap check
- `tools/gen_skill_names.py` — rebuild names from client `cabal_msg.xml`

```powershell
python tools\gen_skill_names.py --xml path\to\Language\English\cabal_msg.xml
```

MIT. [Coffee](https://ko-fi.com/nipperlug)
