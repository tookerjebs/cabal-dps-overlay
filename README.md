# Cabal Online DPS overlay

A small overlay that shows DPS next to the game window. It reads combat from
the network (Npcap). It does not write to the client.

**Currently supported:** PlayCabal (EP36)

Other servers and regions: coming soon. Maybe.

## Install

1. Install [Npcap](https://npcap.com/) (default options are fine). If you already
   have [Wireshark](https://www.wireshark.org/), you already have Npcap — skip
   this step. You do not need Wireshark itself.
2. Download the latest zip from [Releases](https://github.com/tookerjebs/cabal-dps-overlay/releases).
3. Unzip and keep `CabalDps.exe` and `keychain.bin` in the same folder. Run
   `CabalDps.exe`. Windows will ask for Administrator.

If last skill stays at `0` while you are hitting: Npcap is missing, UAC was
declined, or the client was patched. After a client patch you need a new
build / `keychain.bin`.

Drag the left grip to move. Click the strip to expand. **Reset** clears the
session. **Close** exits. `F9` also resets. The overlay hides if the game is
minimized.

## Build

Visual Studio C++ x64 tools, then:

```powershell
cmd /c build.bat
```

MIT. [Coffee](https://ko-fi.com/nipperlug)
