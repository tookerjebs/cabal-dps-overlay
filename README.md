# Cabal Online DPS overlay

A small overlay that shows DPS next to the game window. It reads combat from
the network (Npcap). It does not write to the client.

**Currently supported:** PlayCabal (EP36)

Official Cabal uses a different client build; this overlay is not for that.

## Install

1. Install [Npcap](https://npcap.com/) (default options are fine).
2. Download the latest zip from [Releases](https://github.com/tookerjebs/cabal-dps-overlay/releases).
3. Unzip and run `PlayCabalWire.exe`. Windows will ask for Administrator.

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
