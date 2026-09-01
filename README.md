# Cabal Online DPS overlay

A small overlay that shows DPS next to the game window. It reads combat from
the network (Npcap). It does not write to the client.

> **Release status:** This repository keeps the latest published source
> snapshot. Newer compiled releases may contain changes that are not yet
> reflected in the source tree. For normal use, download the latest release.

**Currently supported in the latest release:** PlayCabal (EP36), Cabal Online
(EU)

## Install

1. Install [Npcap](https://npcap.com/) (default options are fine). If you already
   have [Wireshark](https://www.wireshark.org/), you already have Npcap — skip
   this step. You do not need Wireshark itself.
2. Download the latest zip from [Releases](https://github.com/tookerjebs/cabal-dps-overlay/releases).
3. Unzip and run `CabalDps.exe`. The current release needs no extra data file.
   Windows will ask for Administrator.

If last skill stays at `0` while you are hitting: Npcap is missing, UAC was
declined, or the client was patched. A patched client may require a new release.

Drag the left grip or the strip to move. Click the strip to expand. In the
expanded panel, **Reset** / `F9` clears the session and **x** next to it /
`F10` / running the exe again exits. The overlay hides if the game is closed
or minimized.

## Build

Visual Studio C++ x64 tools, then:

```powershell
cmd /c build.bat
```

These build instructions apply to the published source snapshot and may not
reproduce the newest release exactly.

MIT. [Coffee](https://ko-fi.com/nipperlug)
