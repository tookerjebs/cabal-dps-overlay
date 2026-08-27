"""Build src/skill_names.c from decoded cabal_msg.xml (not committed XML)."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def c_escape(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif o < 32 or o == 127:
            out.append("\\%03o" % o)
        else:
            out.append(ch)
    return "".join(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--xml",
        required=True,
        help="decoded Language/English/cabal_msg.xml",
    )
    parser.add_argument("--out", default=str(HERE / "src" / "skill_names.c"))
    args = parser.parse_args()
    xml = Path(args.xml)
    if not xml.is_file():
        print("missing", xml)
        return 1
    text = xml.read_text(encoding="utf-8", errors="replace")
    rows = {}
    for m in re.finditer(r'<msg id="skill(\d+)" cont="([^"]*)"/>', text):
        idx = int(m.group(1), 10)
        name = m.group(2).strip()
        if name:
            rows[idx] = name
    items = sorted(rows.items())
    out = Path(args.out)
    lines = [
        "/* Generated from cabal_msg.xml skillNNNN entries. Do not edit. */",
        '#include "skill_names.h"',
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "typedef struct {",
        "    uint16_t id;",
        "    const char *name;",
        "} PwSkillName;",
        "",
        "static const PwSkillName k_names[] = {",
    ]
    for idx, name in items:
        lines.append('    {%u, "%s"},' % (idx, c_escape(name)))
    lines += [
        "};",
        "",
        "const char *",
        "pw_skill_name(uint32_t id)",
        "{",
        "    unsigned lo = 0;",
        "    unsigned hi = (unsigned)(sizeof(k_names) / sizeof(k_names[0]));",
        "    while (lo < hi) {",
        "        unsigned mid = lo + (hi - lo) / 2u;",
        "        if (k_names[mid].id == id) {",
        "            return k_names[mid].name;",
        "        }",
        "        if (k_names[mid].id < id) {",
        "            lo = mid + 1u;",
        "        } else {",
        "            hi = mid;",
        "        }",
        "    }",
        "    return NULL;",
        "}",
        "",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")
    print("wrote", out, "skills", len(items))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
