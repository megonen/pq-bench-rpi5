"""miniyaml — a dependency-free parser for the restricted YAML subset used by
config.yaml.

We deliberately avoid a PyYAML runtime dependency so the core pipeline runs on a
stock Python 3 (the RPi5 / Mac smoke box both have only stdlib by default).

Supported subset (sufficient for config.yaml):
  - nested mappings via indentation (2 spaces per level by convention)
  - lists of scalars:           "- value"
  - lists of mappings:          "- key: value" then indented "key: value"
  - scalars: int, float, bool (true/false), null/~, quoted or bare strings
  - "# comment" to end of line (outside quotes)

It is NOT a general YAML implementation. If a user needs full YAML they can
install PyYAML and set PQB_USE_PYYAML=1.
"""
from __future__ import annotations
import os
import re


def _scalar(tok: str):
    s = tok.strip()
    if s == "" or s in ("~", "null", "Null", "NULL"):
        return None
    if (s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'"):
        return s[1:-1]
    low = s.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if re.fullmatch(r"[+-]?\d+", s):
        return int(s)
    if re.fullmatch(r"[+-]?\d*\.\d+([eE][+-]?\d+)?", s):
        return float(s)
    return s


def _strip_comment(line: str) -> str:
    out, q = [], None
    for ch in line:
        if q:
            out.append(ch)
            if ch == q:
                q = None
        elif ch in ("'", '"'):
            q = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def loads(text: str):
    # Tokenize into (indent, content) ignoring blank/comment-only lines.
    lines = []
    for raw in text.splitlines():
        c = _strip_comment(raw)
        if c.strip() == "":
            continue
        lines.append((_indent(c), c.strip(), c))
    pos = [0]

    def parse_block(min_indent: int):
        if pos[0] >= len(lines):
            return None
        indent = lines[pos[0]][0]
        if lines[pos[0]][1].startswith("- "):
            return parse_list(indent)
        return parse_map(indent)

    def parse_map(indent: int):
        obj = {}
        while pos[0] < len(lines):
            ind, stripped, _ = lines[pos[0]]
            if ind < indent or stripped.startswith("- "):
                break
            if ind > indent:  # malformed; skip
                pos[0] += 1
                continue
            m = re.match(r"^([^:]+):\s*(.*)$", stripped)
            if not m:
                pos[0] += 1
                continue
            key, val = m.group(1).strip(), m.group(2)
            pos[0] += 1
            if val == "":
                # nested block or empty
                if pos[0] < len(lines) and lines[pos[0]][0] > indent:
                    obj[key] = parse_block(indent + 1)
                else:
                    obj[key] = None
            else:
                obj[key] = _scalar(val)
        return obj

    def parse_list(indent: int):
        arr = []
        while pos[0] < len(lines):
            ind, stripped, _ = lines[pos[0]]
            if ind < indent or not stripped.startswith("- "):
                break
            if ind > indent:
                break
            item = stripped[2:].strip()
            pos[0] += 1
            if ":" in item and not (item[0] in "'\""):
                # list of mappings — first pair is inline, rest are indented deeper
                sub = {}
                m = re.match(r"^([^:]+):\s*(.*)$", item)
                key, val = m.group(1).strip(), m.group(2)
                sub[key] = _scalar(val) if val != "" else None
                child_indent = indent + 2
                while pos[0] < len(lines) and lines[pos[0]][0] >= child_indent \
                        and not lines[pos[0]][1].startswith("- "):
                    ind2, strip2, _ = lines[pos[0]]
                    m2 = re.match(r"^([^:]+):\s*(.*)$", strip2)
                    if not m2:
                        pos[0] += 1
                        continue
                    k2, v2 = m2.group(1).strip(), m2.group(2)
                    pos[0] += 1
                    sub[k2] = _scalar(v2) if v2 != "" else None
                arr.append(sub)
            else:
                arr.append(_scalar(item))
        return arr

    return parse_block(0) or {}


def load_file(path: str):
    if os.environ.get("PQB_USE_PYYAML") == "1":
        import yaml  # type: ignore
        with open(path) as f:
            return yaml.safe_load(f)
    with open(path) as f:
        return loads(f.read())


if __name__ == "__main__":
    import json
    import sys
    print(json.dumps(load_file(sys.argv[1]), indent=2))
