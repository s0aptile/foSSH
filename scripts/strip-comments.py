#!/usr/bin/env python3
import argparse
import re
import pathlib
import sys

SKIP_DIRS = {
    ".git", "target", "_build", "dist", "node_modules", "vendor",
    "vendor-build", "graveyard", "__pycache__", ".venv", "venv",
    "artifacts", "corpus",
}

def strip_c_like(src, line_comment_tokens, block=("/*", "*/"), nested=False,
                 lifetimes=False, raw_strings=False):
    out = []
    i = 0
    n = len(src)
    depth = 0
    bo, bc = block
    while i < n:
        if depth:
            if nested and src.startswith(bo, i):
                depth += 1
                i += len(bo)
                continue
            if src.startswith(bc, i):
                depth -= 1
                i += len(bc)
                continue
            i += 1
            continue

        c = src[i]

        if c == "'" and lifetimes:
            is_char = False
            if i + 1 < n and src[i + 1] == "\\":
                is_char = True
            elif i + 2 < n and src[i + 2] == "'":
                is_char = True
            if not is_char:
                out.append(c)
                i += 1
                continue

        if c == '"' or c == "'":
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == c:
                    j += 1
                    break
                j += 1
            out.append(src[i:j])
            i = j
            continue

        if raw_strings and c == "r" and i + 1 < n and src[i + 1] in '"#':
            j = i + 1
            hashes = 0
            while j < n and src[j] == "#":
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                terminator = '"' + "#" * hashes
                end = src.find(terminator, j + 1)
                end = n if end < 0 else end + len(terminator)
                out.append(src[i:end])
                i = end
                continue

        if src.startswith(bo, i):
            depth = 1
            i += len(bo)
            continue

        matched = None
        for tok in line_comment_tokens:
            if src.startswith(tok, i):
                matched = tok
                break
        if matched:
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue

        out.append(c)
        i += 1
    return "".join(out)

def strip_ocaml(src):
    out = []
    i = 0
    n = len(src)
    depth = 0
    while i < n:
        if depth:
            if src.startswith("(*", i):
                depth += 1
                i += 2
                continue
            if src.startswith("*)", i):
                depth -= 1
                i += 2
                continue
            if src[i] == '"':
                j = i + 1
                while j < n:
                    if src[j] == "\\":
                        j += 2
                        continue
                    if src[j] == '"':
                        j += 1
                        break
                    j += 1
                i = j
                continue
            i += 1
            continue

        if src.startswith("(*", i):
            depth = 1
            i += 2
            continue

        if src[i] == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(src[i:j])
            i = j
            continue

        if src.startswith("{|", i):
            end = src.find("|}", i + 2)
            end = n if end < 0 else end + 2
            out.append(src[i:end])
            i = end
            continue

        if src[i] == "'" and i + 2 < n:
            if src[i + 1] == "\\":
                end = src.find("'", i + 2)
                if 0 <= end <= i + 6:
                    out.append(src[i:end + 1])
                    i = end + 1
                    continue
            elif src[i + 2] == "'":
                out.append(src[i:i + 3])
                i += 3
                continue

        out.append(src[i])
        i += 1
    return "".join(out)

def strip_hash(src, keep_shebang=True, heredoc=True):
    out = []
    lines = src.split("\n")
    pending = None
    for idx, line in enumerate(lines):
        if idx == 0 and keep_shebang and line.startswith("#!"):
            out.append(line)
            continue
        if pending is not None:
            out.append(line)
            if line.strip() == pending:
                pending = None
            continue
        if heredoc:
            m = re.search(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?", line)
            if m:
                pending = m.group(1)
        res = []
        i = 0
        n = len(line)
        cut = False
        while i < n:
            c = line[i]
            if c in "\"'":
                quote = c
                triple = line.startswith(quote * 3, i)
                if triple:
                    res.append(line[i:])
                    i = n
                    break
                j = i + 1
                closed = False
                while j < n:
                    if line[j] == "\\":
                        j += 2
                        continue
                    if line[j] == quote:
                        j += 1
                        closed = True
                        break
                    j += 1
                res.append(line[i:j])
                i = j
                if not closed:
                    res.append(line[i:])
                    i = n
                continue
            if c == "#" and (i == 0 or line[i - 1] in " \t"):
                cut = True
                break
            res.append(c)
            i += 1
        text = "".join(res)
        out.append(text.rstrip() if cut else text)
    return "\n".join(out)

def strip_python(src):
    import io
    import tokenize

    try:
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None
    kept = [t for t in toks if t.type != tokenize.COMMENT]
    try:
        return tokenize.untokenize(kept)
    except (ValueError, IndentationError):
        return None

def tidy(text):
    lines = [ln.rstrip() for ln in text.split("\n")]
    out = []
    blanks = 0
    for ln in lines:
        if ln.strip():
            out.append(ln)
            blanks = 0
        else:
            blanks += 1
            if blanks <= 1 and out:
                out.append("")
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out) + "\n" if out else ""

HANDLERS = {
    ".rs": lambda s: strip_c_like(s, ["//"], nested=True, lifetimes=True,
                                 raw_strings=True),
    ".c": lambda s: strip_c_like(s, ["//"]),
    ".h": lambda s: strip_c_like(s, ["//"]),
    ".ml": strip_ocaml,
    ".mli": strip_ocaml,
    ".php": lambda s: strip_c_like(s, ["//", "#"]),
    ".py": strip_python,
    ".rb": lambda s: strip_hash(s),
    ".sh": lambda s: strip_hash(s),
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--git", action="store_true")
    args = ap.parse_args()

    root = pathlib.Path(args.root).resolve()
    changed = 0
    skipped = []
    if args.git:
        import subprocess
        listing = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True, text=True, check=True,
        ).stdout.split("\0")
        candidates = [root / f for f in listing if f]
    else:
        candidates = sorted(root.rglob("*"))
    for path in candidates:
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        handler = HANDLERS.get(path.suffix)
        if handler is None:
            continue
        try:
            src = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        result = handler(src)
        if result is None:
            skipped.append(str(path.relative_to(root)))
            continue
        if path.suffix == ".rb":
            result = "\n".join(
                ln for ln in result.split("\n")
                if ln.strip() not in ("=begin", "=end")
            )
        result = tidy(result)
        if result != src:
            changed += 1
            if args.apply:
                path.write_text(result, encoding="utf-8")

    print(f"{'stripped' if args.apply else 'would strip'}: {changed} files")
    for s in skipped:
        print(f"  could not parse, left alone: {s}", file=sys.stderr)

if __name__ == "__main__":
    main()
