"""Relative links in tracked Markdown files must point at tracked files (catches docs that link to
something .gitignore silently kept out of the repo).
Usage: check_links.py      exit 1 on any broken link"""
import pathlib
import posixpath
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LINK = re.compile(r"\]\(([^)\s]+)\)")


def broken(md_path, text, tracked):
    out = []
    for target in LINK.findall(text):
        if re.match(r"[a-z]+:|#", target):
            continue  # external URL or in-page anchor
        norm = posixpath.normpath(posixpath.join(posixpath.dirname(md_path), target.split("#")[0]))
        if norm not in tracked and not any(t.startswith(norm + "/") for t in tracked):
            out.append(f"{md_path}: link to untracked or missing {target}")
    return out


def main():
    tracked = set(subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True,
                                 check=True).stdout.splitlines())
    findings = [f for p in sorted(tracked) if p.endswith(".md")
                for f in broken(p, (ROOT / p).read_text(encoding="utf-8"), tracked)]
    for f in findings:
        print(f"LINK {f}")
    print(f"links: {sum(p.endswith('.md') for p in tracked)} markdown files, {len(findings)} broken")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
