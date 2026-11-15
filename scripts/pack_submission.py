"""Validate the submission layout and build Lab01_<IDs>.zip.

The same `submission_name` is used for the root folder inside the archive and
for the archive file name. Usage (from the repository root):

    python scripts/pack_submission.py --ids 22120001 22120002 22120003 --confirmed-naming
    python scripts/pack_submission.py --name Lab01_22120001_22120002_22120003 --confirmed-naming

The lab template is Lab01_ID1_ID2_ID3_ID4_ID5. A team with fewer than five IDs
must first get the instructor's approval for the shorter name and then pass
--confirmed-naming; otherwise the script refuses to pack.
"""

import argparse
import os
import re
import shutil
import sys
import zipfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REQUIRED_DIRS = ["src", "tests", "logs", "config"]
REQUIRED_FILES = ["README.md", "REPORT.pdf"]
OPTIONAL_ITEMS = ["scripts", "requirements.txt"]
EXCLUDE_DIRS = {"__pycache__", ".pytest_cache", ".git", ".venv"}
EXCLUDE_SUFFIXES = (".pyc", ".pyo")
NAME_RE = re.compile(r"^Lab01(_[0-9]+){1,5}$")


def resolve_name(args: argparse.Namespace) -> str:
    if args.name:
        name = args.name
    elif args.ids:
        name = "Lab01_" + "_".join(args.ids)
    else:
        raise SystemExit("error: provide --ids or --name")
    if re.search(r"ID\d", name, re.IGNORECASE):
        raise SystemExit(f"error: unresolved placeholder IDs in submission name {name!r}")
    if not NAME_RE.match(name):
        raise SystemExit(f"error: {name!r} must look like Lab01_<id>[_<id>...] with numeric student IDs")
    id_count = name.count("_")
    if id_count != 5 and not args.confirmed_naming:
        raise SystemExit(
            f"error: {name!r} has {id_count} IDs but the template expects 5. Get instructor approval "
            "for the team naming, then re-run with --confirmed-naming."
        )
    return name


def check_layout() -> None:
    problems = []
    for d in REQUIRED_DIRS:
        if not os.path.isdir(os.path.join(REPO_ROOT, d)):
            problems.append(f"missing directory {d}/")
    for f in REQUIRED_FILES:
        if not os.path.isfile(os.path.join(REPO_ROOT, f)):
            problems.append(f"missing file {f}")
    logs = os.path.join(REPO_ROOT, "logs")
    if os.path.isdir(logs) and not any(n.endswith(".log") for n in os.listdir(logs)):
        problems.append("logs/ has no .log files; run `python -m tests.run_e2e --all` first")
    if problems:
        raise SystemExit("error: submission layout invalid:\n  - " + "\n  - ".join(problems))


def _ignore(_dir: str, names: list) -> set:
    return {n for n in names if n in EXCLUDE_DIRS or n.endswith(EXCLUDE_SUFFIXES)}


def build(name: str, out_dir: str) -> str:
    stage = os.path.join(out_dir, name)
    if os.path.exists(stage):
        shutil.rmtree(stage)
    os.makedirs(stage)
    for item in REQUIRED_DIRS + REQUIRED_FILES + OPTIONAL_ITEMS:
        src = os.path.join(REPO_ROOT, item)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(stage, item), ignore=_ignore)
        elif os.path.isfile(src):
            shutil.copy2(src, os.path.join(stage, item))

    zip_path = os.path.join(out_dir, f"{name}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(stage):
            for fn in sorted(files):
                full = os.path.join(root, fn)
                arc = os.path.relpath(full, out_dir).replace(os.sep, "/")
                zf.write(full, arc)

    # Verify: one root folder whose name equals the archive base name
    with zipfile.ZipFile(zip_path) as zf:
        roots = {n.split("/", 1)[0] for n in zf.namelist()}
    if roots != {name}:
        raise SystemExit(f"error: archive root {roots} does not match {name!r}")
    return zip_path


def main() -> None:
    p = argparse.ArgumentParser(description="Build the Lab 01 submission archive")
    p.add_argument("--ids", nargs="+", help="Student IDs in team order")
    p.add_argument("--name", help="Full submission name, e.g. Lab01_22120001_22120002_22120003")
    p.add_argument("--confirmed-naming", action="store_true",
                   help="Instructor approved a name with fewer than 5 IDs")
    p.add_argument("--out-dir", default=os.path.join(REPO_ROOT, "dist"))
    args = p.parse_args()

    name = resolve_name(args)
    check_layout()
    zip_path = build(name, os.path.abspath(args.out_dir))
    print(f"Created {zip_path} (root folder {name}/)")


if __name__ == "__main__":
    sys.exit(main())
