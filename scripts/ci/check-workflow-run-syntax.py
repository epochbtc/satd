#!/usr/bin/env python3
"""Parse every bash `run:` block under .github/workflows with `bash -n`.

actionlint runs with shellcheck off, so nothing else parses the scripts
before they run. A step that only runs on a tag (the GitHub Release job)
would otherwise fail for the first time at release time: v0.6.0's did,
on a quote character inside ${prev:-...}.

${{ ... }} expressions are replaced with a plain word first; GitHub
substitutes them before the shell sees the script.
"""

import glob
import re
import subprocess
import sys

import yaml


def run_shell(step, job, workflow):
    for scope in (step, (job.get("defaults") or {}).get("run") or {},
                  (workflow.get("defaults") or {}).get("run") or {}):
        if scope.get("shell"):
            return scope["shell"]
    return "bash"


def main():
    checked = failed = 0
    for path in sorted(glob.glob(".github/workflows/*.yml")):
        with open(path) as f:
            workflow = yaml.safe_load(f)
        for job_id, job in (workflow.get("jobs") or {}).items():
            for i, step in enumerate(job.get("steps") or []):
                script = step.get("run")
                if script is None:
                    continue
                if run_shell(step, job, workflow).split()[0] not in ("bash", "sh"):
                    continue
                checked += 1
                script = re.sub(r"\$\{\{.*?\}\}", "X", script, flags=re.S)
                r = subprocess.run(["bash", "-n"], input=script, text=True,
                                   capture_output=True)
                if r.returncode:
                    failed += 1
                    name = step.get("name", f"step {i}")
                    print(f"::error file={path}::job {job_id}, {name}: "
                          f"{r.stderr.strip()}")
    print(f"{checked} run blocks parsed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
