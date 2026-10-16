#!/usr/bin/env python3
"""Decide which images to build and deploy, from services.json.

  plan-services.py <services.json> <requested> <base-sha> <head-sha>

Run from the repo root. <requested> is "" (derive from the diff), "all", "dotnet", or a
space-separated list of service names. A diff that touches a shared path
(SharedKernel, Dockerfile, ...) rebuilds every .NET service. A base sha that
does not exist (first push, force-push) also means "all".

Writes `matrix` (JSON for a build matrix) and `services` (space-separated)
to $GITHUB_OUTPUT.
"""
import json, os, subprocess, sys

cfg = json.load(open(sys.argv[1]))
requested, base, head = sys.argv[2].strip(), sys.argv[3], sys.argv[4]
services = cfg["services"]
names = [s["service"] for s in services]

def pick(fn):
    return [s for s in services if fn(s)]

if requested == "all":
    chosen = services
elif requested == "dotnet":
    chosen = pick(lambda s: s["kind"] == "dotnet")
elif requested:
    unknown = [n for n in requested.split() if n not in names]
    if unknown:
        sys.exit(f"unknown services: {unknown}")
    chosen = pick(lambda s: s["service"] in requested.split())
else:
    ok = base and set(base) != {"0"} and subprocess.run(
        ["git", "cat-file", "-e", f"{base}^{{commit}}"], capture_output=True).returncode == 0
    if not ok:
        chosen = services
    else:
        files = subprocess.check_output(["git", "diff", "--name-only", base, head], text=True).split()
        shared = any(f.startswith(p) for f in files for p in cfg["shared"])
        chosen = pick(lambda s: (shared and s["kind"] == "dotnet")
                      or any(f.startswith(p) for f in files for p in s["paths"]))

# Build args can come straight from a compose file ("args_from"), so values
# like analytics ids live in one place.
for s in chosen:
    if "args_from" in s:
        import yaml
        build = yaml.safe_load(open(s["args_from"]))["services"][s["service"]].get("build", {})
        s["args"] = build.get("args", {}) if isinstance(build, dict) else {}

print("services:", " ".join(s["service"] for s in chosen) or "(none)")
with open(os.environ.get("GITHUB_OUTPUT", "/dev/stdout"), "a") as out:
    out.write(f"matrix={json.dumps({'include': chosen})}\n")
    out.write(f"services={' '.join(s['service'] for s in chosen)}\n")
