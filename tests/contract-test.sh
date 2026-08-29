#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

python3 - <<'PY'
from __future__ import annotations

import pathlib
import re
import json
import subprocess
import tomllib
import urllib.parse

root = pathlib.Path.cwd()

listed = subprocess.run(
    ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
    check=True,
    capture_output=True,
).stdout.decode().split("\0")
files = [root / name for name in listed if name and (root / name).is_file()]

for path in files:
    if path.suffix == ".toml":
        with path.open("rb") as handle:
            tomllib.load(handle)
    if path.suffix == ".json":
        with path.open() as handle:
            json.load(handle)

catalog_path = root / "config/model-catalog.toml"
with catalog_path.open("rb") as handle:
    catalog = tomllib.load(handle)

models = catalog["models"]
bindings = catalog["bindings"]
assert catalog["model_scope"] == "official-openai-only"
assert catalog["model_family"].startswith("gpt-")
expected_bindings = {
    "main",
    "scout",
    "surveyor",
    "mech_executor",
    "executor",
    "light_verifier",
    "verifier",
    "heavy_verifier",
    "security_executor",
}
assert set(bindings) == expected_bindings

official_hosts = {
    "developers.openai.com",
    "platform.openai.com",
    "learn.chatgpt.com",
}
for model in models.values():
    assert model["id"] == catalog["model_family"] or model["id"].startswith(catalog["model_family"] + "-")
    assert urllib.parse.urlparse(model["source_url"]).hostname in official_hosts
    assert model["effort_support"] == "hypothesis"

for binding in bindings.values():
    assert binding["model"] in models
    assert binding["effort"] in models[binding["model"]]["candidate_efforts"]
    assert binding["status"] == "hypothesis"

with (root / "config/routing-defaults.toml").open("rb") as handle:
    routing = tomllib.load(handle)
for name in (
    "concurrency",
    "verification_skip",
    "ultra",
    "transcript_parsing",
    "hook_enforcement",
):
    assert routing[name]["status"] == "hypothesis"
assert routing["strict_verification"]["status"] == "blocked"
assert routing["strict_verification"]["enabled"] is False
assert len(routing["strict_verification"]["required_canaries"]) == 15

with (root / "config/compatibility.toml").open("rb") as handle:
    compatibility = tomllib.load(handle)
assert compatibility["status"] == "test-target"
assert compatibility["platform"]["architecture"] == "arm64"
assert compatibility["standalone_cli"]["certification"] == "not-run"
assert compatibility["desktop"]["certification"] == "not-run"
for section, keys in (
    ("standalone_cli", ("launcher_sha256", "payload_sha256")),
    ("desktop", ("executable_sha256", "embedded_cli_sha256")),
):
    for key in keys:
        assert re.fullmatch(r"[0-9a-f]{64}", compatibility[section][key])

with (root / "evals/certification.toml").open("rb") as handle:
    certification = tomllib.load(handle)
assert certification["status"] == "not-run"
for client in certification["clients"].values():
    assert client["routing_cases"] == 120
    assert client["seeded_defect_cases"] == 120
    assert client["clean_cases"] == 120
assert certification["gates"]["required_instruction_passes"] == 120
assert certification["gates"]["seeded_defects_detected"] == 120
assert certification["gates"]["routing_correct_min"] == 119
assert certification["gates"]["clean_false_positives_max"] == 1

ledger = (root / "docs/REVALIDATION.md").read_text()
rows = [line for line in ledger.splitlines() if line.startswith("| C-")]
assert rows
for row in rows:
    cells = [cell.strip() for cell in row.strip("|").split("|")]
    assert len(cells) == 7
    assert cells[1] and cells[2] and cells[4] and cells[5] and cells[6]
    urls = re.findall(r"https://[^)]+", cells[3])
    assert urls
    assert all(urllib.parse.urlparse(url).hostname in official_hosts for url in urls)

catalog_resolved = catalog_path.resolve()
model_pattern = re.compile(r"\bgpt-\d", re.IGNORECASE)
binding_pattern = re.compile(
    r'(?:model_reasoning_effort|effort)\s*=\s*"(?:minimal|low|medium|high|xhigh|max|ultra)"',
    re.IGNORECASE,
)
blocked_words = [
    "mile" + "stone",
    "PROJECT" + "_" + "NAME",
    "project" + "-" + "slug",
    "Anth" + "ropic",
    "Cla" + "ude",
    "Deep" + "Seek",
    "Open" + "Router",
]

for path in files:
    text = path.read_text(errors="strict")
    assert chr(0x2014) not in text, f"em dash in {path}"
    for word in blocked_words:
        assert word.casefold() not in text.casefold(), f"blocked word in {path}: {word}"
    if path.resolve() != catalog_resolved:
        assert not model_pattern.search(text), f"model ID outside catalog: {path}"
        assert not binding_pattern.search(text), f"effort binding outside catalog: {path}"

ignored_paths = (
    "notes/PLAN.md",
    ".DS_Store",
    ".tmp/example",
    "tmp/example",
    "__pycache__/x.pyc",
    ".pytest_cache/x",
    ".coverage",
    "coverage/index.html",
    "debug.log",
)
for path in ignored_paths:
    subprocess.run(["git", "check-ignore", "-q", path], check=True)

assert all(not name.startswith("notes/") for name in listed)

readme = (root / "README.md").read_text()
design = (root / "docs/design.md").read_text()
native_adr = (root / "docs/adr/0005-native-codex-loading.md").read_text()
assert "normal Codex CLI and desktop sessions load Juno" in readme
assert "does not require a wrapper command for daily use" in readme
assert "Juno does not change Pi" in readme
assert "only when Pi launches the real `codex` executable" in readme
assert "Loaded project instructions remain closer in scope" in design
assert "Juno does not change Pi or make model selection inside Pi" in design
assert "Lifecycle tools may install, update, check, or remove Juno" in design
assert "Do not change Pi" in native_adr
assert "project_doc_max_bytes" in design

required_files = (
    "LICENSE",
    "docs/lifecycle.md",
    "docs/verification.md",
    "config/compatibility.toml",
    "scripts/build-bundle.sh",
)
for name in required_files:
    assert (root / name).is_file(), f"missing required file: {name}"
print("contract tests passed")
PY
