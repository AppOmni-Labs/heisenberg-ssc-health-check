"""Offline end-to-end tests: drive the real `heisenberg` CLI entry point for every subcommand.

External HTTP is faked; the bulk/vendor pipeline's per-package subprocess is replaced by an
in-process call to the real deps.dev checker so the full chain
(SBOM -> parse -> thread pool -> checker report -> report parsing -> CSV) is exercised.
"""

import base64
import contextlib
import csv
import io
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from heisenberg import actions_bulk, bulk_check, heisenberg_depsdev, main
from tests.conftest import FakeResponse

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_cli(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["heisenberg", *argv])
    return main.cli()


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


@pytest.fixture
def depsdev_api(fake_http):
    """A fake deps.dev / registries world where every package exists with one advisory."""
    fake_http.add(r"registry\.npmjs\.org/[^/]+/[^/]+$",
                  json_data={"deprecated": None, "dist": {"tarball": "https://registry.npmjs.org/x.tgz"}})
    fake_http.add(r"pypi\.org", json_data={"info": {"classifiers": []}})
    fake_http.add(r"crates\.io", json_data={"version": {"yanked": False}})
    fake_http.add(r":dependents$", json_data={"dependentCount": 42})
    fake_http.add(r"api\.deps\.dev/v3/systems/", json_data={
        "relatedProjects": [{"projectKey": {"id": "github.com/o/r"}}],
        "advisoryKeys": [{"id": "GHSA-test"}],
        "publishedAt": "2020-01-01T00:00:00Z",
    })
    fake_http.add(r"api\.deps\.dev/v3/projects/", json_data={
        "description": "pkg", "starsCount": 10, "forksCount": 2,
        "scorecard": {"overallScore": 6.0, "checks": [{"name": "Maintained", "score": 5}]},
    })
    return fake_http


@pytest.fixture
def inprocess_checker(monkeypatch, depsdev_api, tarball):
    """Replace the per-package subprocess with the real checker running in-process."""
    npm_tarball = tarball({"package/package.json": json.dumps({"scripts": {}})})
    depsdev_api.routes.insert(0, (re.compile(r"/x\.tgz$"), FakeResponse(content=npm_tarball)))

    def fake_run(cmd, **kwargs):
        assert cmd[:3] == [sys.executable, "-m", "heisenberg.heisenberg_depsdev"]
        assert not kwargs.get("shell")
        parser = heisenberg_depsdev.argparse.ArgumentParser()
        heisenberg_depsdev.add_arguments(parser)
        ns = parser.parse_args(cmd[3:])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            heisenberg_depsdev.cli(ns)
        return subprocess.CompletedProcess(cmd, 0, stdout=buf.getvalue(), stderr="")

    monkeypatch.setattr(bulk_check.subprocess, "run", fake_run)
    monkeypatch.setattr(bulk_check, "MAX_WORKERS", 1)  # redirect_stdout is process-global
    monkeypatch.setattr(bulk_check, "PAUSE_EVERY", 10**6)


def test_help_lists_all_subcommands():
    out = subprocess.run([sys.executable, "-m", "heisenberg.main", "--help"],
                         capture_output=True, text=True, cwd=PROJECT_ROOT, check=True).stdout
    for cmd in ("sbom", "check", "bulk", "vendor", "analyze", "actions"):
        assert cmd in out


def test_installed_console_script_works():
    out = subprocess.run(["heisenberg", "--help"], capture_output=True, text=True, check=True).stdout
    assert "Heisenberg toolkit" in out


def test_analyze_subprocess_end_to_end(fixtures_dir, tmp_path):
    out = tmp_path / "findings.csv"
    subprocess.run(
        [sys.executable, "-m", "heisenberg.main", "analyze", "-sbom", str(fixtures_dir / "sbom.csv"),
         "-pkg", "left-pad", "-o", str(out)],
        cwd=PROJECT_ROOT, check=True, capture_output=True, text=True,
    )
    assert [r["package"] for r in read_csv(out)] == ["left-pad", "Left-Pad"]


def test_check_command(monkeypatch, depsdev_api, capsys):
    run_cli(monkeypatch, "check", "-mgmt", "pypi", "-pkg", "requests", "-v", "2.32.3")
    out = capsys.readouterr().out
    assert "Package Health Score: 6.0" in out
    assert "Security Advisory IDs: GHSA-test" in out
    assert "Fresh Publish (<24h): No" in out


@pytest.mark.parametrize("sbom", ["cyclonedx.json", "cyclonedx.xml", "spdx.json", "spdx.xml", "sbom.csv"])
def test_vendor_command_full_pipeline(monkeypatch, inprocess_checker, fixtures_dir, tmp_path, sbom):
    out = tmp_path / "vendor.csv"
    run_cli(monkeypatch, "vendor", "--sbom-file", str(fixtures_dir / sbom), "--vendor-name", "acme", "-o", str(out))

    rows = read_csv(out)
    assert rows, "vendor run produced no rows"
    assert list(rows[0].keys()) == bulk_check.CSV_HEADER
    for r in rows:
        assert r["repo_name"] == "acme"
        assert r["health_score"] == "6.0"
        assert r["security_advisories"] == "GHSA-test"
        assert r["deps_url"].startswith("https://deps.dev/")


def test_bulk_command_full_pipeline(monkeypatch, inprocess_checker, fixtures_dir, tmp_path):
    sbom_dir = tmp_path / "sbom"
    out = tmp_path / "bulk.csv"

    def fake_generate(d, org, repos_file):
        assert org == "my-org"
        assert (sbom_dir / repos_file).read_text() == "svc\n"
        (sbom_dir / "svc_sbom.csv").write_text((fixtures_dir / "sbom.csv").read_text())
        return True

    monkeypatch.setattr(bulk_check, "run_github_sbom_script", fake_generate)
    run_cli(monkeypatch, "bulk", "-r", "svc", "--org", "my-org", "--sbom-dir", str(sbom_dir), "-o", str(out))

    rows = read_csv(out)
    assert sorted(r["package"] for r in rows) == sorted(
        ["requests", "left-pad", "Left-Pad", "serde", "github.com/pkg/errors"])
    assert {r["language"] for r in rows} == {"pypi", "npm", "cargo", "go"}
    assert not sbom_dir.exists(), "temporary SBOM dir must be removed after bulk"


def test_sbom_command(monkeypatch, fake_http, tmp_path):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    fake_http.add(r"/repos/my-org/svc/dependency-graph/sbom$", json_data={"sbom": {"packages": [
        {"name": "flask", "versionInfo": "3.0.0", "licenseConcluded": "BSD-3-Clause",
         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/flask@3.0.0"}]}]}})
    run_cli(monkeypatch, "sbom", "-r", "svc", "--org", "my-org", "-out", str(tmp_path))
    assert read_csv(tmp_path / "svc_sbom.csv") == [
        {"package": "flask", "version": "3.0.0", "language": "pypi", "license": "BSD-3-Clause"}]


def test_actions_command(monkeypatch, fake_http, tmp_path):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    wf = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: tj-actions/changed-files@" + "b" * 40 + "\n"
    fake_http.add(r"/repos/my-org/svc/contents/\.github/workflows$",
                  json_data=[{"name": "ci.yml", "path": ".github/workflows/ci.yml", "url": "https://api.github.com/f/ci"}])
    fake_http.add(r"/f/ci$", json_data={"content": base64.b64encode(wf.encode()).decode()})
    fake_http.add(r"/security-advisories$", json_data=[{"ghsa_id": "GHSA-tj"}])
    fake_http.add(r"/repos/[^/]+/[^/]+$", json_data={"stargazers_count": 100, "archived": False})

    out = tmp_path / "actions.csv"
    run_cli(monkeypatch, "actions", "-r", "svc", "--org", "my-org", "-o", str(out))

    rows = read_csv(out)
    assert list(rows[0].keys()) == actions_bulk.CSV_HEADER
    by_action = {r["full_action"]: r for r in rows}
    assert by_action["actions/checkout@v4"]["is_sha_pinned"] == "False"
    assert by_action["tj-actions/changed-files@" + "b" * 40]["is_sha_pinned"] == "True"
    assert by_action["actions/checkout@v4"]["advisories"] == "GHSA-tj"

    # --pkg filter (investigation mode) keeps only the requested action
    out2 = tmp_path / "filtered.csv"
    run_cli(monkeypatch, "actions", "-r", "svc", "--org", "my-org", "-o", str(out2),
            "-pkg", "actions/checkout@v4")
    assert [r["full_action"] for r in read_csv(out2)] == ["actions/checkout@v4"]


def test_actions_command_requires_token(monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    run_cli(monkeypatch, "actions", "-r", "svc", "--org", "my-org", "-o", str(tmp_path / "x.csv"))
    assert "GITHUB_TOKEN env var not set" in capsys.readouterr().out
    assert not (tmp_path / "x.csv").exists()
