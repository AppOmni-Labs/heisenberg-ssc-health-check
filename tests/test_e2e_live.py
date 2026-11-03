"""Live end-to-end tests against the real public APIs (deps.dev, PyPI, npm, crates.io).

Deselected by default; run with `uv run pytest -m live`. No credentials are required.
"""

import subprocess
import sys

import pytest

pytestmark = pytest.mark.live


def heisenberg(*args):
    return subprocess.run([sys.executable, "-m", "heisenberg.main", *args],
                          capture_output=True, text=True, timeout=180)


@pytest.mark.parametrize(
    "mgmt, pkg, version, extra",
    [
        ("pypi", "requests", "2.32.3", None),
        ("npm", "left-pad", "1.3.0", "Has Postinstall:"),
        ("cargo", "serde", "1.0.200", "Has Build Script (build.rs):"),
        ("go", "github.com/pkg/errors", "v0.9.1", None),
    ],
)
def test_check_real_package(mgmt, pkg, version, extra):
    proc = heisenberg("check", "-mgmt", mgmt, "-pkg", pkg, "-v", version)
    assert proc.returncode == 0, proc.stderr
    assert f"Package: {pkg}" in proc.stdout
    assert "Package Health Score: Not Found" not in proc.stdout, proc.stdout
    assert "deps.dev:" in proc.stdout
    if extra:
        assert extra in proc.stdout


def test_vendor_real_pipeline(tmp_path):
    sbom = tmp_path / "vendor.csv"
    sbom.write_text("package,version,language,license\nrequests,2.32.3,pypi,Apache-2.0\nleft-pad,1.3.0,npm,MIT\n")
    out = tmp_path / "out.csv"
    proc = heisenberg("vendor", "--sbom-file", str(sbom), "-o", str(out))
    assert proc.returncode == 0, proc.stderr
    import csv
    with open(out) as f:
        rows = list(csv.DictReader(f))
    assert {r["package"] for r in rows} == {"requests", "left-pad"}
    assert all(r["deps_url"].startswith("https://deps.dev/") for r in rows)
