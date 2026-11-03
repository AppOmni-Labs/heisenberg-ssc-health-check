import argparse
from datetime import datetime, timedelta, timezone

import pytest

from heisenberg import heisenberg_depsdev as dd


def _version_payload(published_at=None, advisories=("GHSA-aaaa",), project="github.com/psf/requests"):
    payload = {
        "relatedProjects": [{"projectKey": {"id": project}}] if project else [],
        "advisoryKeys": [{"id": a} for a in advisories],
    }
    if published_at:
        payload["publishedAt"] = published_at
    return payload


PROJECT = {
    "description": "HTTP for humans",
    "starsCount": 50000,
    "forksCount": 9000,
    "scorecard": {
        "overallScore": 7.5,
        "checks": [{"name": "Maintained", "score": 10}, {"name": "Vulnerabilities", "score": 9}],
    },
}


@pytest.fixture
def depsdev_ok(fake_http):
    fake_http.add(r"pypi\.org/pypi/requests/2\.32\.3/json$", json_data={"info": {"classifiers": []}})
    fake_http.add(r"v3alpha/.*:dependents$", json_data={"dependentCount": 1234})
    fake_http.add(r"/v3/systems/pypi/packages/requests/versions/2\.32\.3$",
                  json_data=_version_payload("2020-01-01T00:00:00Z"))
    fake_http.add(r"/v3/projects/github\.com%2Fpsf%2Frequests$", json_data=PROJECT)
    return fake_http


def test_map_ecosystems():
    assert dd.map_ecosystems("pypi") == ("python", "pypi")
    assert dd.map_ecosystems("npm") == ("npm-package", "npm")
    assert dd.map_ecosystems("go") == ("golang", "go")
    assert dd.map_ecosystems("cargo") == ("cargo", "cargo")
    assert dd.map_ecosystems("maven") == ("maven", "maven")


def test_custom_health_score_blends_with_scorecard():
    parsed = {
        "popularity_info_stars": 0, "popularity_info_forks": 0, "maintenance_info": 10,
        "security_score": 10, "dependents": 0, "health_score": "N/A",
    }
    assert dd.compute_custom_health_score(parsed) == 5.0  # 10*0.2 + 10*0.3
    parsed["health_score"] = 9.0
    assert dd.compute_custom_health_score(parsed) == 7.0


def test_custom_health_score_caps_and_handles_garbage():
    huge = {
        "popularity_info_stars": 10**9, "popularity_info_forks": 10**9, "maintenance_info": 10,
        "security_score": 10, "dependents": 10**12, "health_score": "N/A",
    }
    assert dd.compute_custom_health_score(huge) == 10.0
    assert dd.compute_custom_health_score({"popularity_info_stars": "lots"}) == "Unknown"


def test_unsupported_manager():
    assert "not supported" in dd.check_package("maven", "x", "1")["error"]


def test_check_package_happy_path(depsdev_ok):
    out = dd.check_package("PyPI", "requests", "2.32.3")
    assert out["health_score"] == 7.5
    assert out["popularity_info_stars"] == 50000
    assert out["dependents"] == 1234
    assert out["security_info"] == "1"
    assert out["security_advisories"] == "GHSA-aaaa"
    assert out["fresh_publish"] == "No"
    assert out["deps_url"] == "https://deps.dev/pypi/requests/2.32.3"
    assert out["deprecated"] is None


def test_check_package_not_found(fake_http):
    fake_http.add(r"pypi\.org", status_code=404)
    fake_http.add(r"api\.deps\.dev", status_code=404)
    out = dd.check_package("pypi", "nope", "0.0.0")
    assert out["health_score"] == "Not Found"


def test_fresh_publish_flag(fake_http):
    recent = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    fake_http.add(r"crates\.io", json_data={"version": {"yanked": True}})
    fake_http.add(r":dependents$", status_code=500)
    fake_http.add(r"/v3/systems/cargo/", json_data=_version_payload(recent, advisories=(), project=None))
    out = dd.check_package("cargo", "evil", "0.1.0")
    assert out["fresh_publish"] == "Yes"
    assert out["deprecated"] == "Yanked from crates.io"
    assert out["dependents"] == "N/A"
    assert out["security_info"] == "None"


def test_package_names_are_url_encoded_for_depsdev(fake_http):
    fake_http.add(r"registry\.npmjs\.org", status_code=404)
    fake_http.add(r"api\.deps\.dev", status_code=404)
    dd.check_package("npm", "@scope/pkg/../../admin", "1.0.0")
    depsdev = [u for u in fake_http.urls() if "api.deps.dev" in u][0]
    assert "%40scope%2Fpkg%2F..%2F..%2Fadmin" in depsdev
    assert "/../" not in depsdev


def test_npm_deprecated(fake_http):
    fake_http.add(r"registry\.npmjs\.org/request/2\.88\.2$", json_data={"deprecated": "request has been deprecated"})
    assert dd.fetch_npm_deprecated("npm", "request", "2.88.2") == "request has been deprecated"
    assert dd.fetch_npm_deprecated("pypi", "request", "2.88.2") is None


def test_pypi_inactive_classifier(fake_http):
    fake_http.add(r"pypi\.org", json_data={"info": {"classifiers": ["Development Status :: 7 - Inactive"]}})
    assert "Inactive" in dd.fetch_pypi_deprecated("pypi", "old", "1.0")


def test_github_fallback_when_project_missing(fake_http):
    fake_http.add(r"/v3/projects/", status_code=404)
    fake_http.add(r"api\.github\.com/repos/o/r$", json_data={"stargazers_count": 3, "forks_count": 1})
    data, stars, forks = dd.fetch_project_data_with_github_fallback(dd.BASE_URL, "github.com/o/r")
    assert (data, stars, forks) == ({}, 3, 1)


def test_cli_report_output(depsdev_ok, capsys):
    dd.cli(argparse.Namespace(mgmt="pypi", pkg="requests", version="2.32.3"))
    out = capsys.readouterr().out
    assert "Package: requests" in out
    assert "Package Health Score: 7.5" in out
    assert "Security Advisory IDs: GHSA-aaaa" in out
    assert "deps.dev:    https://deps.dev/pypi/requests/2.32.3" in out


def test_cli_rejects_unsupported_manager(capsys):
    with pytest.raises(SystemExit) as exc:
        dd.cli(argparse.Namespace(mgmt="maven", pkg="x", version="1"))
    assert exc.value.code == 1
