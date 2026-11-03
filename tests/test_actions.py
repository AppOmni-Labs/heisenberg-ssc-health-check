import base64

import pytest

from heisenberg import actions_checker as ac
from heisenberg import actions_parser as ap
from tests.conftest import FakeResponse

SHA = "a" * 40

WORKFLOW = f"""
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tj-actions/changed-files@{SHA}
      - uses: ./local-action
      - uses: docker://alpine:3.19
      - run: 'echo "uses: not-an-action@v1"'
  reusable:
    uses: my-org/.github/.github/workflows/shared.yml@main
"""


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def test_parse_uses_from_workflow_finds_nested_uses():
    uses = ap.parse_uses_from_workflow(WORKFLOW)
    assert uses == [
        "actions/checkout@v4",
        f"tj-actions/changed-files@{SHA}",
        "./local-action",
        "docker://alpine:3.19",
        "my-org/.github/.github/workflows/shared.yml@main",
    ]


@pytest.mark.parametrize("content", ["", "   ", "key: [unclosed", "null"])
def test_parse_uses_handles_empty_or_invalid_yaml(content):
    assert ap.parse_uses_from_workflow(content) == []


def test_parse_uses_uses_safe_loader():
    # A python-object tag must not be constructed (yaml.safe_load rejects it -> treated as invalid).
    malicious = "steps: !!python/object/apply:os.system ['echo pwned']"
    assert ap.parse_uses_from_workflow(malicious) == []


@pytest.mark.parametrize(
    "uses, expected",
    [
        ("actions/checkout@v4",
         {"owner": "actions", "action_repo": "checkout", "ref": "v4", "is_sha_pinned": False, "action_type": "action"}),
        (f"github/codeql-action/init@{SHA}",
         {"owner": "github", "action_repo": "codeql-action", "ref": SHA, "is_sha_pinned": True, "action_type": "action"}),
        ("actions/checkout@" + "A" * 40,
         {"is_sha_pinned": False, "action_type": "action"}),
        ("actions/checkout@" + "a" * 39,
         {"is_sha_pinned": False, "action_type": "action"}),
        ("docker://alpine:3.19", {"owner": None, "action_type": "docker", "is_sha_pinned": False}),
        ("./local", {"owner": None, "action_type": "local"}),
        ("no-ref-at-all", {"owner": None, "action_type": "unknown"}),
    ],
)
def test_parse_action_ref(uses, expected):
    parsed = ap.parse_action_ref(uses)
    assert parsed["full_action"] == uses
    for k, v in expected.items():
        assert parsed[k] == v, k


def test_is_internal_action():
    assert ap._is_internal_action("my-org", ".github", "my-org/.github/actions/setup@main")
    assert not ap._is_internal_action("my-org", ".github", "other-org/.github/actions/setup@main")


def test_fetch_workflow_files_404_returns_empty(fake_http):
    fake_http.add(r"/contents/\.github/workflows$", status_code=404)
    assert ap.fetch_workflow_files("org", "repo", "tok") == []


def test_extract_actions_from_repo_resolves_internal_composite_actions(fake_http):
    wf = "jobs:\n  a:\n    steps:\n      - uses: my-org/.github/actions/setup@main\n      - uses: actions/setup-python@v5\n"
    composite = "runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n    - uses: ./nested\n"
    fake_http.add(
        r"/repos/my-org/svc/contents/\.github/workflows$",
        json_data=[
            {"name": "ci.yml", "path": ".github/workflows/ci.yml", "url": "https://api.github.com/f/ci"},
            {"name": "README.md", "path": ".github/workflows/README.md", "url": "https://api.github.com/f/readme"},
        ],
    )
    fake_http.add(r"/f/ci$", json_data={"content": b64(wf)})
    fake_http.add(r"/repos/my-org/\.github/contents/actions/setup/action\.yml$", json_data={"content": b64(composite)})

    rows = ap.extract_actions_from_repo("my-org", "svc", "tok", shared_actions_repo=".github")

    assert [(r["full_action"], r["resolved_via"]) for r in rows] == [
        ("actions/cache@v4", "my-org/.github/actions/setup@main"),
        ("actions/setup-python@v5", None),
    ]
    assert all(r["repo"] == "svc" and r["workflow_file"] == "ci.yml" for r in rows)
    assert not any("readme" in u for u in fake_http.urls()), "non-YAML files must not be fetched"


def test_github_requests_send_token_and_timeout(fake_http):
    fake_http.add(r"/repos/o/r$", json_data={"stargazers_count": 1})
    ac.fetch_action_repo_info("o", "r", "secret-token")
    call = fake_http.calls[0]
    assert call["headers"]["Authorization"] == "Bearer secret-token"
    assert call["timeout"], "GitHub calls must always have a timeout"


def test_fetch_action_repo_info_ok(fake_http):
    fake_http.add(r"/repos/o/r$", json_data={
        "stargazers_count": 10, "forks_count": 2, "archived": True, "disabled": False,
        "pushed_at": "2024-01-01T00:00:00Z", "description": None,
    })
    info = ac.fetch_action_repo_info("o", "r", "t")
    assert info == {
        "stars": 10, "forks": 2, "archived": True, "disabled": False,
        "last_push": "2024-01-01T00:00:00Z", "action_description": "", "repo_error": None,
    }


def test_fetch_action_repo_info_404(fake_http):
    fake_http.add(r"/repos/o/gone$", status_code=404)
    assert ac.fetch_action_repo_info("o", "gone", "t")["repo_error"] == "repo not found"


@pytest.mark.parametrize("status", [403, 404, 500])
def test_fetch_action_advisories_errors_return_empty(fake_http, status):
    fake_http.add(r"/security-advisories$", status_code=status)
    assert ac.fetch_action_advisories("o", "r", "t") == []


def test_assess_action_combines_repo_info_and_advisories(fake_http):
    fake_http.add(r"/repos/o/r/security-advisories$", json_data=[{"ghsa_id": "GHSA-1"}, {"ghsa_id": "GHSA-2"}, {}])
    fake_http.add(r"/repos/o/r$", json_data={"stargazers_count": 5})
    ref = ap.parse_action_ref("o/r@v1")
    out = ac.assess_action(ref, "t")
    assert out["advisories"] == "GHSA-1, GHSA-2"
    assert out["stars"] == 5
    assert out["full_action"] == "o/r@v1"


def test_assess_action_skips_non_actions_without_http(fake_http):
    out = ac.assess_action(ap.parse_action_ref("docker://alpine"), "t")
    assert out["advisories"] == "N/A"
    assert fake_http.calls == []
