# heisenberg/actions_checker.py

import requests


def _github_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def fetch_action_repo_info(owner: str, repo: str, token: str) -> dict:
    headers = _github_headers(token)
    url = f"https://api.github.com/repos/{owner}/{repo}"
    resp = requests.get(url, headers=headers, timeout=15)

    if resp.status_code == 404:
        return {
            "stars": "N/A", "forks": "N/A", "archived": "N/A",
            "disabled": "N/A", "last_push": "N/A", "action_description": "N/A",
            "repo_error": "repo not found",
        }

    resp.raise_for_status()
    data = resp.json()
    return {
        "stars": data.get("stargazers_count", 0),
        "forks": data.get("forks_count", 0),
        "archived": data.get("archived", False),
        "disabled": data.get("disabled", False),
        "last_push": data.get("pushed_at", "N/A"),
        "action_description": data.get("description") or "",
        "repo_error": None,
    }


def fetch_action_advisories(owner: str, repo: str, token: str) -> list[str]:
    headers = _github_headers(token)
    url = f"https://api.github.com/repos/{owner}/{repo}/security-advisories"
    resp = requests.get(url, headers=headers, timeout=15)

    if resp.status_code in (403, 404):
        return []
    if not resp.ok:
        return []

    return [a.get("ghsa_id", "") for a in resp.json() if a.get("ghsa_id")]


def assess_action(action_ref: dict, token: str) -> dict:
    result = dict(action_ref)

    owner = action_ref.get("owner")
    repo = action_ref.get("action_repo")

    if action_ref.get("action_type") != "action" or not owner or not repo:
        result.update({
            "stars": "N/A", "forks": "N/A", "archived": "N/A",
            "disabled": "N/A", "last_push": "N/A", "action_description": "N/A",
            "advisories": "N/A", "repo_error": "N/A",
        })
        return result

    repo_info = fetch_action_repo_info(owner, repo, token)
    result.update(repo_info)

    advisories = fetch_action_advisories(owner, repo, token)
    result["advisories"] = ", ".join(advisories) if advisories else "None"

    return result